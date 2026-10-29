#define _GNU_SOURCE
#include "llm_client.h"
#include "command_guard.h"
#include "db/db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <ctype.h>
#include <errno.h>

#if __has_include(<curl/curl.h>)
#include <curl/curl.h>
#define HAVE_LIBCURL 1
#else
#define HAVE_LIBCURL 0
#endif

#if __has_include(<glib.h>)
#include <glib.h>
#define HAVE_GLIB 1
#else
#define HAVE_GLIB 0
#endif

// -----------------------------------------------------------------------------
// Global Lifecycle & Configuration
// -----------------------------------------------------------------------------

int llm_client_init(void) {
#if HAVE_LIBCURL
    CURLcode code = curl_global_init(CURL_GLOBAL_ALL);
    return (code == CURLE_OK) ? 0 : -1;
#else
    return 0;
#endif
}

void llm_client_cleanup(void) {
#if HAVE_LIBCURL
    curl_global_cleanup();
#endif
}

LLMConfig llm_config_default(void) {
    LLMConfig config;
    memset(&config, 0, sizeof(config));

    const char *env_endpoint = getenv("GRIT_LLM_ENDPOINT");
    if (env_endpoint && env_endpoint[0] != '\0') {
        strncpy(config.endpoint, env_endpoint, sizeof(config.endpoint) - 1);
    } else {
        strncpy(config.endpoint, LLM_DEFAULT_CHAT_ENDPOINT, sizeof(config.endpoint) - 1);
    }

    const char *env_model = getenv("GRIT_LLM_MODEL");
    if (env_model && env_model[0] != '\0') {
        strncpy(config.model, env_model, sizeof(config.model) - 1);
    } else {
        strncpy(config.model, LLM_DEFAULT_MODEL, sizeof(config.model) - 1);
    }

    config.connect_timeout_s = LLM_DEFAULT_CONNECT_TIMEOUT_S;
    config.total_timeout_s = LLM_DEFAULT_TOTAL_TIMEOUT_S;
    return config;
}

// -----------------------------------------------------------------------------
// Safe JSON Escaping
// -----------------------------------------------------------------------------

static void json_escape(const char *src, char *dst, size_t dst_max) {
    if (!src || !dst || dst_max == 0) return;
    size_t d = 0;

    for (size_t s = 0; src[s] != '\0' && d + 2 < dst_max; s++) {
        unsigned char c = (unsigned char)src[s];
        switch (c) {
            case '"':
                if (d + 2 >= dst_max) break;
                dst[d++] = '\\'; dst[d++] = '"';
                break;
            case '\\':
                if (d + 2 >= dst_max) break;
                dst[d++] = '\\'; dst[d++] = '\\';
                break;
            case '\n':
                if (d + 2 >= dst_max) break;
                dst[d++] = '\\'; dst[d++] = 'n';
                break;
            case '\r':
                if (d + 2 >= dst_max) break;
                dst[d++] = '\\'; dst[d++] = 'r';
                break;
            case '\t':
                if (d + 2 >= dst_max) break;
                dst[d++] = '\\'; dst[d++] = 't';
                break;
            default:
                if (c >= 32) {
                    dst[d++] = (char)c;
                }
                break;
        }
    }
    dst[d] = '\0';
}

static void json_unescape(const char *src, char *dst, size_t dst_max) {
    if (!src || !dst || dst_max == 0) return;
    size_t d = 0;

    for (size_t s = 0; src[s] != '\0' && d + 1 < dst_max; s++) {
        if (src[s] == '\\' && src[s + 1] != '\0') {
            s++;
            switch (src[s]) {
                case '"':  dst[d++] = '"'; break;
                case '\\': dst[d++] = '\\'; break;
                case '/':  dst[d++] = '/'; break;
                case 'b':  dst[d++] = '\b'; break;
                case 'f':  dst[d++] = '\f'; break;
                case 'n':  dst[d++] = '\n'; break;
                case 'r':  dst[d++] = '\r'; break;
                case 't':  dst[d++] = '\t'; break;
                default:   dst[d++] = src[s]; break;
            }
        } else {
            dst[d++] = src[s];
        }
    }
    dst[d] = '\0';
}

static bool extract_json_string_field(const char *json, const char *key, char *out_val, size_t max_len) {
    if (!json || !key || !out_val || max_len == 0) return false;

    char search_pattern[128];
    snprintf(search_pattern, sizeof(search_pattern), "\"%s\"", key);

    const char *pos = strstr(json, search_pattern);
    if (!pos) return false;

    pos += strlen(search_pattern);
    while (*pos && (isspace((unsigned char)*pos) || *pos == ':')) {
        pos++;
    }

    if (*pos != '"') return false;
    pos++; // Skip opening quote

    char temp[4096];
    size_t t = 0;
    bool in_escape = false;

    while (*pos && t + 1 < sizeof(temp)) {
        if (in_escape) {
            temp[t++] = *pos;
            in_escape = false;
        } else if (*pos == '\\') {
            temp[t++] = *pos;
            in_escape = true;
        } else if (*pos == '"') {
            break;
        } else {
            temp[t++] = *pos;
        }
        pos++;
    }
    temp[t] = '\0';

    json_unescape(temp, out_val, max_len);
    return true;
}

// -----------------------------------------------------------------------------
// Payload Construction
// -----------------------------------------------------------------------------

int llm_build_payload(const LLMConfig *config,
                      const Incident *incident,
                      char *out_payload,
                      size_t max_len) {
    if (!config || !incident || !out_payload || max_len == 0) {
        return -1;
    }

    char esc_id[64];
    char esc_category[128];
    char esc_ip[96];
    char esc_user[128];
    char esc_excerpt[1024];

    json_escape(incident->incident_id, esc_id, sizeof(esc_id));
    json_escape(incident->category, esc_category, sizeof(esc_category));
    json_escape(incident->source_ip, esc_ip, sizeof(esc_ip));
    json_escape(incident->target_user, esc_user, sizeof(esc_user));
    json_escape(incident->raw_log_excerpt, esc_excerpt, sizeof(esc_excerpt));

    char inner_prompt[2048];
    int written = snprintf(inner_prompt, sizeof(inner_prompt),
        "{\"incident\": {\"id\": \"%s\", \"category\": \"%s\", \"source_ip\": \"%s\", \"target_user\": \"%s\", \"frequency\": %d, \"severity\": %d, \"excerpt\": \"%s\"}, \"user_knowledge_level\": {\"pam_auth\": 1, \"firewall_ufw\": 1}}",
        esc_id, esc_category, esc_ip, esc_user, incident->frequency_count, (int)incident->severity, esc_excerpt);

    if (written < 0 || (size_t)written >= sizeof(inner_prompt)) {
        return -1;
    }

    char outer_prompt_escaped[4096];
    json_escape(inner_prompt, outer_prompt_escaped, sizeof(outer_prompt_escaped));

    const char *system_prompt =
        "You are Grit, an offline Socratic Linux security mentor. Guide the user using short Socratic hints, "
        "1 diagnostic question, and safe diagnostic commands (classified as SAFE, CAUTION, or BLOCKED). "
        "Never spoon-feed answers directly. "
        "Format output as JSON matching: {\"mentor_analysis\": \"<string>\", \"actions\": [{\"command\": \"<string>\", \"explanation\": \"<string>\"}]}";

    char esc_system[1024];
    json_escape(system_prompt, esc_system, sizeof(esc_system));

    written = snprintf(out_payload, max_len,
        "{\n"
        "  \"model\": \"%s\",\n"
        "  \"system\": \"%s\",\n"
        "  \"prompt\": \"%s\",\n"
        "  \"stream\": false,\n"
        "  \"format\": \"json\"\n"
        "}",
        config->model, esc_system, outer_prompt_escaped);

    return (written > 0 && (size_t)written < max_len) ? 0 : -1;
}

int llm_build_chat_payload(const LLMConfig *config,
                           const char *incident_id,
                           const char *user_message,
                           char *out_payload,
                           size_t max_len) {
    if (!config || !user_message || !out_payload || max_len == 0) {
        return -1;
    }

    const char *system_prompt =
        "You are Grit, an offline Socratic Linux security mentor. Guide the user using short Socratic hints, "
        "1 diagnostic question, and safe diagnostic commands (classified as SAFE, CAUTION, or BLOCKED). "
        "Never spoon-feed answers directly.";

    char esc_system[1024];
    json_escape(system_prompt, esc_system, sizeof(esc_system));

    // Initialize messages array
    char messages_buf[8192];
    size_t m_len = 0;
    m_len += (size_t)snprintf(messages_buf + m_len, sizeof(messages_buf) - m_len,
                              "    {\"role\": \"system\", \"content\": \"%s\"}", esc_system);

    // Load last up to 6 chat history items from SQLite
    if (incident_id && incident_id[0] != '\0') {
        ChatMessage *history = NULL;
        size_t count = 0;
        if (grit_db_load_chat_history(incident_id, &history, &count) && history) {
            size_t start_idx = (count > 6) ? count - 6 : 0;
            for (size_t i = start_idx; i < count; i++) {
                char esc_content[2048];
                json_escape(history[i].content, esc_content, sizeof(esc_content));
                const char *role = (strcmp(history[i].sender, "mentor") == 0) ? "assistant" : "user";
                m_len += (size_t)snprintf(messages_buf + m_len, sizeof(messages_buf) - m_len,
                                          ",\n    {\"role\": \"%s\", \"content\": \"%s\"}", role, esc_content);
            }
            free(history);
        }
    }

    // Append current user message
    char esc_user[2048];
    json_escape(user_message, esc_user, sizeof(esc_user));
    m_len += (size_t)snprintf(messages_buf + m_len, sizeof(messages_buf) - m_len,
                              ",\n    {\"role\": \"user\", \"content\": \"%s\"}", esc_user);

    int written = snprintf(out_payload, max_len,
        "{\n"
        "  \"model\": \"%s\",\n"
        "  \"messages\": [\n"
        "%s\n"
        "  ],\n"
        "  \"stream\": false\n"
        "}",
        config->model, messages_buf);

    return (written > 0 && (size_t)written < max_len) ? 0 : -1;
}

// -----------------------------------------------------------------------------
// Response Parsing & Socratic Hypothesis Processing
// -----------------------------------------------------------------------------

int llm_parse_response(const char *raw_json,
                       MentorResponse *out_response,
                       char *error_buf,
                       size_t err_len) {
    if (!raw_json || !out_response) {
        if (error_buf && err_len > 0) snprintf(error_buf, err_len, "Null arguments provided to parser");
        return -1;
    }

    memset(out_response, 0, sizeof(MentorResponse));

    char extracted_text[8192];
    bool found_content = false;

    // Check 1: /api/chat format (message.content)
    const char *msg_pos = strstr(raw_json, "\"message\"");
    if (msg_pos) {
        found_content = extract_json_string_field(msg_pos, "content", extracted_text, sizeof(extracted_text));
    }

    // Check 2: /api/generate format (response)
    if (!found_content) {
        found_content = extract_json_string_field(raw_json, "response", extracted_text, sizeof(extracted_text));
    }

    const char *content_ptr = found_content ? extracted_text : raw_json;
    while (isspace((unsigned char)*content_ptr)) content_ptr++;

    // Check if inner content is structured JSON
    if (*content_ptr == '{') {
        char analysis_text[2048];
        if (!extract_json_string_field(content_ptr, "mentor_analysis", analysis_text, sizeof(analysis_text))) {
            if (error_buf && err_len > 0) {
                snprintf(error_buf, err_len, "Missing 'mentor_analysis' in LLM output");
            }
            return -1;
        }

        snprintf(out_response->mentor_analysis, sizeof(out_response->mentor_analysis), "%s", analysis_text);

        // Extract actions array
        const char *actions_pos = strstr(content_ptr, "\"actions\"");
        if (actions_pos) {
            const char *arr_start = strchr(actions_pos, '[');
            const char *arr_end = arr_start ? strrchr(arr_start, ']') : NULL;

            if (arr_start && arr_end && arr_end > arr_start) {
                const char *curr = arr_start + 1;
                while (curr < arr_end && out_response->action_count < 3) {
                    const char *obj_start = strchr(curr, '{');
                    if (!obj_start || obj_start >= arr_end) break;
                    const char *obj_end = strchr(obj_start, '}');
                    if (!obj_end || obj_end > arr_end) break;

                    size_t obj_len = (size_t)(obj_end - obj_start + 1);
                    char obj_buf[1024];
                    if (obj_len < sizeof(obj_buf)) {
                        memcpy(obj_buf, obj_start, obj_len);
                        obj_buf[obj_len] = '\0';

                        SuggestedAction *action = &out_response->actions[out_response->action_count];
                        extract_json_string_field(obj_buf, "command", action->command, sizeof(action->command));
                        extract_json_string_field(obj_buf, "explanation", action->explanation, sizeof(action->explanation));
                        action->safety_level = evaluate_command_safety(action->command);

                        if (strlen(action->command) > 0) {
                            out_response->action_count++;
                        }
                    }
                    curr = obj_end + 1;
                }
            }
        }
        return 0;
    }

    // Free-form Socratic text response
    if (found_content && strlen(extracted_text) > 0) {
        snprintf(out_response->mentor_analysis, sizeof(out_response->mentor_analysis), "%.*s",
                 (int)(sizeof(out_response->mentor_analysis) - 1), extracted_text);

        // Scan for code blocks or commands inside backticks
        const char *p = extracted_text;
        while (*p && out_response->action_count < 3) {
            const char *tick_start = strchr(p, '`');
            if (!tick_start) break;
            tick_start++;
            if (*tick_start == '`') tick_start++; // Skip multi-ticks
            if (*tick_start == '`') tick_start++;
            if (strncmp(tick_start, "bash\n", 5) == 0) tick_start += 5;
            else if (strncmp(tick_start, "sh\n", 3) == 0) tick_start += 3;

            const char *tick_end = strchr(tick_start, '`');
            if (!tick_end) break;

            size_t cmd_len = (size_t)(tick_end - tick_start);
            if (cmd_len > 0 && cmd_len < sizeof(out_response->actions[0].command)) {
                SuggestedAction *act = &out_response->actions[out_response->action_count];
                memcpy(act->command, tick_start, cmd_len);
                act->command[cmd_len] = '\0';

                while (cmd_len > 0 && (act->command[cmd_len - 1] == '\n' || act->command[cmd_len - 1] == '\r')) {
                    act->command[--cmd_len] = '\0';
                }

                if (strlen(act->command) > 0) {
                    act->safety_level = evaluate_command_safety(act->command);
                    snprintf(act->explanation, sizeof(act->explanation), "Diagnostic command suggested by Socratic mentor");
                    out_response->action_count++;
                }
            }
            p = tick_end + 1;
        }

        return 0;
    }

    if (error_buf && err_len > 0) {
        snprintf(error_buf, err_len, "Unable to extract response content from LLM output");
    }
    return -1;
}

// -----------------------------------------------------------------------------
// Synchronous libcurl HTTP Transfer
// -----------------------------------------------------------------------------

#if HAVE_LIBCURL

typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} MemoryBuffer;

static size_t curl_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t real_size = size * nmemb;
    MemoryBuffer *mem = (MemoryBuffer *)userp;

    if (mem->size + real_size + 1 > mem->capacity) {
        size_t new_cap = (mem->capacity == 0) ? 8192 : mem->capacity * 2;
        while (new_cap < mem->size + real_size + 1) {
            new_cap *= 2;
        }
        char *new_buf = realloc(mem->data, new_cap);
        if (!new_buf) return 0;
        mem->data = new_buf;
        mem->capacity = new_cap;
    }

    memcpy(mem->data + mem->size, contents, real_size);
    mem->size += real_size;
    mem->data[mem->size] = '\0';
    return real_size;
}

static int execute_curl_post(const char *url,
                             const char *payload,
                             long connect_timeout_s,
                             long total_timeout_s,
                             char **out_response_text,
                             char *error_buf,
                             size_t err_len) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        if (error_buf && err_len > 0) snprintf(error_buf, err_len, "curl_easy_init failed");
        return -1;
    }

    MemoryBuffer mem = { .data = NULL, .size = 0, .capacity = 0 };
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(payload));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&mem);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connect_timeout_s > 0 ? connect_timeout_s : 3L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, total_timeout_s > 0 ? total_timeout_s : 45L);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        if (error_buf && err_len > 0) {
            snprintf(error_buf, err_len, "cURL error (%d): %s", res, curl_easy_strerror(res));
        }
        if (mem.data) free(mem.data);
        if (headers) curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return -1;
    }

    *out_response_text = mem.data;
    if (headers) curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return 0;
}

// Deterministic offline Socratic fallback
static void populate_offline_socratic_fallback(MentorResponse *out_response, const char *context_hint) {
    memset(out_response, 0, sizeof(MentorResponse));

    snprintf(out_response->mentor_analysis, sizeof(out_response->mentor_analysis),
        "Offline Socratic Guidance:\n"
        "We observe anomalous authentication activity (%s). "
        "Before altering system firewall configurations or terminating active user sessions, "
        "what network services are currently accepting connections on this host?",
        context_hint ? context_hint : "System event");

    // Action 1: ss (Safe)
    strncpy(out_response->actions[0].command, "ss -tulpn | grep :22", sizeof(out_response->actions[0].command) - 1);
    out_response->actions[0].safety_level = CMD_SAFE;
    strncpy(out_response->actions[0].explanation, "Inspect listening sockets for the SSH daemon.", sizeof(out_response->actions[0].explanation) - 1);

    // Action 2: journalctl (Safe)
    strncpy(out_response->actions[1].command, "journalctl -u ssh -n 30 --no-pager", sizeof(out_response->actions[1].command) - 1);
    out_response->actions[1].safety_level = CMD_SAFE;
    strncpy(out_response->actions[1].explanation, "Review the last 30 log records specifically generated by sshd.", sizeof(out_response->actions[1].explanation) - 1);

    // Action 3: ufw status (Safe)
    strncpy(out_response->actions[2].command, "ufw status verbose", sizeof(out_response->actions[2].command) - 1);
    out_response->actions[2].safety_level = CMD_SAFE;
    strncpy(out_response->actions[2].explanation, "Audit active packet filtering policies without modifying firewall state.", sizeof(out_response->actions[2].explanation) - 1);

    out_response->action_count = 3;
}

int llm_query_sync(const LLMConfig *config,
                   const Incident *incident,
                   MentorResponse *out_response,
                   char *error_buf,
                   size_t err_len) {
    if (!config || !incident || !out_response) return -1;

    char payload[8192];
    if (llm_build_payload(config, incident, payload, sizeof(payload)) != 0) {
        if (error_buf && err_len > 0) snprintf(error_buf, err_len, "Failed to build request payload");
        return -1;
    }

    char *response_body = NULL;
    int rc = execute_curl_post(config->endpoint, payload,
                               config->connect_timeout_s, config->total_timeout_s,
                               &response_body, error_buf, err_len);

    if (rc == 0 && response_body) {
        int parse_rc = llm_parse_response(response_body, out_response, error_buf, err_len);
        free(response_body);
        if (parse_rc == 0) return 0;
    }

    // Fallback gracefully on Ollama offline / timeout
    populate_offline_socratic_fallback(out_response, incident->category);
    return 0;
}

int llm_chat_sync(const LLMConfig *config,
                  const char *incident_id,
                  const char *user_prompt,
                  MentorResponse *out_response,
                  char *error_buf,
                  size_t err_len) {
    if (!config || !user_prompt || !out_response) return -1;

    char payload[16384];
    if (llm_build_chat_payload(config, incident_id, user_prompt, payload, sizeof(payload)) != 0) {
        if (error_buf && err_len > 0) snprintf(error_buf, err_len, "Failed to assemble chat payload");
        return -1;
    }

    char *response_body = NULL;
    int rc = execute_curl_post(config->endpoint, payload,
                               config->connect_timeout_s, config->total_timeout_s,
                               &response_body, error_buf, err_len);

    if (rc == 0 && response_body) {
        int parse_rc = llm_parse_response(response_body, out_response, error_buf, err_len);
        free(response_body);
        if (parse_rc == 0) return 0;
    }

    populate_offline_socratic_fallback(out_response, user_prompt);
    return 0;
}

#else // !HAVE_LIBCURL

int llm_query_sync(const LLMConfig *config,
                   const Incident *incident,
                   MentorResponse *out_response,
                   char *error_buf,
                   size_t err_len) {
    (void)config; (void)error_buf; (void)err_len;
    memset(out_response, 0, sizeof(MentorResponse));
    snprintf(out_response->mentor_analysis, sizeof(out_response->mentor_analysis),
             "Offline Socratic Advice: Host %s targeted user %s. Check open sockets before taking action.",
             incident->source_ip, incident->target_user);
    strncpy(out_response->actions[0].command, "ss -tulpn | grep :22", sizeof(out_response->actions[0].command) - 1);
    out_response->actions[0].safety_level = CMD_SAFE;
    strncpy(out_response->actions[0].explanation, "Inspect listening sockets.", sizeof(out_response->actions[0].explanation) - 1);
    out_response->action_count = 1;
    return 0;
}

int llm_chat_sync(const LLMConfig *config,
                  const char *incident_id,
                  const char *user_prompt,
                  MentorResponse *out_response,
                  char *error_buf,
                  size_t err_len) {
    (void)config; (void)incident_id; (void)error_buf; (void)err_len;
    memset(out_response, 0, sizeof(MentorResponse));
    snprintf(out_response->mentor_analysis, sizeof(out_response->mentor_analysis),
             "Socratic Hint: Consider what processes could authenticate with '%s'.", user_prompt);
    out_response->action_count = 0;
    return 0;
}

#endif // HAVE_LIBCURL

// -----------------------------------------------------------------------------
// Asynchronous Thread Dispatcher (Safe g_idle_add Bridge)
// -----------------------------------------------------------------------------

typedef struct {
    LLMConfig config;
    Incident incident;
    char incident_id[64];
    char user_prompt[2048];
    bool is_chat;
    LLMResponseCallback callback;
    void *user_data;
} AsyncWorkerContext;

typedef struct {
    LLMResponseCallback callback;
    void *user_data;
    MentorResponse response;
    bool success;
    char error_msg[512];
} GTKIdleDispatchData;

#if HAVE_GLIB
static gboolean llm_gtk_idle_dispatcher(gpointer data) {
    GTKIdleDispatchData *d = (GTKIdleDispatchData *)data;
    if (d) {
        if (d->callback) {
            d->callback(&d->response, d->success, d->error_msg, d->user_data);
        }
        free(d);
    }
    return G_SOURCE_REMOVE;
}
#endif

static void *llm_worker_thread(void *arg) {
    AsyncWorkerContext *ctx = (AsyncWorkerContext *)arg;
    if (!ctx) pthread_exit(NULL);

    MentorResponse response;
    memset(&response, 0, sizeof(response));
    char err_buf[512] = {0};

    int rc = 0;
    if (ctx->is_chat) {
        rc = llm_chat_sync(&ctx->config, ctx->incident_id, ctx->user_prompt, &response, err_buf, sizeof(err_buf));
    } else {
        rc = llm_query_sync(&ctx->config, &ctx->incident, &response, err_buf, sizeof(err_buf));
    }

    GTKIdleDispatchData *dispatch = malloc(sizeof(GTKIdleDispatchData));
    if (dispatch) {
        dispatch->callback = ctx->callback;
        dispatch->user_data = ctx->user_data;
        dispatch->response = response;
        dispatch->success = (rc == 0);
        strncpy(dispatch->error_msg, err_buf, sizeof(dispatch->error_msg) - 1);
        dispatch->error_msg[sizeof(dispatch->error_msg) - 1] = '\0';

#if HAVE_GLIB
        g_idle_add(llm_gtk_idle_dispatcher, dispatch);
#else
        if (dispatch->callback) {
            dispatch->callback(&dispatch->response, dispatch->success, dispatch->error_msg, dispatch->user_data);
        }
        free(dispatch);
#endif
    }

    free(ctx);
    pthread_exit(NULL);
    return NULL;
}

int llm_query_async(const LLMConfig *config,
                    const Incident *incident,
                    LLMResponseCallback callback,
                    void *user_data) {
    if (!config || !incident) return -1;

    AsyncWorkerContext *ctx = malloc(sizeof(AsyncWorkerContext));
    if (!ctx) return -1;

    ctx->config = *config;
    ctx->incident = *incident;
    ctx->is_chat = false;
    ctx->callback = callback;
    ctx->user_data = user_data;

    pthread_t thread;
    int rc = pthread_create(&thread, NULL, llm_worker_thread, ctx);
    if (rc != 0) {
        free(ctx);
        return -1;
    }
    pthread_detach(thread);
    return 0;
}

int llm_chat_async(const LLMConfig *config,
                   const char *incident_id,
                   const char *user_prompt,
                   LLMResponseCallback callback,
                   void *user_data) {
    if (!config || !user_prompt) return -1;

    AsyncWorkerContext *ctx = malloc(sizeof(AsyncWorkerContext));
    if (!ctx) return -1;

    ctx->config = *config;
    memset(&ctx->incident, 0, sizeof(ctx->incident));
    if (incident_id) {
        strncpy(ctx->incident_id, incident_id, sizeof(ctx->incident_id) - 1);
    } else {
        ctx->incident_id[0] = '\0';
    }
    strncpy(ctx->user_prompt, user_prompt, sizeof(ctx->user_prompt) - 1);
    ctx->is_chat = true;
    ctx->callback = callback;
    ctx->user_data = user_data;

    pthread_t thread;
    int rc = pthread_create(&thread, NULL, llm_worker_thread, ctx);
    if (rc != 0) {
        free(ctx);
        return -1;
    }
    pthread_detach(thread);
    return 0;
}
