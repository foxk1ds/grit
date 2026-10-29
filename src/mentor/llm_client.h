#ifndef GRIT_MENTOR_LLM_CLIENT_H
#define GRIT_MENTOR_LLM_CLIENT_H

#include "core/types.h"
#include <stdbool.h>
#include <stddef.h>

#define LLM_DEFAULT_CHAT_ENDPOINT     "http://localhost:11434/api/chat"
#define LLM_DEFAULT_GENERATE_ENDPOINT "http://localhost:11434/api/generate"
#define LLM_DEFAULT_MODEL             "qwen2.5-coder:latest"
#define LLM_DEFAULT_CONNECT_TIMEOUT_S 3L
#define LLM_DEFAULT_TOTAL_TIMEOUT_S   45L

/*
 * Configuration for local Ollama orchestration
 */
typedef struct {
    char endpoint[256];     // e.g. "http://localhost:11434/api/chat"
    char model[64];         // e.g. "qwen2.5-coder:latest" or "deepseek-r1:7b"
    long connect_timeout_s; // Connection timeout (default: 3s)
    long total_timeout_s;   // Total network transfer timeout (default: 45s)
} LLMConfig;

/*
 * Callback signature for asynchronous queries.
 * Guaranteed to be dispatched onto the GTK main thread via g_idle_add.
 */
typedef void (*LLMResponseCallback)(const MentorResponse *response,
                                    bool success,
                                    const char *error_msg,
                                    void *user_data);

/*
 * Global library initialization (calls curl_global_init)
 */
int llm_client_init(void);

/*
 * Global library cleanup (calls curl_global_cleanup)
 */
void llm_client_cleanup(void);

/*
 * Returns default LLMConfig targeting local Ollama with defensive timeouts
 * Respects GRIT_LLM_MODEL and GRIT_LLM_ENDPOINT environment variables.
 */
LLMConfig llm_config_default(void);

/*
 * Builds strict JSON payload for Ollama POST /api/generate
 */
int llm_build_payload(const LLMConfig *config,
                      const Incident *incident,
                      char *out_payload,
                      size_t max_len);

/*
 * Builds multi-turn conversational JSON payload for Ollama POST /api/chat
 * Integrates up to last 6 chat messages from database history.
 */
int llm_build_chat_payload(const LLMConfig *config,
                           const char *incident_id,
                           const char *user_message,
                           char *out_payload,
                           size_t max_len);

/*
 * Parses Ollama JSON response into MentorResponse and validates safety levels
 */
int llm_parse_response(const char *raw_json,
                       MentorResponse *out_response,
                       char *error_buf,
                       size_t err_len);

/*
 * Synchronous query (executes on current thread, blocks until response/timeout)
 */
int llm_query_sync(const LLMConfig *config,
                   const Incident *incident,
                   MentorResponse *out_response,
                   char *error_buf,
                   size_t err_len);

/*
 * Asynchronous query (spawns worker pthread, executes non-blocking network I/O,
 * and schedules GTK main-thread callback execution via g_idle_add)
 */
int llm_query_async(const LLMConfig *config,
                    const Incident *incident,
                    LLMResponseCallback callback,
                    void *user_data);

/*
 * Multi-turn Socratic conversation query
 */
int llm_chat_sync(const LLMConfig *config,
                  const char *incident_id,
                  const char *user_prompt,
                  MentorResponse *out_response,
                  char *error_buf,
                  size_t err_len);

int llm_chat_async(const LLMConfig *config,
                   const char *incident_id,
                   const char *user_prompt,
                   LLMResponseCallback callback,
                   void *user_data);

#endif // GRIT_MENTOR_LLM_CLIENT_H
