#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "core/types.h"
#include "mentor/llm_client.h"
#include "mentor/command_guard.h"

static void test_config_and_payload_builder(void) {
    printf("[TEST] Running LLM Config & Payload Builder tests...\n");

    LLMConfig cfg = llm_config_default();
    assert(strstr(cfg.endpoint, "11434") != NULL);
    assert(strlen(cfg.model) > 0);
    assert(cfg.connect_timeout_s >= 2);
    assert(cfg.total_timeout_s >= 30);
    printf("  [PASS] llm_config_default initialized with correct parameters\n");

    Incident inc = {
        .incident_id = "SEC-1704100000-001",
        .category = "SSH \"Brute Force\" Attack",
        .source_ip = "192.168.1.50",
        .target_user = "root\nadmin",
        .frequency_count = 42,
        .first_seen = 1704100000,
        .last_seen = 1704100360,
        .severity = SEV_CRIT,
        .raw_log_excerpt = "Failed password for root from 192.168.1.50: <REDACTED>"
    };

    char payload[4096];
    int rc = llm_build_payload(&cfg, &inc, payload, sizeof(payload));
    assert(rc == 0);

    // Verify critical JSON fields
    assert(strstr(payload, "\"model\":") != NULL);
    assert(strstr(payload, "\"stream\": false") != NULL);
    assert(strstr(payload, "\"format\": \"json\"") != NULL);
    assert(strstr(payload, "Socratic Linux security mentor") != NULL);
    // Verify string escaping
    assert(strstr(payload, "Brute Force") != NULL);
    assert(strstr(payload, "\\\\\\\"Brute Force\\\\\\\"") != NULL);
    assert(strstr(payload, "root\\\\nadmin") != NULL);

    printf("  [PASS] llm_build_payload generated compliant JSON with proper escaping\n");
}

static void test_response_parser(void) {
    printf("[TEST] Running LLM Response Parser tests...\n");

    // Simulated Ollama /api/generate JSON response containing inner escaped JSON string
    const char *mock_ollama_response =
        "{\n"
        "  \"model\": \"deepseek-r1:7b\",\n"
        "  \"created_at\": \"2026-10-29T12:00:00Z\",\n"
        "  \"response\": \"{\\n"
        "    \\\"mentor_analysis\\\": \\\"Multiple failed SSH authentications detected from untrusted source 192.168.1.50.\\\",\\n"
        "    \\\"actions\\\": [\\n"
        "      {\\n"
        "        \\\"command\\\": \\\"ss -tulpn | grep :22\\\",\\n"
        "        \\\"explanation\\\": \\\"Verify which service is listening on port 22\\\"\\n"
        "      },\\n"
        "      {\\n"
        "        \\\"command\\\": \\\"ufw deny from 192.168.1.50\\\",\\n"
        "        \\\"explanation\\\": \\\"Block offending IP via uncomplicated firewall\\\"\\n"
        "      },\\n"
        "      {\\n"
        "        \\\"command\\\": \\\"rm -rf /var/log/auth.log\\\",\\n"
        "        \\\"explanation\\\": \\\"Destructive log deletion attempt\\\"\\n"
        "      }\\n"
        "    ]\\n"
        "  }\",\n"
        "  \"done\": true\n"
        "}";

    MentorResponse resp;
    char err_buf[256] = {0};
    int rc = llm_parse_response(mock_ollama_response, &resp, err_buf, sizeof(err_buf));
    assert(rc == 0);

    // Verify mentor analysis extraction
    assert(strstr(resp.mentor_analysis, "Multiple failed SSH authentications detected") != NULL);
    printf("  [PASS] mentor_analysis correctly parsed: \"%s\"\n", resp.mentor_analysis);

    // Verify actions and automatic CommandGuard integration
    assert(resp.action_count == 3);

    // Action 1: ss (Safe)
    assert(strcmp(resp.actions[0].command, "ss -tulpn | grep :22") == 0);
    assert(resp.actions[0].safety_level == CMD_SAFE);

    // Action 2: ufw deny (Caution)
    assert(strcmp(resp.actions[1].command, "ufw deny from 192.168.1.50") == 0);
    assert(resp.actions[1].safety_level == CMD_CAUTION);

    // Action 3: rm -rf (Blocked)
    assert(strcmp(resp.actions[2].command, "rm -rf /var/log/auth.log") == 0);
    assert(resp.actions[2].safety_level == CMD_BLOCKED);

    printf("  [PASS] Suggested actions parsed and correctly classified by Command Guard\n");

    // Test malformed JSON error handling
    const char *bad_json = "{\"response\": \"{\\\"bad\\\": true}\"}";
    MentorResponse bad_resp;
    rc = llm_parse_response(bad_json, &bad_resp, err_buf, sizeof(err_buf));
    assert(rc == -1);
    assert(strlen(err_buf) > 0);
    printf("  [PASS] Malformed JSON rejected with error: \"%s\"\n", err_buf);
}

static bool g_async_callback_fired = false;
static void test_async_cb(const MentorResponse *response, bool success, const char *error_msg, void *user_data) {
    (void)response;
    (void)error_msg;
    int *flag = (int *)user_data;
    *flag = 1;
    g_async_callback_fired = true;
    // Without Ollama running on localhost, success will be false, but thread dispatch must work
    (void)success;
}

static void test_async_dispatch(void) {
    printf("[TEST] Running Asynchronous Dispatch & Threading tests...\n");

    LLMConfig cfg = llm_config_default();
    cfg.connect_timeout_s = 1;
    cfg.total_timeout_s = 1;

    Incident inc = {
        .incident_id = "SEC-TEST-001",
        .category = "Test Incident",
        .source_ip = "127.0.0.1",
        .target_user = "nobody",
        .frequency_count = 1,
        .first_seen = 1000,
        .last_seen = 1001,
        .severity = SEV_INFO,
        .raw_log_excerpt = "Test log"
    };

    int user_context_val = 0;
    int rc = llm_query_async(&cfg, &inc, test_async_cb, &user_context_val);
    assert(rc == 0);

    // Wait a brief period for background worker thread to execute
    for (int i = 0; i < 20 && !g_async_callback_fired; i++) {
        usleep(50000);
    }

    assert(g_async_callback_fired == true);
    assert(user_context_val == 1);
    printf("  [PASS] llm_query_async executed on background thread and safely triggered callback\n");
}

int main(void) {
    printf("================================================================\n");
    printf("   Grit LLM Orchestration Client Verification Suite            \n");
    printf("================================================================\n");

    llm_client_init();

    test_config_and_payload_builder();
    test_response_parser();
    test_async_dispatch();

    llm_client_cleanup();

    printf("\nAll LLM client tests passed successfully!\n");
    return 0;
}
