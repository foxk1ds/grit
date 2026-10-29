#define _GNU_SOURCE
#include "simulator.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

const char *simulator_scenario_name(ScenarioType type) {
    switch (type) {
        case SCENARIO_SSH_BRUTE_FORCE:
            return "SSH Brute Force Attack (203.0.113.42)";
        case SCENARIO_SUDO_ESCALATION:
            return "Privilege Escalation Attempt (sudo /usr/bin/su)";
        case SCENARIO_REDACTION_VALIDATION:
            return "Real-Time Credential Redaction Verification";
        default:
            return "Unknown Scenario";
    }
}

bool simulator_parse_type(const char *name, ScenarioType *out_type) {
    if (!name || !out_type) return false;

    if (strcmp(name, "ssh_brute") == 0 || strcmp(name, "ssh") == 0) {
        *out_type = SCENARIO_SSH_BRUTE_FORCE;
        return true;
    }
    if (strcmp(name, "sudo_abuse") == 0 || strcmp(name, "sudo") == 0) {
        *out_type = SCENARIO_SUDO_ESCALATION;
        return true;
    }
    if (strcmp(name, "redaction_test") == 0 || strcmp(name, "redaction") == 0) {
        *out_type = SCENARIO_REDACTION_VALIDATION;
        return true;
    }
    return false;
}

bool simulator_inject_scenario(ScenarioType type, const char *target_log_path) {
    const char *path = (target_log_path && target_log_path[0] != '\0')
                       ? target_log_path
                       : "/tmp/grit_test_auth.log";

    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        fprintf(stderr, "[Simulator] Failed to open target log file '%s': %s\n", path, strerror(errno));
        return false;
    }

    char buffer[2048];
    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    char ts[32];
    strftime(ts, sizeof(ts), "%b %e %H:%M:%S", &tm_info);

    switch (type) {
        case SCENARIO_SSH_BRUTE_FORCE: {
            // 6 failed SSH login attempts from 203.0.113.42 spaced across 150ms intervals
            const char *probe_users[] = {"root", "ubuntu", "admin", "postgres", "deploy", "admin"};
            for (int i = 0; i < 6; i++) {
                int port = 49152 + i;
                int len = snprintf(buffer, sizeof(buffer),
                    "%s host sshd[%d]: Failed password for invalid user %s from 203.0.113.42 port %d ssh2\n",
                    ts, 28100 + i, probe_users[i], port);

                if (len > 0) {
                    ssize_t w = write(fd, buffer, (size_t)len);
                    (void)w;
                    fsync(fd);
                }
                if (i < 5) {
                    usleep(150000); // 150ms interval between attack attempts
                }
            }
            break;
        }

        case SCENARIO_SUDO_ESCALATION: {
            // 3 bad password attempts attempting sudo /usr/bin/su
            for (int i = 1; i <= 3; i++) {
                int len = snprintf(buffer, sizeof(buffer),
                    "%s host sudo: pam_unix(sudo:auth): authentication failure; logname=alice uid=1001 euid=0 tty=/dev/pts/1 ruser=alice rhost= user=root\n",
                    ts);
                if (len > 0) {
                    ssize_t w = write(fd, buffer, (size_t)len);
                    (void)w;
                    fsync(fd);
                }
                usleep(100000);
            }
            int final_len = snprintf(buffer, sizeof(buffer),
                "%s host sudo: alice : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/su\n",
                ts);
            if (final_len > 0) {
                ssize_t w = write(fd, buffer, (size_t)final_len);
                (void)w;
                fsync(fd);
            }
            break;
        }

        case SCENARIO_REDACTION_VALIDATION: {
            // Injects private key header, cleartext password, and mock JWT token
            int len = snprintf(buffer, sizeof(buffer),
                "%s host test-service[9999]: Auth failure token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c "
                "context: password=SuperSecret123 key=-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...SECRET_PRIVATE_KEY...==\n-----END RSA PRIVATE KEY-----\n",
                ts);
            if (len > 0) {
                ssize_t w = write(fd, buffer, (size_t)len);
                (void)w;
                fsync(fd);
            }
            break;
        }
    }

    close(fd);
    return true;
}
