#define _GNU_SOURCE
#include "watcher.h"
#include "db/db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/inotify.h>
#include <sys/eventfd.h>
#include <regex.h>
#include <time.h>

// Global observer callback & context (thread-safe synchronization)
static pthread_mutex_t s_observer_mutex = PTHREAD_MUTEX_INITIALIZER;
static IncidentObserverCallback s_observer_cb = NULL;
static void *s_observer_user_data = NULL;

void watcher_register_observer(IncidentObserverCallback callback, void *user_data) {
    pthread_mutex_lock(&s_observer_mutex);
    s_observer_cb = callback;
    s_observer_user_data = user_data;
    pthread_mutex_unlock(&s_observer_mutex);
}

static void notify_incident(const Incident *inc) {
    pthread_mutex_lock(&s_observer_mutex);
    if (s_observer_cb) {
        s_observer_cb(inc, s_observer_user_data);
    }
    pthread_mutex_unlock(&s_observer_mutex);
}

/*
 * Redaction Engine
 * Before Incident.raw_log_excerpt is populated, regex MUST strip:
 * 1. Private keys
 * 2. Passwords in cleartext
 * 3. JWTs
 * Replace with <REDACTED>
 */
static void apply_regex_redaction(const char *in_str, char *out_str, size_t out_max,
                                  const char *pattern, int cflags, const char *replacement) {
    if (!in_str || !out_str || out_max == 0) return;

    regex_t re;
    if (regcomp(&re, pattern, cflags) != 0) {
        // Fallback: copy as much as possible if regex compilation failed
        snprintf(out_str, out_max, "%s", in_str);
        return;
    }

    size_t repl_len = strlen(replacement);
    size_t out_pos = 0;
    const char *cursor = in_str;
    regmatch_t match;

    out_str[0] = '\0';

    while (*cursor != '\0' && out_pos + 1 < out_max) {
        if (regexec(&re, cursor, 1, &match, 0) == 0) {
            // Copy prefix before match
            size_t prefix_len = (size_t)match.rm_so;
            if (out_pos + prefix_len >= out_max) {
                prefix_len = out_max - out_pos - 1;
            }
            memcpy(out_str + out_pos, cursor, prefix_len);
            out_pos += prefix_len;
            out_str[out_pos] = '\0';

            // Insert replacement
            if (out_pos + repl_len < out_max) {
                memcpy(out_str + out_pos, replacement, repl_len);
                out_pos += repl_len;
                out_str[out_pos] = '\0';
            }

            // Move cursor past match
            cursor += match.rm_eo;
        } else {
            // No more matches, copy the remaining string
            size_t rem_len = strlen(cursor);
            if (out_pos + rem_len >= out_max) {
                rem_len = out_max - out_pos - 1;
            }
            memcpy(out_str + out_pos, cursor, rem_len);
            out_pos += rem_len;
            out_str[out_pos] = '\0';
            break;
        }
    }

    out_str[out_max - 1] = '\0';
    regfree(&re);
}

void redact_sensitive_data(const char *input, char *output, size_t max_len) {
    if (!input || !output || max_len == 0) return;

    char stage1[1024];
    char stage2[1024];

    // Stage 1: Strip Private Keys
    // Matches standard PEM private key blocks: -----BEGIN ... PRIVATE KEY----- ... -----END ... PRIVATE KEY-----
    const char *key_pattern = "-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[^-]*-----END [A-Z0-9 ]*PRIVATE KEY-----";
    apply_regex_redaction(input, stage1, sizeof(stage1), key_pattern, REG_EXTENDED, "<REDACTED>");

    // Stage 2: Strip Passwords in cleartext
    // Matches password=xyz, password: xyz, pwd=xyz, passwd:xyz, etc.
    const char *pwd_pattern = "(password|passwd|pwd)[[:space:]]*[=:][[:space:]]*[^[:space:];,]+";
    apply_regex_redaction(stage1, stage2, sizeof(stage2), pwd_pattern, REG_EXTENDED | REG_ICASE, "<REDACTED>");

    // Stage 3: Strip JSON Web Tokens (JWT)
    // Matches base64url encoded tokens eyJ...
    const char *jwt_pattern = "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]+";
    apply_regex_redaction(stage2, output, max_len, jwt_pattern, REG_EXTENDED, "<REDACTED>");
}

static void parse_and_process_line(const char *line) {
    if (!line || strlen(line) == 0) return;

    // Check for SSH authentication failures
    // e.g., "Failed password for invalid user root from 192.168.1.50 port 55432 ssh2"
    // e.g., "Failed password for admin from 10.0.0.2 port 42111 ssh2"
    static int incident_counter = 1;
    static int ssh_fail_freq = 0;
    static time_t first_ssh_time = 0;

    char user[64] = "unknown";
    char ip[46] = "0.0.0.0";
    bool matched = false;
    char category[64] = "Security Log Event";
    IncidentSeverity sev = SEV_INFO;

    if (strstr(line, "Failed password") != NULL) {
        matched = true;
        ssh_fail_freq++;
        if (first_ssh_time == 0) first_ssh_time = time(NULL);

        strncpy(category, "SSH Brute Force", sizeof(category) - 1);
        if (ssh_fail_freq > 20) {
            sev = SEV_CRIT;
        } else if (ssh_fail_freq > 5) {
            sev = SEV_WARN;
        } else {
            sev = SEV_INFO;
        }

        // Extract user
        const char *user_ptr = strstr(line, "for invalid user ");
        if (user_ptr) {
            user_ptr += strlen("for invalid user ");
            sscanf(user_ptr, "%63s", user);
        } else {
            user_ptr = strstr(line, "for ");
            if (user_ptr) {
                user_ptr += strlen("for ");
                sscanf(user_ptr, "%63s", user);
            }
        }

        // Extract IP
        const char *from_ptr = strstr(line, "from ");
        if (from_ptr) {
            from_ptr += strlen("from ");
            sscanf(from_ptr, "%45s", ip);
        }
    } else if (strstr(line, "authentication failure") != NULL || strstr(line, "FAILED SU") != NULL) {
        matched = true;
        strncpy(category, "Privilege Escalation Attempt", sizeof(category) - 1);
        sev = SEV_WARN;
        const char *user_ptr = strstr(line, "user=");
        if (user_ptr) {
            user_ptr += strlen("user=");
            sscanf(user_ptr, "%63s", user);
        }
        const char *rhost_ptr = strstr(line, "rhost=");
        if (rhost_ptr) {
            rhost_ptr += strlen("rhost=");
            sscanf(rhost_ptr, "%45s", ip);
        }
    }

    if (matched) {
        Incident inc;
        memset(&inc, 0, sizeof(inc));

        time_t now = time(NULL);
        snprintf(inc.incident_id, sizeof(inc.incident_id), "SEC-%ld-%03d", (long)now, incident_counter++);
        snprintf(inc.category, sizeof(inc.category), "%s", category);
        snprintf(inc.source_ip, sizeof(inc.source_ip), "%s", ip);
        snprintf(inc.target_user, sizeof(inc.target_user), "%s", user);
        inc.frequency_count = ssh_fail_freq > 0 ? ssh_fail_freq : 1;
        inc.first_seen = first_ssh_time > 0 ? first_ssh_time : now;
        inc.last_seen = now;
        inc.severity = sev;

        // Apply Redaction Engine to raw_log_excerpt before storage/transmission
        redact_sensitive_data(line, inc.raw_log_excerpt, sizeof(inc.raw_log_excerpt));

        // Persist to SQLite3 database
        grit_db_save_incident(&inc, NULL);

        notify_incident(&inc);
    }
}

// Background thread loop strictly implementing poll() on inotify_fd & event_fd
static void *watcher_thread_func(void *arg) {
    WatcherContext *ctx = (WatcherContext *)arg;
    if (!ctx) pthread_exit(NULL);

    int wd = -1;
    if (ctx->inotify_fd >= 0) {
        wd = inotify_add_watch(ctx->inotify_fd, ctx->target_file,
                               IN_MODIFY | IN_ATTRIB | IN_MOVE_SELF | IN_DELETE_SELF);
    }

    FILE *fp = fopen(ctx->target_file, "r");
    if (fp) {
        fseek(fp, 0, SEEK_END);
    }

    struct pollfd fds[2];
    fds[0].fd = ctx->inotify_fd;
    fds[0].events = POLLIN;
    fds[1].fd = ctx->event_fd;
    fds[1].events = POLLIN;

    while (atomic_load(&ctx->is_running)) {
        // poll() blocks until inotify event or eventfd interruption
        int ret = poll(fds, 2, -1);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        // High priority: event_fd readable -> IMMEDIATE SHUTDOWN (0ms latency)
        if (fds[1].revents & (POLLIN | POLLERR | POLLHUP)) {
            uint64_t val = 0;
            ssize_t s = read(ctx->event_fd, &val, sizeof(val));
            (void)s;
            // Free thread resources and exit immediately
            break;
        }

        // inotify_fd readable -> log file update
        if (fds[0].revents & (POLLIN | POLLERR | POLLHUP)) {
            char buffer[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
            ssize_t len;
            bool target_modified = false;

            while ((len = read(ctx->inotify_fd, buffer, sizeof(buffer))) > 0) {
                const struct inotify_event *event;
                for (char *ptr = buffer; ptr < buffer + len;
                     ptr += sizeof(struct inotify_event) + event->len) {
                    event = (const struct inotify_event *)ptr;
                    if (event->mask & IN_MODIFY) {
                        target_modified = true;
                    }
                    if (event->mask & (IN_DELETE_SELF | IN_MOVE_SELF)) {
                        // File was rotated or deleted; re-arm watch
                        if (wd >= 0) inotify_rm_watch(ctx->inotify_fd, wd);
                        wd = inotify_add_watch(ctx->inotify_fd, ctx->target_file,
                                               IN_MODIFY | IN_ATTRIB | IN_MOVE_SELF | IN_DELETE_SELF);
                        if (fp) fclose(fp);
                        fp = fopen(ctx->target_file, "r");
                        target_modified = true;
                    }
                }
            }

            if (target_modified) {
                if (!fp) {
                    fp = fopen(ctx->target_file, "r");
                }
                if (fp) {
                    char line_buf[1024];
                    while (fgets(line_buf, sizeof(line_buf), fp)) {
                        // Strip trailing newline
                        size_t l = strlen(line_buf);
                        while (l > 0 && (line_buf[l - 1] == '\n' || line_buf[l - 1] == '\r')) {
                            line_buf[--l] = '\0';
                        }
                        if (l > 0) {
                            parse_and_process_line(line_buf);
                        }
                    }
                }
            }
        }
    }

    // Clean resource cleanup before exit
    if (wd >= 0 && ctx->inotify_fd >= 0) {
        inotify_rm_watch(ctx->inotify_fd, wd);
    }
    if (fp) {
        fclose(fp);
        fp = NULL;
    }

    pthread_exit(NULL);
    return NULL;
}

int watcher_init(WatcherContext *ctx, const char *filepath) {
    if (!ctx || !filepath) return -1;

    atomic_init(&ctx->is_running, false);
    ctx->thread_id = 0;

    ctx->inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (ctx->inotify_fd < 0) {
        return -1;
    }

    ctx->event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (ctx->event_fd < 0) {
        close(ctx->inotify_fd);
        ctx->inotify_fd = -1;
        return -1;
    }

    strncpy(ctx->target_file, filepath, sizeof(ctx->target_file) - 1);
    ctx->target_file[sizeof(ctx->target_file) - 1] = '\0';

    return 0;
}

int watcher_start(WatcherContext *ctx) {
    if (!ctx) return -1;

    // Check if thread is already running
    if (atomic_load(&ctx->is_running)) {
        return 0;
    }

    // Reinitialize descriptors if previously destroyed
    if (ctx->inotify_fd < 0) {
        ctx->inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (ctx->inotify_fd < 0) return -1;
    }
    if (ctx->event_fd < 0) {
        ctx->event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (ctx->event_fd < 0) return -1;
    }

    // Flush any pending eventfd counter
    uint64_t flush_val = 0;
    ssize_t s = read(ctx->event_fd, &flush_val, sizeof(flush_val));
    (void)s;

    atomic_store(&ctx->is_running, true);

    int rc = pthread_create(&ctx->thread_id, NULL, watcher_thread_func, ctx);
    if (rc != 0) {
        atomic_store(&ctx->is_running, false);
        return -1;
    }

    return 0;
}

void watcher_stop(WatcherContext *ctx) {
    if (!ctx) return;

    if (!atomic_load(&ctx->is_running)) {
        return;
    }

    // Signal state change
    atomic_store(&ctx->is_running, false);

    // MUST write to event_fd to break poll() with 0ms latency
    uint64_t signal_val = 1;
    ssize_t w = write(ctx->event_fd, &signal_val, sizeof(signal_val));
    (void)w;

    // Await clean thread termination
    if (ctx->thread_id != 0) {
        pthread_join(ctx->thread_id, NULL);
        ctx->thread_id = 0;
    }
}

void watcher_destroy(WatcherContext *ctx) {
    if (!ctx) return;

    watcher_stop(ctx);

    if (ctx->inotify_fd >= 0) {
        close(ctx->inotify_fd);
        ctx->inotify_fd = -1;
    }
    if (ctx->event_fd >= 0) {
        close(ctx->event_fd);
        ctx->event_fd = -1;
    }
}
