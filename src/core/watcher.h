 #ifndef GRIT_CORE_WATCHER_H
#define GRIT_CORE_WATCHER_H

#include <stdatomic.h>
#include <pthread.h>
#include <stddef.h>
#include "types.h"

typedef struct {
    atomic_bool is_running;
    int inotify_fd;
    int event_fd;          // Used for instant shutdown signaling
    pthread_t thread_id;
    char target_file[256]; // e.g., "/var/log/auth.log"
} WatcherContext;

// Signatures
int watcher_init(WatcherContext *ctx, const char *filepath);
int watcher_start(WatcherContext *ctx);
void watcher_stop(WatcherContext *ctx); // MUST write to event_fd to break poll()

// Resource teardown for file descriptors
void watcher_destroy(WatcherContext *ctx);

// Security & Redaction Engine
// Strips private keys, cleartext passwords, and JWTs, replacing with <REDACTED>
void redact_sensitive_data(const char *input, char *output, size_t max_len);

// Log analysis callback signature
typedef void (*IncidentObserverCallback)(const Incident *incident, void *user_data);
void watcher_register_observer(IncidentObserverCallback callback, void *user_data);

#endif // GRIT_CORE_WATCHER_H
