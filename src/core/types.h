#ifndef GRIT_CORE_TYPES_H
#define GRIT_CORE_TYPES_H

#include <time.h>
#include <stddef.h>

typedef enum {
    SEV_INFO = 0,
    SEV_WARN,
    SEV_CRIT
} IncidentSeverity;

typedef enum {
    CMD_SAFE = 0,     // Read-only (ss, cat, ps)
    CMD_CAUTION,      // State-modifying (kill, chmod)
    CMD_BLOCKED       // Destructive (rm -rf, dd)
} CommandSafety;

typedef struct {
    char incident_id[32];     // e.g., "SEC-1704100000-001"
    char category[64];        // e.g., "SSH Brute Force"
    char source_ip[46];       // IPv4/IPv6 address
    char target_user[64];
    int frequency_count;
    time_t first_seen;
    time_t last_seen;
    IncidentSeverity severity;
    char raw_log_excerpt[512]; // Sanitized!
} Incident;

typedef struct {
    char command[256];
    CommandSafety safety_level;
    char explanation[512];
} SuggestedAction;

typedef struct {
    char mentor_analysis[2048];
    SuggestedAction actions[3];
    size_t action_count;
} MentorResponse;

#endif // GRIT_CORE_TYPES_H
