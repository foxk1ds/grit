#ifndef GRIT_CORE_SIMULATOR_H
#define GRIT_CORE_SIMULATOR_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
    SCENARIO_SSH_BRUTE_FORCE = 0,
    SCENARIO_SUDO_ESCALATION,
    SCENARIO_REDACTION_VALIDATION
} ScenarioType;

/*
 * Injects realistic attack scenarios into the target log file.
 * Uses unbuffered POSIX write() + fsync() to trigger inotify IN_MODIFY immediately.
 * If target_log_path is NULL, defaults to "/tmp/grit_test_auth.log".
 */
bool simulator_inject_scenario(ScenarioType type, const char *target_log_path);

/*
 * Returns a human-readable name for the scenario type.
 */
const char *simulator_scenario_name(ScenarioType type);

/*
 * Parses scenario name string from CLI ("ssh_brute", "sudo_abuse", "redaction_test")
 */
bool simulator_parse_type(const char *name, ScenarioType *out_type);

#endif // GRIT_CORE_SIMULATOR_H
