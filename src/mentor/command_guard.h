#ifndef GRIT_MENTOR_COMMAND_GUARD_H
#define GRIT_MENTOR_COMMAND_GUARD_H

#include "core/types.h"

/*
 * Evaluates command safety using an explicit allowlist/denylist logic tree.
 * Returns:
 *   CMD_SAFE    : Read-only observational commands (ss, cat, ps, grep, journalctl, etc.)
 *   CMD_CAUTION : State-modifying operations (kill, chmod, systemctl restart, ufw allow/deny, etc.)
 *   CMD_BLOCKED : Destructive commands, shell injection patterns, command chaining vulnerabilities (rm, dd, mkfs, > /dev/..., etc.)
 */
CommandSafety evaluate_command_safety(const char *raw_command);

/*
 * Alias for evaluate_command_safety
 */
static inline CommandSafety command_guard_classify(const char *raw_command) {
    return evaluate_command_safety(raw_command);
}

/*
 * Returns a human-readable safety tier string for UI badges.
 */
const char *command_safety_to_string(CommandSafety safety);

#endif // GRIT_MENTOR_COMMAND_GUARD_H
