#define _GNU_SOURCE
#include "command_guard.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

static bool is_token_boundary(char c) {
    return (c == '\0' || isspace((unsigned char)c) || c == ';' || c == '|' ||
            c == '&' || c == '>' || c == '<' || c == '(' || c == ')' ||
            c == '"' || c == '\'' || c == '`' || c == ':');
}

// Checks if a binary/word exists as a standalone token or command prefix
static bool contains_word(const char *cmd, const char *word) {
    if (!cmd || !word) return false;
    size_t wlen = strlen(word);
    const char *p = cmd;

    while ((p = strstr(p, word)) != NULL) {
        bool left_bound = (p == cmd || is_token_boundary(*(p - 1)) || *(p - 1) == '/');
        char right_char = *(p + wlen);
        bool right_bound = is_token_boundary(right_char) ||
                           (strcmp(word, "mkfs") == 0 && right_char == '.');

        if (left_bound && right_bound) {
            return true;
        }
        p += wlen;
    }
    return false;
}

// Denylist patterns: destructive commands or arbitrary execution
static const char *s_denylist_binaries[] = {
    "rm",
    "rmdir",
    "dd",
    "mkfs",
    "fdisk",
    "cfdisk",
    "sfdisk",
    "parted",
    "gdisk",
    "wipefs",
    "shred",
    "blkdiscard",
    "format",
    "reboot",
    "shutdown",
    "poweroff",
    "halt",
    "init",
    NULL
};

// Safe allowlist: read-only observational tools
static const char *s_safe_binaries[] = {
    "ss",
    "netstat",
    "ps",
    "cat",
    "less",
    "more",
    "head",
    "tail",
    "grep",
    "egrep",
    "fgrep",
    "zgrep",
    "journalctl",
    "dmesg",
    "lsof",
    "ip",
    "uptime",
    "who",
    "w",
    "id",
    "whoami",
    "last",
    "lastb",
    "faillog",
    "df",
    "du",
    "free",
    "uname",
    "top",
    "htop",
    "stat",
    "file",
    "ls",
    "sha256sum",
    "md5sum",
    "diff",
    "awk",
    "sed",
    "cut",
    "tr",
    "sort",
    "uniq",
    "wc",
    NULL
};

// State-modifying / caution binaries
static const char *s_caution_binaries[] = {
    "kill",
    "pkill",
    "killall",
    "chmod",
    "chown",
    "chgrp",
    "systemctl",
    "service",
    "ufw",
    "iptables",
    "ip6tables",
    "nft",
    "passwd",
    "usermod",
    "userdel",
    "useradd",
    "groupadd",
    "groupdel",
    "touch",
    "cp",
    "mv",
    "ln",
    "truncate",
    "tee",
    "apt",
    "apt-get",
    "dpkg",
    NULL
};

CommandSafety evaluate_command_safety(const char *raw_command) {
    if (!raw_command) {
        return CMD_BLOCKED;
    }

    // Skip leading whitespace
    while (isspace((unsigned char)*raw_command)) {
        raw_command++;
    }
    if (*raw_command == '\0') {
        return CMD_BLOCKED;
    }

    // 1. Check for command injection, subshells, dangerous expansion
    if (strchr(raw_command, '`') != NULL ||
        strstr(raw_command, "$(") != NULL ||
        strstr(raw_command, "${") != NULL) {
        return CMD_BLOCKED;
    }

    // Check for piping directly into an interpreter or shell
    if (strstr(raw_command, "| sh") != NULL ||
        strstr(raw_command, "| bash") != NULL ||
        strstr(raw_command, "| zsh") != NULL ||
        strstr(raw_command, "| sudo sh") != NULL ||
        strstr(raw_command, "| sudo bash") != NULL ||
        strstr(raw_command, "| python") != NULL ||
        strstr(raw_command, "| perl") != NULL) {
        return CMD_BLOCKED;
    }

    // Check for reverse shells or direct raw socket connections
    if (strstr(raw_command, "/dev/tcp/") != NULL ||
        strstr(raw_command, "/dev/udp/") != NULL ||
        strstr(raw_command, "nc -e") != NULL ||
        strstr(raw_command, "ncat -e") != NULL) {
        return CMD_BLOCKED;
    }

    // Check for destructive redirection to device files or core directories
    if (strstr(raw_command, "> /dev/sd") != NULL ||
        strstr(raw_command, "> /dev/nvme") != NULL ||
        strstr(raw_command, "> /etc/") != NULL ||
        strstr(raw_command, "> /boot/") != NULL ||
        strstr(raw_command, "> /sys/") != NULL ||
        strstr(raw_command, "> /proc/") != NULL) {
        return CMD_BLOCKED;
    }

    // Check for destructive recursive permission changes or wipes
    if ((strstr(raw_command, "chmod") != NULL || strstr(raw_command, "chown") != NULL) &&
        (strstr(raw_command, "-R 777") != NULL || strstr(raw_command, "-R 000") != NULL ||
         strstr(raw_command, "-R") != NULL)) {
        return CMD_BLOCKED;
    }

    // Check for firewall flush commands that drop network security
    if (strstr(raw_command, "iptables -F") != NULL ||
        strstr(raw_command, "ufw reset") != NULL ||
        strstr(raw_command, "nft flush") != NULL) {
        return CMD_BLOCKED;
    }

    // 2. Explicit Denylist Check
    for (size_t i = 0; s_denylist_binaries[i] != NULL; i++) {
        if (contains_word(raw_command, s_denylist_binaries[i])) {
            return CMD_BLOCKED;
        }
    }

    // 3. Inspect Safe commands with dangerous flags
    // If output redirection exists (> or >>), the command is modifying file state
    if (strchr(raw_command, '>') != NULL) {
        return CMD_CAUTION;
    }

    // Check for find with destructive flags
    if (contains_word(raw_command, "find")) {
        if (strstr(raw_command, "-delete") != NULL ||
            strstr(raw_command, "-exec") != NULL ||
            strstr(raw_command, "-execdir") != NULL) {
            return CMD_BLOCKED;
        }
    }

    // Check for sed in-place flag
    if (contains_word(raw_command, "sed")) {
        if (strstr(raw_command, "-i") != NULL) {
            return CMD_CAUTION;
        }
    }

    // Check for caution binaries (kill, chmod, systemctl, etc.)
    for (size_t i = 0; s_caution_binaries[i] != NULL; i++) {
        if (contains_word(raw_command, s_caution_binaries[i])) {
            // Exception: systemctl status, ufw status, iptables -L, iptables -S are safe
            if (strcmp(s_caution_binaries[i], "systemctl") == 0 && strstr(raw_command, "status") != NULL) {
                return CMD_SAFE;
            }
            if (strcmp(s_caution_binaries[i], "ufw") == 0 && strstr(raw_command, "status") != NULL) {
                return CMD_SAFE;
            }
            if ((strcmp(s_caution_binaries[i], "iptables") == 0 || strcmp(s_caution_binaries[i], "ip6tables") == 0) &&
                (strstr(raw_command, "-L") != NULL || strstr(raw_command, "-S") != NULL)) {
                return CMD_SAFE;
            }
            return CMD_CAUTION;
        }
    }

    // 4. Explicit Allowlist Check
    for (size_t i = 0; s_safe_binaries[i] != NULL; i++) {
        if (contains_word(raw_command, s_safe_binaries[i])) {
            return CMD_SAFE;
        }
    }

    // Default: defense in depth, any unrecognized command is treated as CAUTION
    return CMD_CAUTION;
}

const char *command_safety_to_string(CommandSafety safety) {
    switch (safety) {
        case CMD_SAFE:
            return "SAFE (Read-Only)";
        case CMD_CAUTION:
            return "CAUTION (State-Modifying)";
        case CMD_BLOCKED:
            return "BLOCKED (Destructive)";
        default:
            return "UNKNOWN";
    }
}
