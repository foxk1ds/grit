#define _GNU_SOURCE
#include "db.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <pthread.h>

static sqlite3 *s_db = NULL;
static pthread_mutex_t s_db_mutex = PTHREAD_MUTEX_INITIALIZER;

// Embedded DDL schema
static const char *s_schema_ddl =
    "PRAGMA foreign_keys = ON;\n"
    "PRAGMA journal_mode = WAL;\n"
    "PRAGMA synchronous = NORMAL;\n"
    "\n"
    "CREATE TABLE IF NOT EXISTS incidents (\n"
    "    id TEXT PRIMARY KEY,\n"
    "    timestamp INTEGER NOT NULL,\n"
    "    severity INTEGER NOT NULL,\n"
    "    raw_log TEXT NOT NULL,\n"
    "    source_path TEXT NOT NULL,\n"
    "    resolved INTEGER DEFAULT 0\n"
    ");\n"
    "\n"
    "CREATE TABLE IF NOT EXISTS mentor_sessions (\n"
    "    id TEXT PRIMARY KEY,\n"
    "    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,\n"
    "    summary TEXT NOT NULL,\n"
    "    diagnostic_question TEXT NOT NULL,\n"
    "    created_at INTEGER NOT NULL\n"
    ");\n"
    "\n"
    "CREATE TABLE IF NOT EXISTS mentor_commands (\n"
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
    "    session_id TEXT NOT NULL REFERENCES mentor_sessions(id) ON DELETE CASCADE,\n"
    "    command TEXT NOT NULL,\n"
    "    safety_level INTEGER NOT NULL,\n"
    "    purpose TEXT NOT NULL\n"
    ");\n"
    "\n"
    "CREATE TABLE IF NOT EXISTS chat_messages (\n"
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
    "    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,\n"
    "    sender TEXT NOT NULL CHECK(sender IN ('user', 'mentor')),\n"
    "    content TEXT NOT NULL,\n"
    "    timestamp INTEGER NOT NULL\n"
    ");\n"
    "\n"
    "CREATE TABLE IF NOT EXISTS user_skills (\n"
    "    skill_name TEXT PRIMARY KEY,\n"
    "    xp INTEGER NOT NULL DEFAULT 0,\n"
    "    level INTEGER GENERATED ALWAYS AS (xp / 100) VIRTUAL\n"
    ");\n"
    "\n"
    "INSERT OR IGNORE INTO incidents (id, timestamp, severity, raw_log, source_path, resolved) VALUES\n"
    "    ('GLOBAL', 0, 0, 'Global Conversation Stream', 'system', 1);\n"
    "\n"
    "INSERT OR IGNORE INTO user_skills (skill_name, xp) VALUES\n"
    "    ('Brute Force Triage', 120),\n"
    "    ('Privilege Escalation', 60),\n"
    "    ('Credential Hygiene', 180),\n"
    "    ('Network Auditing', 90),\n"
    "    ('Firewall Hardening', 40);\n";

// Helper to recursively create directories with 0700 permissions
static bool ensure_directory_exists(const char *dir_path) {
    if (!dir_path || dir_path[0] == '\0') return false;

    char temp[512];
    snprintf(temp, sizeof(temp), "%s", dir_path);
    size_t len = strlen(temp);

    for (size_t i = 1; i < len; i++) {
        if (temp[i] == '/') {
            temp[i] = '\0';
            if (mkdir(temp, 0700) != 0 && errno != EEXIST) {
                return false;
            }
            temp[i] = '/';
        }
    }

    if (mkdir(temp, 0700) != 0 && errno != EEXIST) {
        return false;
    }
    return true;
}

// Resolves XDG data directory path
static void get_default_db_path(char *out_path, size_t max_len) {
    const char *xdg_data = getenv("XDG_DATA_HOME");
    if (xdg_data && xdg_data[0] != '\0') {
        snprintf(out_path, max_len, "%s/grit/grit.db", xdg_data);
    } else {
        const char *home = getenv("HOME");
        if (home && home[0] != '\0') {
            snprintf(out_path, max_len, "%s/.local/share/grit/grit.db", home);
        } else {
            snprintf(out_path, max_len, "/tmp/grit/grit.db");
        }
    }
}

bool grit_db_init(const char *custom_path) {
    pthread_mutex_lock(&s_db_mutex);

    if (s_db != NULL) {
        pthread_mutex_unlock(&s_db_mutex);
        return true; // Already initialized
    }

    char db_file[512];
    if (custom_path && custom_path[0] != '\0') {
        snprintf(db_file, sizeof(db_file), "%s", custom_path);
    } else {
        get_default_db_path(db_file, sizeof(db_file));
    }

    // Ensure parent directory exists with 0700 permissions
    char dir_path[512];
    snprintf(dir_path, sizeof(dir_path), "%s", db_file);
    char *last_slash = strrchr(dir_path, '/');
    if (last_slash) {
        *last_slash = '\0';
        ensure_directory_exists(dir_path);
    }

    int rc = sqlite3_open_v2(db_file, &s_db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (rc != SQLITE_OK && custom_path == NULL) {
        // Fallback to /tmp if default home directory is read-only (e.g. containers / sandboxes)
        snprintf(db_file, sizeof(db_file), "/tmp/grit_db.sqlite");
        rc = sqlite3_open_v2(db_file, &s_db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    }
    if (rc != SQLITE_OK) {
        if (s_db) {
            sqlite3_close(s_db);
            s_db = NULL;
        }
        pthread_mutex_unlock(&s_db_mutex);
        return false;
    }

    // Apply Pragmas and run idempotent migration
    char *errmsg = NULL;
    rc = sqlite3_exec(s_db, s_schema_ddl, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        if (errmsg) {
            sqlite3_free(errmsg);
        }
        sqlite3_close(s_db);
        s_db = NULL;
        pthread_mutex_unlock(&s_db_mutex);
        return false;
    }

    pthread_mutex_unlock(&s_db_mutex);
    return true;
}

void grit_db_close(void) {
    pthread_mutex_lock(&s_db_mutex);
    if (s_db) {
        sqlite3_close(s_db);
        s_db = NULL;
    }
    pthread_mutex_unlock(&s_db_mutex);
}

bool grit_db_save_incident(const Incident *incident, const MentorResponse *response) {
    if (!incident) return false;

    pthread_mutex_lock(&s_db_mutex);
    if (!s_db) {
        pthread_mutex_unlock(&s_db_mutex);
        return false;
    }

    // 1. Insert or Replace into incidents
    const char *sql_inc =
        "INSERT OR REPLACE INTO incidents (id, timestamp, severity, raw_log, source_path, resolved) "
        "VALUES (?, ?, ?, ?, ?, 0);";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(s_db, sql_inc, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        pthread_mutex_unlock(&s_db_mutex);
        return false;
    }

    sqlite3_bind_text(stmt, 1, incident->incident_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)(incident->last_seen > 0 ? incident->last_seen : time(NULL)));
    sqlite3_bind_int(stmt, 3, (int)incident->severity);
    sqlite3_bind_text(stmt, 4, incident->raw_log_excerpt, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, incident->category, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        pthread_mutex_unlock(&s_db_mutex);
        return false;
    }

    // 2. Persist Mentor Session & Commands if response provided
    if (response) {
        char session_id[64];
        snprintf(session_id, sizeof(session_id), "SES-%s", incident->incident_id);

        const char *sql_session =
            "INSERT OR REPLACE INTO mentor_sessions (id, incident_id, summary, diagnostic_question, created_at) "
            "VALUES (?, ?, ?, ?, ?);";

        if (sqlite3_prepare_v2(s_db, sql_session, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, session_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, incident->incident_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 3, response->mentor_analysis, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 4, "What network ports or services are currently listening?", -1, SQLITE_STATIC);
            sqlite3_bind_int64(stmt, 5, (sqlite3_int64)time(NULL));
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }

        // Insert suggested actions
        const char *sql_cmd =
            "INSERT INTO mentor_commands (session_id, command, safety_level, purpose) VALUES (?, ?, ?, ?);";

        for (size_t i = 0; i < response->action_count && i < 3; i++) {
            if (sqlite3_prepare_v2(s_db, sql_cmd, -1, &stmt, NULL) == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, session_id, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 2, response->actions[i].command, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(stmt, 3, (int)response->actions[i].safety_level);
                sqlite3_bind_text(stmt, 4, response->actions[i].explanation, -1, SQLITE_TRANSIENT);
                sqlite3_step(stmt);
                sqlite3_finalize(stmt);
            }
        }
    }

    pthread_mutex_unlock(&s_db_mutex);
    return true;
}

bool grit_db_load_recent_incidents(Incident **out_incidents, size_t *out_count, size_t limit) {
    if (!out_incidents || !out_count) return false;
    *out_incidents = NULL;
    *out_count = 0;

    pthread_mutex_lock(&s_db_mutex);
    if (!s_db) {
        pthread_mutex_unlock(&s_db_mutex);
        return false;
    }

    const char *sql =
        "SELECT id, timestamp, severity, raw_log, source_path FROM incidents "
        "ORDER BY timestamp DESC LIMIT ?;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s_db_mutex);
        return false;
    }

    sqlite3_bind_int(stmt, 1, (int)(limit > 0 ? limit : 50));

    size_t capacity = 16;
    Incident *list = malloc(capacity * sizeof(Incident));
    if (!list) {
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&s_db_mutex);
        return false;
    }

    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (count >= capacity) {
            capacity *= 2;
            Incident *new_list = realloc(list, capacity * sizeof(Incident));
            if (!new_list) {
                free(list);
                sqlite3_finalize(stmt);
                pthread_mutex_unlock(&s_db_mutex);
                return false;
            }
            list = new_list;
        }

        Incident *inc = &list[count];
        memset(inc, 0, sizeof(Incident));

        const unsigned char *id = sqlite3_column_text(stmt, 0);
        sqlite3_int64 ts = sqlite3_column_int64(stmt, 1);
        int sev = sqlite3_column_int(stmt, 2);
        const unsigned char *raw = sqlite3_column_text(stmt, 3);
        const unsigned char *src = sqlite3_column_text(stmt, 4);

        if (id) snprintf(inc->incident_id, sizeof(inc->incident_id), "%s", (const char *)id);
        inc->first_seen = (time_t)ts;
        inc->last_seen = (time_t)ts;
        inc->severity = (IncidentSeverity)sev;
        if (raw) snprintf(inc->raw_log_excerpt, sizeof(inc->raw_log_excerpt), "%s", (const char *)raw);
        if (src) snprintf(inc->category, sizeof(inc->category), "%s", (const char *)src);

        count++;
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s_db_mutex);

    *out_incidents = list;
    *out_count = count;
    return true;
}

bool grit_db_save_chat_message(const char *incident_id, const char *sender, const char *message) {
    if (!incident_id || !sender || !message) return false;

    pthread_mutex_lock(&s_db_mutex);
    if (!s_db) {
        pthread_mutex_unlock(&s_db_mutex);
        return false;
    }

    // Ensure parent incident exists to satisfy foreign key constraint
    const char *sql_ensure_inc =
        "INSERT OR IGNORE INTO incidents (id, timestamp, severity, raw_log, source_path, resolved) "
        "VALUES (?, ?, 0, 'Active Investigation', 'chat', 0);";
    sqlite3_stmt *stmt_inc = NULL;
    if (sqlite3_prepare_v2(s_db, sql_ensure_inc, -1, &stmt_inc, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt_inc, 1, incident_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt_inc, 2, (sqlite3_int64)time(NULL));
        sqlite3_step(stmt_inc);
        sqlite3_finalize(stmt_inc);
    }

    const char *sql =
        "INSERT INTO chat_messages (incident_id, sender, content, timestamp) VALUES (?, ?, ?, ?);";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s_db_mutex);
        return false;
    }

    sqlite3_bind_text(stmt, 1, incident_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, sender, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, message, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)time(NULL));

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s_db_mutex);

    return (rc == SQLITE_DONE);
}

bool grit_db_load_chat_history(const char *incident_id, ChatMessage **out_messages, size_t *out_count) {
    if (!incident_id || !out_messages || !out_count) return false;
    *out_messages = NULL;
    *out_count = 0;

    pthread_mutex_lock(&s_db_mutex);
    if (!s_db) {
        pthread_mutex_unlock(&s_db_mutex);
        return false;
    }

    const char *sql =
        "SELECT sender, content, timestamp FROM chat_messages WHERE incident_id = ? ORDER BY id ASC;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s_db_mutex);
        return false;
    }

    sqlite3_bind_text(stmt, 1, incident_id, -1, SQLITE_TRANSIENT);

    size_t capacity = 8;
    ChatMessage *list = malloc(capacity * sizeof(ChatMessage));
    if (!list) {
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&s_db_mutex);
        return false;
    }

    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (count >= capacity) {
            capacity *= 2;
            ChatMessage *new_list = realloc(list, capacity * sizeof(ChatMessage));
            if (!new_list) {
                free(list);
                sqlite3_finalize(stmt);
                pthread_mutex_unlock(&s_db_mutex);
                return false;
            }
            list = new_list;
        }

        ChatMessage *msg = &list[count];
        memset(msg, 0, sizeof(ChatMessage));

        const unsigned char *sender = sqlite3_column_text(stmt, 0);
        const unsigned char *content = sqlite3_column_text(stmt, 1);
        sqlite3_int64 ts = sqlite3_column_int64(stmt, 2);

        if (sender) snprintf(msg->sender, sizeof(msg->sender), "%s", (const char *)sender);
        if (content) snprintf(msg->content, sizeof(msg->content), "%s", (const char *)content);
        msg->timestamp = (time_t)ts;

        count++;
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s_db_mutex);

    *out_messages = list;
    *out_count = count;
    return true;
}

bool grit_db_add_skill_xp(const char *skill_name, int xp_delta) {
    if (!skill_name) return false;

    pthread_mutex_lock(&s_db_mutex);
    if (!s_db) {
        pthread_mutex_unlock(&s_db_mutex);
        return false;
    }

    const char *sql =
        "INSERT INTO user_skills (skill_name, xp) VALUES (?, ?) "
        "ON CONFLICT(skill_name) DO UPDATE SET xp = MAX(0, user_skills.xp + excluded.xp);";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s_db_mutex);
        return false;
    }

    sqlite3_bind_text(stmt, 1, skill_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, xp_delta);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s_db_mutex);

    return (rc == SQLITE_DONE);
}

bool grit_db_get_skill_tree(SkillNode **out_skills, size_t *out_count) {
    if (!out_skills || !out_count) return false;
    *out_skills = NULL;
    *out_count = 0;

    pthread_mutex_lock(&s_db_mutex);
    if (!s_db) {
        pthread_mutex_unlock(&s_db_mutex);
        return false;
    }

    const char *sql = "SELECT skill_name, xp, level FROM user_skills ORDER BY skill_name ASC;";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(s_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&s_db_mutex);
        return false;
    }

    size_t capacity = 8;
    SkillNode *list = malloc(capacity * sizeof(SkillNode));
    if (!list) {
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&s_db_mutex);
        return false;
    }

    size_t count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (count >= capacity) {
            capacity *= 2;
            SkillNode *new_list = realloc(list, capacity * sizeof(SkillNode));
            if (!new_list) {
                free(list);
                sqlite3_finalize(stmt);
                pthread_mutex_unlock(&s_db_mutex);
                return false;
            }
            list = new_list;
        }

        SkillNode *node = &list[count];
        memset(node, 0, sizeof(SkillNode));

        const unsigned char *name = sqlite3_column_text(stmt, 0);
        int xp = sqlite3_column_int(stmt, 1);
        int level = sqlite3_column_int(stmt, 2);

        if (name) snprintf(node->skill_name, sizeof(node->skill_name), "%s", (const char *)name);
        node->xp = xp;
        node->level = level;

        count++;
    }

    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&s_db_mutex);

    *out_skills = list;
    *out_count = count;
    return true;
}
