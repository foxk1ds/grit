#ifndef GRIT_DB_DB_H
#define GRIT_DB_DB_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include "core/types.h"

typedef struct {
    char sender[16];   // "user" or "mentor"
    char content[2048];
    time_t timestamp;
} ChatMessage;

typedef struct {
    char skill_name[64];
    int xp;
    int level;
} SkillNode;

/*
 * Database Lifecycle
 * Initializes XDG paths (~/.local/share/grit/grit.db), applies pragmas,
 * and runs migrations idempotently.
 */
bool grit_db_init(const char *custom_path);
void grit_db_close(void);

/*
 * Incident & Mentor Storage
 * Persists Incident record and associated MentorResponse session/commands.
 */
bool grit_db_save_incident(const Incident *incident, const MentorResponse *response);

/*
 * Loads recent incidents. Caller must free(*out_incidents).
 */
bool grit_db_load_recent_incidents(Incident **out_incidents, size_t *out_count, size_t limit);

/*
 * Multi-turn Chat Storage
 */
bool grit_db_save_chat_message(const char *incident_id, const char *sender, const char *message);

/*
 * Loads conversation history. Caller must free(*out_messages).
 */
bool grit_db_load_chat_history(const char *incident_id, ChatMessage **out_messages, size_t *out_count);

/*
 * Skill Tree Progression
 */
bool grit_db_add_skill_xp(const char *skill_name, int xp_delta);

/*
 * Retrieves all skill nodes. Caller must free(*out_skills).
 */
bool grit_db_get_skill_tree(SkillNode **out_skills, size_t *out_count);

#endif // GRIT_DB_DB_H
