-- Grit SQLite3 Relational Database Schema

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    severity INTEGER NOT NULL,
    raw_log TEXT NOT NULL,
    source_path TEXT NOT NULL,
    resolved INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS mentor_sessions (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    summary TEXT NOT NULL,
    diagnostic_question TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS mentor_commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES mentor_sessions(id) ON DELETE CASCADE,
    command TEXT NOT NULL,
    safety_level INTEGER NOT NULL,
    purpose TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    sender TEXT NOT NULL CHECK(sender IN ('user', 'mentor')),
    content TEXT NOT NULL,
    timestamp INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_skills (
    skill_name TEXT PRIMARY KEY,
    xp INTEGER NOT NULL DEFAULT 0,
    level INTEGER GENERATED ALWAYS AS (xp / 100) VIRTUAL
);

-- Seed initial GLOBAL incident for general conversation
INSERT OR IGNORE INTO incidents (id, timestamp, severity, raw_log, source_path, resolved) VALUES
    ('GLOBAL', 0, 0, 'Global Conversation Stream', 'system', 1);

-- Seed initial skill tree nodes if empty
INSERT OR IGNORE INTO user_skills (skill_name, xp) VALUES
    ('Brute Force Triage', 120),
    ('Privilege Escalation', 60),
    ('Credential Hygiene', 180),
    ('Network Auditing', 90),
    ('Firewall Hardening', 40);
