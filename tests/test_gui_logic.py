#!/usr/bin/env python3
"""
Test harness for Grit Python GUI logic, C bindings, and tools.
"""
import sys
import os
import ctypes
from pathlib import Path

# Setup paths
repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root / "src" / "gui"))

import app

def test_markdown_to_pango():
    print("[1] Testing markdown_to_pango...")
    sample = "Hello **world** and *italic* and `cat /etc/passwd` & <safe>"
    res = app.markdown_to_pango(sample)
    assert "<b>world</b>" in res, f"Expected bold markup, got: {res}"
    assert "<i>italic</i>" in res, f"Expected italic markup, got: {res}"
    assert "<tt><b>cat /etc/passwd</b></tt>" in res, f"Expected code markup, got: {res}"
    assert "&amp;" in res, f"Expected escaped ampersand, got: {res}"
    print("    [PASS] markdown_to_pango converts correctly")

def test_extract_commands():
    print("[2] Testing extract_commands...")
    text = "You should run `ss -tulpn` to check open sockets, and maybe `cat /etc/hosts` or `invalid_thing 123`"
    cmds = app.extract_commands(text)
    assert "ss -tulpn" in cmds, f"Expected ss in cmds, got: {cmds}"
    assert "cat /etc/hosts" in cmds, f"Expected cat in cmds, got: {cmds}"
    assert "invalid_thing 123" not in cmds, f"Did not expect invalid_thing in cmds: {cmds}"
    print("    [PASS] extract_commands filters correctly")

def test_security_tools():
    print("[3] Testing SecurityAgentTools...")
    ports = app.SecurityAgentTools.inspect_open_ports()
    assert isinstance(ports, str) and len(ports) > 0, "inspect_open_ports returned empty"
    
    logs = app.SecurityAgentTools.inspect_auth_logs("/dev/null")
    assert isinstance(logs, str), "inspect_auth_logs failed"
    
    users = app.SecurityAgentTools.check_active_users()
    assert isinstance(users, str) and len(users) > 0, "check_active_users returned empty"
    
    fw = app.SecurityAgentTools.check_firewall()
    assert isinstance(fw, str) and len(fw) > 0, "check_firewall returned empty"
    print("    [PASS] All SecurityAgentTools returned valid strings")

def test_c_engine_bindings():
    print("[4] Testing C engine bindings...")
    c_eng = app.load_c_engine()
    assert c_eng is not None, "Failed to load C engine"

    # Test Command Guard bindings
    safe_res = c_eng.evaluate_command_safety(b"ss -tulpn")
    assert safe_res == app.CMD_SAFE, f"Expected CMD_SAFE (0), got {safe_res}"

    caution_res = c_eng.evaluate_command_safety(b"kill -9 1234")
    assert caution_res == app.CMD_CAUTION, f"Expected CMD_CAUTION (1), got {caution_res}"

    blocked_res = c_eng.evaluate_command_safety(b"rm -rf /")
    assert blocked_res == app.CMD_BLOCKED, f"Expected CMD_BLOCKED (2), got {blocked_res}"

    # Test Redaction bindings
    buf = ctypes.create_string_buffer(512)
    c_eng.redact_sensitive_data(b"auth failed user=root password=SuperSecret!", buf, 512)
    redacted = buf.value.decode("utf-8")
    assert "<REDACTED>" in redacted, f"Expected <REDACTED>, got: {redacted}"
    assert "SuperSecret!" not in redacted, f"Secret was not stripped: {redacted}"

    # Test SQLite DB bindings
    init_res = c_eng.grit_db_init(b"/tmp/grit_py_test.db")
    assert init_res == True, "Failed to init DB"

    save_res = c_eng.grit_db_save_chat_message(b"TEST_INC", b"user", b"Hello Grit!")
    assert save_res == True, "Failed to save chat message"

    xp_res = c_eng.grit_db_add_skill_xp(b"Brute Force Triage", 25)
    assert xp_res == True, "Failed to add XP"

    skills_ptr = ctypes.POINTER(app.SkillNodeC)()
    count = ctypes.c_size_t(0)
    tree_res = c_eng.grit_db_get_skill_tree(ctypes.byref(skills_ptr), ctypes.byref(count))
    assert tree_res == True, "Failed to get skill tree"
    assert count.value > 0, "Skill tree was empty"

    c_eng.grit_db_close()
    print("    [PASS] C engine bindings verified")

def test_offline_socratic_reply():
    print("[5] Testing offline socratic fallback reply logic...")
    c_eng = app.load_c_engine()
    # Mock window instance or test method directly
    class DummyWindow:
        pass
    dummy = DummyWindow()
    dummy.target_log_file = "/tmp/grit_auth.log"
    res1 = app.GritModernWindow._generate_offline_socratic_reply(dummy, "How to stop SSH brute force attack?")
    assert "ssh" in res1.lower(), f"Expected SSH in reply, got: {res1}"
    assert "`ss -tulpn" in res1, f"Expected diagnostic command in reply, got: {res1}"

    res2 = app.GritModernWindow._generate_offline_socratic_reply(dummy, "Someone tried sudo without permission")
    assert "sudo" in res2.lower(), f"Expected sudo in reply, got: {res2}"
    print("    [PASS] Offline Socratic replies generated correctly")

if __name__ == "__main__":
    print("=" * 60)
    print("   Running Grit Python GUI & Backend Verification Tests     ")
    print("=" * 60)
    test_markdown_to_pango()
    test_extract_commands()
    test_security_tools()
    test_c_engine_bindings()
    test_offline_socratic_reply()
    print("=" * 60)
    print("   All Python GUI Logic & Engine Tests PASSED (0 Errors)    ")
    print("=" * 60)
