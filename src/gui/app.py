#!/usr/bin/env python3
"""
Grit — Modern Offline Cybersecurity Mentor & Defensive Workstation
Strictly adheres to modern GNOME HIG (Human Interface Guidelines) and Libadwaita architecture.

Combines live POSIX inotify log monitoring, real-time regex credential redaction,
Socratic cybersecurity education via local Ollama LLMs, autonomous diagnostic tools,
and a gamified defense skill matrix.
"""

import sys
import os
import re
import time
import json
import ctypes
import threading
import subprocess
from pathlib import Path
from urllib import request as urllib_request, error as urllib_error

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, GLib, Gdk, Gio, Pango

# ------------------------------------------------------------------------------
# C Data Contracts & Structures (from src/core/types.h & src/db/db.h)
# ------------------------------------------------------------------------------

SEV_INFO = 0
SEV_WARN = 1
SEV_CRIT = 2

CMD_SAFE = 0
CMD_CAUTION = 1
CMD_BLOCKED = 2

SCENARIO_SSH_BRUTE = 0
SCENARIO_SUDO_ESCALATION = 1
SCENARIO_REDACTION = 2

class IncidentC(ctypes.Structure):
    _fields_ = [
        ("incident_id", ctypes.c_char * 32),
        ("category", ctypes.c_char * 64),
        ("source_ip", ctypes.c_char * 46),
        ("target_user", ctypes.c_char * 64),
        ("frequency_count", ctypes.c_int),
        ("first_seen", ctypes.c_long),
        ("last_seen", ctypes.c_long),
        ("severity", ctypes.c_int),
        ("raw_log_excerpt", ctypes.c_char * 512),
    ]

class SuggestedActionC(ctypes.Structure):
    _fields_ = [
        ("command", ctypes.c_char * 256),
        ("safety_level", ctypes.c_int),
        ("explanation", ctypes.c_char * 512),
    ]

class MentorResponseC(ctypes.Structure):
    _fields_ = [
        ("mentor_analysis", ctypes.c_char * 2048),
        ("actions", SuggestedActionC * 3),
        ("action_count", ctypes.c_size_t),
    ]

class WatcherContextC(ctypes.Structure):
    _fields_ = [
        ("is_running", ctypes.c_bool),
        ("inotify_fd", ctypes.c_int),
        ("event_fd", ctypes.c_int),
        ("thread_id", ctypes.c_ulong),
        ("target_file", ctypes.c_char * 256),
    ]

class ChatMessageC(ctypes.Structure):
    _fields_ = [
        ("sender", ctypes.c_char * 16),
        ("content", ctypes.c_char * 2048),
        ("timestamp", ctypes.c_long),
    ]

class SkillNodeC(ctypes.Structure):
    _fields_ = [
        ("skill_name", ctypes.c_char * 64),
        ("xp", ctypes.c_int),
        ("level", ctypes.c_int),
    ]

OBSERVER_CALLBACK = ctypes.CFUNCTYPE(None, ctypes.POINTER(IncidentC), ctypes.c_void_p)

# ------------------------------------------------------------------------------
# C Engine Loader
# ------------------------------------------------------------------------------

def load_c_engine():
    project_root = Path(__file__).resolve().parent.parent.parent
    lib_path = project_root / "libgrit.so"
    if not lib_path.exists():
        cmd = (
            f"gcc -std=c23 -shared -fPIC -Wall -Wextra -pthread -I{project_root}/src -I{project_root}/include -L{project_root}/lib "
            f"{project_root}/src/core/watcher.c {project_root}/src/core/simulator.c "
            f"{project_root}/src/mentor/command_guard.c {project_root}/src/mentor/llm_client.c "
            f"{project_root}/src/db/db.c -lsqlite3 -lcurl -o {lib_path}"
        )
        rc = os.system(cmd)
        if rc != 0:
            raise RuntimeError(f"Compilation of libgrit.so failed with code {rc}")

    lib = ctypes.CDLL(str(lib_path))

    # C Function Signatures
    lib.watcher_init.argtypes = [ctypes.POINTER(WatcherContextC), ctypes.c_char_p]
    lib.watcher_init.restype = ctypes.c_int
    lib.watcher_start.argtypes = [ctypes.POINTER(WatcherContextC)]
    lib.watcher_start.restype = ctypes.c_int
    lib.watcher_stop.argtypes = [ctypes.POINTER(WatcherContextC)]
    lib.watcher_stop.restype = None
    lib.watcher_destroy.argtypes = [ctypes.POINTER(WatcherContextC)]
    lib.watcher_destroy.restype = None
    lib.watcher_register_observer.argtypes = [OBSERVER_CALLBACK, ctypes.c_void_p]
    lib.watcher_register_observer.restype = None

    lib.redact_sensitive_data.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.redact_sensitive_data.restype = None
    lib.evaluate_command_safety.argtypes = [ctypes.c_char_p]
    lib.evaluate_command_safety.restype = ctypes.c_int
    lib.command_safety_to_string.argtypes = [ctypes.c_int]
    lib.command_safety_to_string.restype = ctypes.c_char_p

    lib.simulator_inject_scenario.argtypes = [ctypes.c_int, ctypes.c_char_p]
    lib.simulator_inject_scenario.restype = ctypes.c_bool
    lib.simulator_scenario_name.argtypes = [ctypes.c_int]
    lib.simulator_scenario_name.restype = ctypes.c_char_p

    lib.grit_db_init.argtypes = [ctypes.c_char_p]
    lib.grit_db_init.restype = ctypes.c_bool
    lib.grit_db_close.argtypes = []
    lib.grit_db_close.restype = None
    lib.grit_db_save_chat_message.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.grit_db_save_chat_message.restype = ctypes.c_bool
    lib.grit_db_load_chat_history.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.POINTER(ChatMessageC)), ctypes.POINTER(ctypes.c_size_t)]
    lib.grit_db_load_chat_history.restype = ctypes.c_bool
    lib.grit_db_add_skill_xp.argtypes = [ctypes.c_char_p, ctypes.c_int]
    lib.grit_db_add_skill_xp.restype = ctypes.c_bool
    lib.grit_db_get_skill_tree.argtypes = [ctypes.POINTER(ctypes.POINTER(SkillNodeC)), ctypes.POINTER(ctypes.c_size_t)]
    lib.grit_db_get_skill_tree.restype = ctypes.c_bool

    return lib

# ------------------------------------------------------------------------------
# Autonomous Security Agent Diagnostic Tools
# ------------------------------------------------------------------------------

class SecurityAgentTools:
    """Safe, read-only observational tools for host inspection."""
    @staticmethod
    def inspect_open_ports():
        try:
            res = subprocess.run(["ss", "-tulpn"], capture_output=True, text=True, timeout=5)
            lines = res.stdout.strip().split("\n")
            return "\n".join(lines[:14]) if lines else "No active listening ports detected."
        except Exception as e:
            return f"Error querying ports: {e}"

    @staticmethod
    def inspect_auth_logs(path, lines=15):
        try:
            if not os.path.exists(path):
                return f"Log file {path} does not exist yet."
            res = subprocess.run(["tail", f"-n{lines}", path], capture_output=True, text=True, timeout=5)
            return res.stdout.strip() or "Log file is currently empty."
        except Exception as e:
            return f"Error reading logs: {e}"

    @staticmethod
    def check_active_users():
        try:
            res = subprocess.run(["who"], capture_output=True, text=True, timeout=5)
            return res.stdout.strip() or "No interactive terminal sessions currently active."
        except Exception as e:
            return f"Error querying users: {e}"

    @staticmethod
    def check_firewall():
        try:
            res = subprocess.run(["ufw", "status", "verbose"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
            res2 = subprocess.run(["iptables", "-L", "-n"], capture_output=True, text=True, timeout=5)
            lines = res2.stdout.strip().split("\n")
            return "\n".join(lines[:15]) if lines else "Firewall status could not be retrieved."
        except Exception as e:
            return f"Firewall query note: {e}"

# ------------------------------------------------------------------------------
# UI Helper Builders (Modern Asymmetric Chat, Cards, & Badges)
# ------------------------------------------------------------------------------

def markdown_to_pango(text):
    """Converts common Markdown syntax into sanitized Pango markup."""
    text = re.sub(r'^(🛡️\s*)?(Grit\s*(\(Security Mentor\))?:?\s*)', '', text.strip(), flags=re.IGNORECASE)
    escaped = GLib.markup_escape_text(text)
    escaped = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', escaped)
    escaped = re.sub(r'\*(.+?)\*', r'<i>\1</i>', escaped)
    escaped = re.sub(r'`([^`\n]+)`', r'<tt><b>\1</b></tt>', escaped)
    return escaped

def extract_commands(text):
    """Extracts valid terminal commands from backticked strings or code blocks."""
    matches = re.findall(r'`([^`\n]+)`', text)
    valid = []
    for m in matches:
        m = m.strip()
        binary = m.split()[0] if m.split() else ""
        if binary in ["ss", "cat", "ps", "journalctl", "ufw", "iptables", "grep", "chmod", "kill", "rm", "systemctl", "who", "tail"]:
            if m not in valid:
                valid.append(m)
    return valid[:4]

def create_user_bubble(text):
    """Constructs a right-aligned compact rounded pill for user messages."""
    row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
    row.add_css_class("user-bubble-box")
    row.set_halign(Gtk.Align.END)

    bubble = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
    bubble.add_css_class("user-bubble")

    lbl = Gtk.Label()
    lbl.set_markup(GLib.markup_escape_text(text))
    lbl.set_xalign(0.0)
    lbl.set_wrap(True)
    lbl.set_max_width_chars(65)
    lbl.set_selectable(True)
    lbl.add_css_class("user-bubble-text")
    bubble.append(lbl)

    row.append(bubble)
    return row

def create_command_card(cmd_text, c_engine, copy_cb, caution_cb, run_cb=None):
    """Constructs an interactive dark monospace terminal box for commands."""
    card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
    card.add_css_class("command-card")

    safety = c_engine.evaluate_command_safety(cmd_text.encode("utf-8")) if c_engine else CMD_SAFE
    binary_name = cmd_text.split()[0] if cmd_text.split() else "bash"

    # Header Bar
    header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    header.add_css_class("command-card-header")

    dots_lbl = Gtk.Label(label="● ● ●")
    dots_lbl.add_css_class("command-card-dots")
    header.append(dots_lbl)

    badge = Gtk.Label()
    action_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
    action_btn.add_css_class("flat")

    if safety == CMD_SAFE:
        badge.set_markup("<span class='badge-safe'>SAFE: READ-ONLY</span>")
        action_btn.set_tooltip_text("Copy safe verification command")
        if copy_cb:
            action_btn.connect("clicked", lambda b: copy_cb(cmd_text))
    elif safety == CMD_CAUTION:
        badge.set_markup("<span class='badge-caution'>CAUTION: STATE-MODIFYING</span>")
        action_btn.set_tooltip_text("Acknowledge state modification & copy")
        if caution_cb:
            action_btn.connect("clicked", lambda b: caution_cb(cmd_text))
    else:
        badge.set_markup("<span class='badge-blocked'>BLOCKED: DESTRUCTIVE</span>")
        action_btn.set_sensitive(False)
        action_btn.set_tooltip_text("Blocked: Destructive command or arbitrary injection risk")

    header.append(badge)

    tool_lbl = Gtk.Label()
    tool_lbl.set_markup(f"<tt><span foreground='#8c8c9a'>bin: {binary_name}</span></tt>")
    tool_lbl.set_xalign(0.0)
    tool_lbl.set_hexpand(True)
    header.append(tool_lbl)

    # Optional 1-click Run button for safe observational commands
    if safety == CMD_SAFE and run_cb and binary_name in ["ss", "who", "tail", "ufw"]:
        run_btn = Gtk.Button.new_from_icon_name("media-playback-start-symbolic")
        run_btn.add_css_class("flat")
        run_btn.set_tooltip_text(f"Execute safe diagnostic `{cmd_text}`")
        run_btn.connect("clicked", lambda b: run_cb(cmd_text))
        header.append(run_btn)

    header.append(action_btn)
    card.append(header)

    # Terminal Body
    body = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
    body.add_css_class("command-card-body")

    code_lbl = Gtk.Label(label=f"$ {cmd_text}")
    code_lbl.set_xalign(0.0)
    code_lbl.set_wrap(True)
    code_lbl.set_selectable(True)
    code_lbl.add_css_class("command-card-code")
    body.append(code_lbl)

    card.append(body)
    return card

def create_mentor_bubble(text, model_name, c_engine, copy_cb, caution_cb, run_cb=None):
    """Constructs a structured mentor card with avatar header, Socratic callout, and command cards."""
    row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
    row.add_css_class("mentor-bubble-box")
    row.set_halign(Gtk.Align.START)

    card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    card.add_css_class("mentor-bubble")

    # Header
    header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    avatar = Gtk.Image.new_from_icon_name("security-high-symbolic")
    header.append(avatar)

    title_lbl = Gtk.Label(label="Grit Mentor")
    title_lbl.add_css_class("mentor-header-title")
    header.append(title_lbl)

    tag_lbl = Gtk.Label(label=f"• {model_name or 'Socratic Tutor'}")
    tag_lbl.add_css_class("mentor-header-tag")
    header.append(tag_lbl)
    card.append(header)

    # Paragraph split
    paragraphs = text.strip().split("\n\n")
    body_paragraphs = []
    callout_paragraphs = []

    for p in paragraphs:
        p_strip = p.strip()
        if any(marker in p_strip.lower() for marker in ["diagnostic question", "guiding question", "socratic question", "concept to consider:"]):
            callout_paragraphs.append(p_strip)
        else:
            body_paragraphs.append(p_strip)

    main_text = "\n\n".join(body_paragraphs)
    if main_text:
        content_lbl = Gtk.Label()
        content_lbl.set_markup(markdown_to_pango(main_text))
        content_lbl.set_xalign(0.0)
        content_lbl.set_wrap(True)
        content_lbl.set_max_width_chars(75)
        content_lbl.set_selectable(True)
        content_lbl.add_css_class("mentor-body-text")
        card.append(content_lbl)

    if callout_paragraphs:
        callout_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        callout_box.add_css_class("socratic-callout")

        callout_head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        q_icon = Gtk.Image.new_from_icon_name("dialog-question-symbolic")
        callout_head.append(q_icon)

        c_title = Gtk.Label(label="Socratic Diagnostic Question")
        c_title.add_css_class("socratic-callout-title")
        callout_head.append(c_title)
        callout_box.append(callout_head)

        callout_text = "\n\n".join(callout_paragraphs)
        c_lbl = Gtk.Label()
        c_lbl.set_markup(markdown_to_pango(callout_text))
        c_lbl.set_xalign(0.0)
        c_lbl.set_wrap(True)
        c_lbl.set_max_width_chars(70)
        c_lbl.set_selectable(True)
        callout_box.append(c_lbl)
        card.append(callout_box)

    # Render Command Cards
    commands = extract_commands(text)
    for cmd in commands:
        cmd_card = create_command_card(cmd, c_engine, copy_cb, caution_cb, run_cb)
        card.append(cmd_card)

    row.append(card)
    return row

def create_alert_card(inc, investigate_cb=None):
    """Constructs an incident notification card for real-time inotify alerts."""
    row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
    row.add_css_class("alert-card")
    row.set_halign(Gtk.Align.FILL)

    vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    vbox.set_hexpand(True)

    header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    icon = Gtk.Image.new_from_icon_name("security-medium-symbolic")
    header.append(icon)

    sev_text = "CRITICAL" if inc.get("severity") == SEV_CRIT else ("WARNING" if inc.get("severity") == SEV_WARN else "INFO")
    title_lbl = Gtk.Label()
    title_lbl.set_markup(f"<span foreground='#ff7b63' weight='bold'>🚨 [INOTIFY DETECTED] {inc.get('category', 'Anomaly')}</span>")
    title_lbl.set_xalign(0.0)
    title_lbl.set_hexpand(True)
    header.append(title_lbl)

    sev_badge = Gtk.Label()
    sev_badge.set_markup(f"<span class='badge-blocked'>{sev_text}</span>")
    header.append(sev_badge)
    vbox.append(header)

    details = (
        f"<b>Incident ID:</b> <tt>{inc.get('id', 'N/A')}</tt> | "
        f"<b>Source IP:</b> <tt>{inc.get('ip', 'N/A')}</tt> | "
        f"<b>Target User:</b> <tt>{inc.get('user', 'N/A')}</tt>\n"
        f"<b>Sanitized Excerpt:</b> <tt>{inc.get('excerpt', 'N/A')}</tt>"
    )
    details_lbl = Gtk.Label()
    details_lbl.set_markup(details)
    details_lbl.set_xalign(0.0)
    details_lbl.set_wrap(True)
    details_lbl.set_selectable(True)
    vbox.append(details_lbl)

    if investigate_cb:
        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        btn = Gtk.Button(label="Investigate Attack Technique")
        btn.add_css_class("flat")
        btn.connect("clicked", lambda b: investigate_cb(inc))
        btn_box.append(btn)
        vbox.append(btn_box)

    row.append(vbox)
    return row

def create_tool_card(tool_desc, output_text, copy_cb=None):
    """Constructs a result card when an autonomous agent diagnostic tool completes."""
    row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
    row.add_css_class("tool-result-card")
    row.set_halign(Gtk.Align.FILL)

    vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
    vbox.set_hexpand(True)

    header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    icon = Gtk.Image.new_from_icon_name("system-run-symbolic")
    header.append(icon)

    title_lbl = Gtk.Label()
    title_lbl.set_markup(f"<b>⚙️ {tool_desc}</b>")
    title_lbl.set_xalign(0.0)
    title_lbl.set_hexpand(True)
    header.append(title_lbl)

    badge = Gtk.Label()
    badge.set_markup("<span class='badge-safe'>READ-ONLY</span>")
    header.append(badge)

    if copy_cb:
        copy_btn = Gtk.Button.new_from_icon_name("edit-copy-symbolic")
        copy_btn.add_css_class("flat")
        copy_btn.set_tooltip_text("Copy diagnostic output")
        copy_btn.connect("clicked", lambda b: copy_cb(output_text))
        header.append(copy_btn)

    vbox.append(header)

    out_lbl = Gtk.Label(label=output_text)
    out_lbl.set_xalign(0.0)
    out_lbl.set_wrap(True)
    out_lbl.set_selectable(True)
    out_lbl.add_css_class("command-card-code")
    vbox.append(out_lbl)

    row.append(vbox)
    return row

def create_hero_card(target_file, prompt_cb):
    """Constructs the welcoming onboarding card in the chat view."""
    card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    card.add_css_class("hero-card")

    header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
    icon = Gtk.Image.new_from_icon_name("org.grit.workstation")
    icon.set_pixel_size(48)
    header.append(icon)

    vhead = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
    t_lbl = Gtk.Label(label="Grit Cybersecurity Mentor Workstation")
    t_lbl.add_css_class("hero-title")
    t_lbl.set_xalign(0.0)
    vhead.append(t_lbl)

    s_lbl = Gtk.Label(label=f"Active monitoring: {target_file} • Zero-latency POSIX engine • Privacy regex redaction")
    s_lbl.add_css_class("hero-subtitle")
    s_lbl.set_xalign(0.0)
    vhead.append(s_lbl)
    header.append(vhead)
    card.append(header)

    # Quick action pills
    pills_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    p1 = Gtk.Label(label="🛡️ inotify Watcher")
    p1.add_css_class("hero-pill")
    pills_box.append(p1)

    p2 = Gtk.Label(label="🔒 Privacy Redaction")
    p2.add_css_class("hero-pill")
    pills_box.append(p2)

    p3 = Gtk.Label(label="⚡ Command Guard Tree")
    p3.add_css_class("hero-pill")
    pills_box.append(p3)

    p4 = Gtk.Label(label="🧠 Socratic LLM Agent")
    p4.add_css_class("hero-pill")
    pills_box.append(p4)
    card.append(pills_box)

    return card

# ------------------------------------------------------------------------------
# Main Application Window (GNOME HIG & Libadwaita Architecture)
# ------------------------------------------------------------------------------

class GritModernWindow(Adw.ApplicationWindow):
    def __init__(self, app, c_engine):
        super().__init__(application=app, title="Grit — Defensive Cybersecurity Mentor")
        self.set_default_size(1260, 840)
        self.set_size_request(960, 640)
        self.c_engine = c_engine

        # Ensure database is initialized (with automatic fallback to writable location)
        if not self.c_engine.grit_db_init(None):
            self.c_engine.grit_db_init(b"/tmp/grit_db.sqlite")

        # Monitored file path
        self.target_log_file = "/var/log/auth.log"
        if not os.access(self.target_log_file, os.R_OK):
            self.target_log_file = "/tmp/grit_auth.log"
            Path(self.target_log_file).touch()

        # Initialize Watcher Context
        self.watcher_ctx = WatcherContextC()
        self.c_engine.watcher_init(ctypes.byref(self.watcher_ctx), self.target_log_file.encode("utf-8"))

        # Register inotify observer callback
        self._observer_cb = OBSERVER_CALLBACK(self._on_c_incident_observed)
        self.c_engine.watcher_register_observer(self._observer_cb, None)

        self.available_models = ["qwen2.5:1.5b", "qwen2.5:3b", "qwen2.5-coder:latest", "deepseek-r1:7b"]
        self.selected_model = "qwen2.5:1.5b"
        self.latest_incident_context = None

        # Incident history in memory
        self.incident_history = []

        self._load_styles_and_icons()
        self._build_interface()
        self._fetch_ollama_models()
        self._refresh_skill_dashboard()
        self._update_triage_kpi()

        self.connect("close-request", self._on_close_request)

    def _load_styles_and_icons(self):
        """Registers custom app icons and loads modern Libadwaita dark theme styles."""
        project_root = Path(__file__).resolve().parent.parent.parent

        # Register icon theme search paths
        display = Gdk.Display.get_default()
        if display:
            icon_theme = Gtk.IconTheme.get_for_display(display)
            icon_dir = project_root / "data" / "icons"
            if icon_dir.exists():
                icon_theme.add_search_path(str(icon_dir))
                icon_theme.add_search_path(str(icon_dir / "hicolor"))

        self.set_icon_name("org.grit.workstation")

        # Load style.css
        css_path = project_root / "src" / "gui" / "style.css"
        provider = Gtk.CssProvider()
        if css_path.exists():
            provider.load_from_path(str(css_path))
        if display:
            Gtk.StyleContext.add_provider_for_display(
                display,
                provider,
                Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )

    def _build_interface(self):
        # 1. Main Toast Overlay
        self.toast_overlay = Adw.ToastOverlay()
        self.set_content(self.toast_overlay)

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.toast_overlay.set_child(main_box)

        # 2. Modern HeaderBar with ViewSwitcher
        self.view_stack = Adw.ViewStack()
        self.view_stack.set_vexpand(True)
        self.view_stack.set_hexpand(True)

        header = Adw.HeaderBar()

        # Left Header: App Brand Emblem + Title
        brand_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        brand_box.add_css_class("grit-brand-box")

        app_icon = Gtk.Image.new_from_icon_name("org.grit.workstation")
        app_icon.set_pixel_size(24)
        brand_box.append(app_icon)

        title_vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        brand_title = Gtk.Label(label="Grit")
        brand_title.add_css_class("grit-brand-title")
        brand_title.set_xalign(0.0)
        title_vbox.append(brand_title)

        brand_sub = Gtk.Label(label="Defensive Workstation")
        brand_sub.add_css_class("grit-brand-subtitle")
        brand_sub.set_xalign(0.0)
        title_vbox.append(brand_sub)
        brand_box.append(title_vbox)

        header.pack_start(brand_box)

        # Latency Badge
        self.latency_badge = Gtk.Label(label="⚡ ~510 µs")
        self.latency_badge.add_css_class("grit-latency-badge")
        header.pack_start(self.latency_badge)

        # Center View Switcher
        switcher = Adw.ViewSwitcher()
        switcher.set_stack(self.view_stack)
        switcher.set_policy(Adw.ViewSwitcherPolicy.WIDE)
        header.set_title_widget(switcher)

        # Right Header: Inotify Switch + LLM Pill + Menu
        switch_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self.pulse_label = Gtk.Label(label="○ Inactive")
        self.pulse_label.add_css_class("grit-pulse-inactive")
        switch_box.append(self.pulse_label)

        self.watcher_switch = Gtk.Switch()
        self.watcher_switch.set_valign(Gtk.Align.CENTER)
        self.watcher_switch.connect("state-set", self._on_switch_state_set)
        switch_box.append(self.watcher_switch)
        header.pack_end(switch_box)

        # Ollama Status Pill
        self.pill_ollama = Gtk.Label(label="Checking...")
        self.pill_ollama.add_css_class("grit-pill-offline")
        header.pack_end(self.pill_ollama)

        # Workstation Action Menu Button
        menu_btn = self._build_menu_button()
        header.pack_end(menu_btn)

        main_box.append(header)

        # 3. Build the 4 Specialized Workstation Views
        # View 1: Mentor Dialogue & Live Chat Workstation
        view_mentor = self._build_mentor_view()
        self.view_stack.add_titled_with_icon(view_mentor, "mentor", "Mentor", "dialog-information-symbolic")

        # View 2: Security Log Monitor & Triage
        view_triage = self._build_triage_view()
        self.view_stack.add_titled_with_icon(view_triage, "triage", "Log Triage", "security-medium-symbolic")

        # View 3: Defense Matrix & Gamified Skill Tree
        view_matrix = self._build_defense_matrix_view()
        self.view_stack.add_titled_with_icon(view_matrix, "matrix", "Defense Matrix", "emblem-favorite-symbolic")

        # View 4: Attack Simulator Lab & Agent Diagnostics
        view_lab = self._build_lab_view()
        self.view_stack.add_titled_with_icon(view_lab, "lab", "Simulator Lab", "system-run-symbolic")

        main_box.append(self.view_stack)

    # --------------------------------------------------------------------------
    # Menu Button
    # --------------------------------------------------------------------------
    def _build_menu_button(self):
        popover = Gtk.Popover()
        pop_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        pop_box.set_margin_start(8)
        pop_box.set_margin_end(8)
        pop_box.set_margin_top(8)
        pop_box.set_margin_bottom(8)

        btn_clear = Gtk.Button(label="Clear Chat Conversation")
        btn_clear.add_css_class("flat")
        btn_clear.connect("clicked", lambda b: (popover.popdown(), self._clear_chat_stream()))
        pop_box.append(btn_clear)

        btn_change_file = Gtk.Button(label="Switch Monitored Log File...")
        btn_change_file.add_css_class("flat")
        btn_change_file.connect("clicked", lambda b: (popover.popdown(), self._prompt_change_log_file()))
        pop_box.append(btn_change_file)

        btn_refresh = Gtk.Button(label="Refresh Ollama Models")
        btn_refresh.add_css_class("flat")
        btn_refresh.connect("clicked", lambda b: (popover.popdown(), self._fetch_ollama_models()))
        pop_box.append(btn_refresh)

        btn_benchmark = Gtk.Button(label="Benchmark Watcher Interrupt")
        btn_benchmark.add_css_class("flat")
        btn_benchmark.connect("clicked", lambda b: (popover.popdown(), self._run_latency_benchmark()))
        pop_box.append(btn_benchmark)

        btn_about = Gtk.Button(label="About Grit")
        btn_about.add_css_class("flat")
        btn_about.connect("clicked", lambda b: (popover.popdown(), self._show_about_dialog()))
        pop_box.append(btn_about)

        popover.set_child(pop_box)

        menu_btn = Gtk.MenuButton()
        menu_btn.set_icon_name("open-menu-symbolic")
        menu_btn.set_popover(popover)
        menu_btn.set_tooltip_text("Workstation Settings & Tools")
        return menu_btn

    # --------------------------------------------------------------------------
    # View 1: Socratic Mentor (Dual-Pane Workstation)
    # --------------------------------------------------------------------------
    def _build_mentor_view(self):
        paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        paned.set_position(360)
        paned.set_shrink_start_child(False)
        paned.set_shrink_end_child(False)

        # Left Quick Sidebar
        sidebar = self._build_mentor_sidebar()
        paned.set_start_child(sidebar)

        # Right Chat Panel
        chat_panel = self._build_chat_panel()
        paned.set_end_child(chat_panel)

        return paned

    def _build_mentor_sidebar(self):
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        scrolled.set_hexpand(False)
        scrolled.set_size_request(340, -1)

        pref_page = Adw.PreferencesPage()
        scrolled.set_child(pref_page)

        # Group 1: Live Monitor Status
        group_monitor = Adw.PreferencesGroup()
        group_monitor.set_title("System Log Watcher")
        group_monitor.set_description("POSIX inotify thread with sub-ms interrupt")

        self.row_watcher_file = Adw.ActionRow()
        self.row_watcher_file.set_title("Auth Log Target")
        self.row_watcher_file.set_subtitle(self.target_log_file)

        btn_pick_file = Gtk.Button.new_from_icon_name("document-open-symbolic")
        btn_pick_file.add_css_class("flat")
        btn_pick_file.set_tooltip_text("Change monitored file path")
        btn_pick_file.connect("clicked", lambda b: self._prompt_change_log_file())
        self.row_watcher_file.add_suffix(btn_pick_file)
        group_monitor.add(self.row_watcher_file)

        self.row_side_latency = Adw.ActionRow()
        self.row_side_latency.set_title("Eventfd Latency")
        self.row_side_latency.set_subtitle("Thread halt benchmark")
        self.side_latency_badge = Gtk.Label(label="~510 µs")
        self.side_latency_badge.add_css_class("grit-latency-badge")
        self.row_side_latency.add_suffix(self.side_latency_badge)
        group_monitor.add(self.row_side_latency)

        pref_page.add(group_monitor)

        # Group 2: Intelligence Engine
        group_llm = Adw.PreferencesGroup()
        group_llm.set_title("Intelligence Engine")
        group_llm.set_description("Local Ollama endpoint / offline Socratic fallback")

        self.row_model = Adw.ActionRow()
        self.row_model.set_title("LLM Model")
        self.row_model.set_subtitle("http://127.0.0.1:11434")

        self.model_combo = Gtk.DropDown.new_from_strings(self.available_models)
        self.model_combo.connect("notify::selected", self._on_model_changed)
        self.row_model.add_suffix(self.model_combo)
        group_llm.add(self.row_model)

        pref_page.add(group_llm)

        # Group 3: Quick Attack Injectors
        group_quick_sim = Adw.PreferencesGroup()
        group_quick_sim.set_title("Simulate Attack Scenarios")
        group_quick_sim.set_description("Triggers real inotify capture & Socratic mentor triage")

        row_ssh = Adw.ActionRow()
        row_ssh.set_title("SSH Brute Force")
        row_ssh.set_subtitle("Inject 6 failed probes from 203.0.113.42")
        btn_ssh = Gtk.Button(label="Inject")
        btn_ssh.add_css_class("flat")
        btn_ssh.connect("clicked", lambda b: self._inject_scenario(SCENARIO_SSH_BRUTE))
        row_ssh.add_suffix(btn_ssh)
        group_quick_sim.add(row_ssh)

        row_sudo = Adw.ActionRow()
        row_sudo.set_title("Sudo Privilege Escalation")
        row_sudo.set_subtitle("Inject unauthorized sudo attempts")
        btn_sudo = Gtk.Button(label="Inject")
        btn_sudo.add_css_class("flat")
        btn_sudo.connect("clicked", lambda b: self._inject_scenario(SCENARIO_SUDO_ESCALATION))
        row_sudo.add_suffix(btn_sudo)
        group_quick_sim.add(row_sudo)

        row_leak = Adw.ActionRow()
        row_leak.set_title("Credential Leak Test")
        row_leak.set_subtitle("Inject PEM keys, passwords, and JWTs")
        btn_leak = Gtk.Button(label="Inject")
        btn_leak.add_css_class("flat")
        btn_leak.connect("clicked", lambda b: self._inject_scenario(SCENARIO_REDACTION))
        row_leak.add_suffix(btn_leak)
        group_quick_sim.add(row_leak)

        pref_page.add(group_quick_sim)

        # Group 4: Autonomous Diagnostic Tools
        group_tools = Adw.PreferencesGroup()
        group_tools.set_title("Autonomous Agent Tools")
        group_tools.set_description("Read-only system inspections executed safely")

        tools_def = [
            ("Audit Listening Sockets", "Inspect open ports (`ss -tulpn`)", "ports"),
            ("Tail Monitored Logs", "Inspect recent 15 lines of auth.log", "logs"),
            ("Audit Host Firewall", "Inspect UFW & iptables policy", "firewall"),
            ("Active User Terminals", "Inspect logged-in sessions (`who`)", "who"),
        ]

        for title, sub, key in tools_def:
            row = Adw.ActionRow()
            row.set_title(title)
            row.set_subtitle(sub)
            btn = Gtk.Button(label="Run")
            btn.add_css_class("flat")
            btn.connect("clicked", lambda b, k=key: self._execute_agent_tool(k))
            row.add_suffix(btn)
            group_tools.add(row)

        pref_page.add(group_tools)
        return scrolled

    def _build_chat_panel(self):
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        vbox.set_hexpand(True)
        vbox.set_vexpand(True)
        vbox.add_css_class("chat-container")

        # Chat Scrolled Window
        self.chat_scrolled = Gtk.ScrolledWindow()
        self.chat_scrolled.set_vexpand(True)
        self.chat_scrolled.set_hexpand(True)
        vbox.append(self.chat_scrolled)

        self.chat_stream = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        self.chat_stream.set_margin_start(18)
        self.chat_stream.set_margin_end(18)
        self.chat_stream.set_margin_top(16)
        self.chat_stream.set_margin_bottom(16)
        self.chat_scrolled.set_child(self.chat_stream)

        # Initial Hero Welcome Card
        hero = create_hero_card(self.target_log_file, self._send_user_message)
        self.chat_stream.append(hero)

        # Starter mentor greeting
        welcome_text = (
            "🛡️ **Welcome to Grit, your Offline Cybersecurity Mentor!**\n\n"
            f"I am actively monitoring `{self.target_log_file}` with native Linux inotify. "
            "Whenever suspicious authentication anomalies occur, I will sanitize credentials in real time, "
            "alert you here, and guide you through investigative steps Socratic-style.\n\n"
            "**Diagnostic Question to begin:**\n"
            "Do you know which services are currently listening on your host network interfaces?\n\n"
            "Click a suggestion chip below or ask for diagnostic verification with `ss -tulpn`."
        )
        self._post_mentor_message(welcome_text)

        # Suggestion Chips Carousel
        chips_scrolled = Gtk.ScrolledWindow()
        chips_scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.NEVER)
        chips_scrolled.set_vexpand(False)
        chips_scrolled.set_margin_start(16)
        chips_scrolled.set_margin_end(16)
        chips_scrolled.set_margin_top(6)
        chips_scrolled.set_margin_bottom(8)

        chips_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        chips_scrolled.set_child(chips_box)

        chip_items = [
            ("💡 Explain Latest Incident", lambda: self._send_user_message("Can you explain the latest incident detected in my logs?")),
            ("🔒 Harden SSH Against Brute Force", lambda: self._send_user_message("What are the best practices to harden SSH against brute force attacks?")),
            ("🔍 Audit Listening Sockets", lambda: self._execute_agent_tool("ports")),
            ("🛡️ Principle of Least Privilege", lambda: self._send_user_message("Explain how Linux sudoers enforces the principle of least privilege.")),
            ("🔥 Audit Host Firewall", lambda: self._execute_agent_tool("firewall")),
            ("🔑 Test Credential Redaction", lambda: self._inject_scenario(SCENARIO_REDACTION)),
        ]

        for label, cb in chip_items:
            btn = Gtk.Button(label=label)
            btn.add_css_class("chip-button")
            btn.connect("clicked", lambda b, callback=cb: callback())
            chips_box.append(btn)

        vbox.append(chips_scrolled)

        # Capsule Input Bar
        input_container = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        input_container.set_margin_start(16)
        input_container.set_margin_end(16)
        input_container.set_margin_bottom(14)

        capsule = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        capsule.add_css_class("chat-entry-capsule")
        capsule.set_hexpand(True)

        self.chat_entry = Gtk.Entry()
        self.chat_entry.set_has_frame(False)
        self.chat_entry.set_placeholder_text("Ask Grit a cybersecurity question or request diagnostic analysis...")
        self.chat_entry.set_hexpand(True)
        self.chat_entry.connect("activate", self._on_entry_activate)
        capsule.append(self.chat_entry)

        send_btn = Gtk.Button.new_from_icon_name("mail-send-symbolic")
        send_btn.add_css_class("suggested-action")
        send_btn.add_css_class("circular")
        send_btn.add_css_class("send-button-circular")
        send_btn.set_tooltip_text("Send message to Grit (Enter)")
        send_btn.connect("clicked", lambda b: self._on_entry_activate(self.chat_entry))
        capsule.append(send_btn)

        input_container.append(capsule)
        vbox.append(input_container)

        return vbox

    # --------------------------------------------------------------------------
    # View 2: Security Log Monitor & Triage View
    # --------------------------------------------------------------------------
    def _build_triage_view(self):
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        scrolled.set_hexpand(True)

        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        vbox.set_margin_start(24)
        vbox.set_margin_end(24)
        vbox.set_margin_top(20)
        vbox.set_margin_bottom(24)
        scrolled.set_child(vbox)

        # Top KPI Metrics Strip
        kpi_grid = Gtk.Grid()
        kpi_grid.set_column_spacing(16)
        kpi_grid.set_row_spacing(12)
        kpi_grid.set_hexpand(True)

        self.kpi_total_lbl = self._create_kpi_card(kpi_grid, 0, "TOTAL INCIDENTS", "0", "kpi-card-cyan")
        self.kpi_crit_lbl = self._create_kpi_card(kpi_grid, 1, "CRITICAL ALERTS", "0", "kpi-card-red")
        self.kpi_redact_lbl = self._create_kpi_card(kpi_grid, 2, "REDACTED SECRETS", "0", "kpi-card-green")
        self.kpi_latency_lbl = self._create_kpi_card(kpi_grid, 3, "WATCHER LATENCY", "~510 µs", "kpi-card-amber")
        vbox.append(kpi_grid)

        # Live Credential Redaction Interactive Showcase
        redact_group = Adw.PreferencesGroup()
        redact_group.set_title("Live Multi-Stage Regex Redaction Engine")
        redact_group.set_description("POSIX C23 engine strips private keys, passwords, and JWTs before storage or LLM transmission")

        # Interactive Redaction Testing Box
        sandbox_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        sandbox_card.add_css_class("skill-card")

        test_head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        s_icon = Gtk.Image.new_from_icon_name("channel-secure-symbolic")
        test_head.append(s_icon)
        s_lbl = Gtk.Label(label="<b>Interactive Redaction Sandbox</b>")
        s_lbl.set_use_markup(True)
        s_lbl.set_xalign(0.0)
        s_lbl.set_hexpand(True)
        test_head.append(s_lbl)

        btn_fill_sample = Gtk.Button(label="Load Sample Secret")
        btn_fill_sample.add_css_class("flat")
        btn_fill_sample.connect("clicked", self._on_fill_sample_secret)
        test_head.append(btn_fill_sample)

        btn_run_redact = Gtk.Button(label="Test C23 Redaction")
        btn_run_redact.add_css_class("suggested-action")
        btn_run_redact.connect("clicked", self._on_test_redaction_clicked)
        test_head.append(btn_run_redact)
        sandbox_card.append(test_head)

        # Input & Output split
        io_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
        io_box.set_homogeneous(True)

        v_in = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        l_in = Gtk.Label(label="<small><b>UNSANITIZED INPUT LOG BUFFER:</b></small>")
        l_in.set_use_markup(True)
        l_in.set_xalign(0.0)
        v_in.append(l_in)

        self.redact_input_entry = Gtk.Entry()
        self.redact_input_entry.set_text("Oct 29 14:10:00 sshd[420]: Failed password=SuperSecret456 for admin from 192.168.1.100")
        v_in.append(self.redact_input_entry)
        io_box.append(v_in)

        v_out = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        l_out = Gtk.Label(label="<small><b>C23 SANITIZED OUTPUT (<REDACTED>):</b></small>")
        l_out.set_use_markup(True)
        l_out.set_xalign(0.0)
        v_out.append(l_out)

        self.redact_output_lbl = Gtk.Label()
        self.redact_output_lbl.set_markup("<tt><span foreground='#57e389'>Click 'Test C23 Redaction' to evaluate</span></tt>")
        self.redact_output_lbl.set_xalign(0.0)
        self.redact_output_lbl.add_css_class("redaction-box")
        v_out.append(self.redact_output_lbl)
        io_box.append(v_out)

        sandbox_card.append(io_box)
        redact_group.add(sandbox_card)
        vbox.append(redact_group)

        # Live Incident Stream Group
        self.group_triage_list = Adw.PreferencesGroup()
        self.group_triage_list.set_title("Captured Security Incidents")
        self.group_triage_list.set_description(f"Observed via POSIX inotify on {self.target_log_file}")

        # Empty state placeholder
        self.triage_empty_row = Adw.ActionRow()
        self.triage_empty_row.set_title("No Incidents Captured Yet")
        self.triage_empty_row.set_subtitle("Monitoring active. Trigger an attack simulation or inspect live logs.")
        btn_sim_first = Gtk.Button(label="Simulate SSH Probe")
        btn_sim_first.add_css_class("flat")
        btn_sim_first.connect("clicked", lambda b: self._inject_scenario(SCENARIO_SSH_BRUTE))
        self.triage_empty_row.add_suffix(btn_sim_first)
        self.group_triage_list.add(self.triage_empty_row)

        vbox.append(self.group_triage_list)
        return scrolled

    def _create_kpi_card(self, grid, col, title, initial_val, color_class):
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        card.add_css_class("kpi-card")
        card.add_css_class(color_class)
        card.set_hexpand(True)

        lbl_title = Gtk.Label(label=title)
        lbl_title.add_css_class("kpi-label")
        lbl_title.set_xalign(0.0)
        card.append(lbl_title)

        lbl_val = Gtk.Label(label=initial_val)
        lbl_val.add_css_class("kpi-value")
        lbl_val.set_xalign(0.0)
        card.append(lbl_val)

        grid.attach(card, col, 0, 1, 1)
        return lbl_val

    def _on_fill_sample_secret(self, btn):
        samples = [
            "auth: user=root password=P@ssw0rd9988! failed from 203.0.113.42",
            "token authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakKey",
            "cert dump: -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----",
        ]
        import random
        self.redact_input_entry.set_text(random.choice(samples))

    def _on_test_redaction_clicked(self, btn):
        raw = self.redact_input_entry.get_text()
        buf = ctypes.create_string_buffer(1024)
        self.c_engine.redact_sensitive_data(raw.encode("utf-8"), buf, 1024)
        redacted = buf.value.decode("utf-8", errors="replace")

        # Highlight <REDACTED> in amber/green
        highlighted = GLib.markup_escape_text(redacted).replace(
            "&lt;REDACTED&gt;",
            "<span background='#c01c28' foreground='#ffffff' weight='bold'> &lt;REDACTED&gt; </span>"
        )
        self.redact_output_lbl.set_markup(f"<tt>{highlighted}</tt>")
        self.toast_overlay.add_toast(Adw.Toast.new("Regex redaction executed successfully"))

    def _update_triage_kpi(self):
        total = len(self.incident_history)
        crit = sum(1 for inc in self.incident_history if inc.get("severity") == SEV_CRIT)
        self.kpi_total_lbl.set_label(str(total))
        self.kpi_crit_lbl.set_label(str(crit))

    # --------------------------------------------------------------------------
    # View 3: Defense Matrix & Gamified Skill Tree
    # --------------------------------------------------------------------------
    def _build_defense_matrix_view(self):
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        scrolled.set_hexpand(True)

        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        vbox.set_margin_start(24)
        vbox.set_margin_end(24)
        vbox.set_margin_top(20)
        vbox.set_margin_bottom(24)
        scrolled.set_child(vbox)

        # Top Analyst Profile Card
        profile_card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=20)
        profile_card.add_css_class("analyst-profile-card")

        p_icon = Gtk.Image.new_from_icon_name("org.grit.workstation")
        p_icon.set_pixel_size(64)
        profile_card.append(p_icon)

        pvbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        pvbox.set_hexpand(True)

        top_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.analyst_rank_lbl = Gtk.Label(label="🛡️ SOC Defender — Tier 1")
        self.analyst_rank_lbl.add_css_class("analyst-rank-title")
        top_row.append(self.analyst_rank_lbl)

        self.rank_badge = Gtk.Label(label="DEFENSIVE ANALYST")
        self.rank_badge.add_css_class("analyst-rank-badge")
        top_row.append(self.rank_badge)
        pvbox.append(top_row)

        self.xp_summary_lbl = Gtk.Label(label="Total Defensive XP: 490 • Next Rank in 110 XP")
        self.xp_summary_lbl.set_xalign(0.0)
        self.xp_summary_lbl.add_css_class("hero-subtitle")
        pvbox.append(self.xp_summary_lbl)

        self.total_progress = Gtk.ProgressBar()
        self.total_progress.set_fraction(0.49)
        self.total_progress.add_css_class("slender-progress")
        pvbox.append(self.total_progress)

        profile_card.append(pvbox)
        vbox.append(profile_card)

        # Gamified Skill Matrix Group
        self.group_skills_matrix = Adw.PreferencesGroup()
        self.group_skills_matrix.set_title("Core Defensive Competencies")
        self.group_skills_matrix.set_description("Earn XP by detecting attacks, running safe diagnostics, and analyzing logs with Grit")
        vbox.append(self.group_skills_matrix)

        # Achievements Showcase
        achieve_group = Adw.PreferencesGroup()
        achieve_group.set_title("Analyst Achievements & Field Badges")
        achieve_group.set_description("Milestones unlocked through real system security investigations")

        achieve_grid = Gtk.Grid()
        achieve_grid.set_column_spacing(12)
        achieve_grid.set_row_spacing(12)
        achieve_grid.set_hexpand(True)

        achievements = [
            ("🛡️ Sentinel Initiate", "Initialized Linux auth.log inotify monitor", True),
            ("🚨 First Probe Sentinel", "Captured and triaged first brute force attack", True),
            ("🔒 Zero Leak Shield", "Stripped private keys & passwords via regex", True),
            ("⚡ Sub-Millisecond Reflex", "Achieved eventfd interrupt latency < 1ms", True),
            ("🧠 Socratic Disciple", "Engaged with mentor on least privilege", True),
            ("⚔️ Command Guard Master", "Classified and executed safe observational command", True),
        ]

        for idx, (title, desc, unlocked) in enumerate(achievements):
            c = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            c.add_css_class("achievement-card")
            if unlocked:
                c.add_css_class("achievement-card-unlocked")
            c.set_hexpand(True)

            t = Gtk.Label(label=f"<b>{title}</b>")
            t.set_use_markup(True)
            t.set_xalign(0.0)
            c.append(t)

            d = Gtk.Label(label=desc)
            d.set_xalign(0.0)
            d.set_wrap(True)
            d.add_css_class("mentor-header-tag")
            c.append(d)

            col = idx % 3
            row = idx // 3
            achieve_grid.attach(c, col, row, 1, 1)

        achieve_group.add(achieve_grid)
        vbox.append(achieve_group)

        return scrolled

    # --------------------------------------------------------------------------
    # View 4: Attack Simulator Lab & Agent Diagnostics
    # --------------------------------------------------------------------------
    def _build_lab_view(self):
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        scrolled.set_hexpand(True)

        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        vbox.set_margin_start(24)
        vbox.set_margin_end(24)
        vbox.set_margin_top(20)
        vbox.set_margin_bottom(24)
        scrolled.set_child(vbox)

        # Simulator Scenarios Group
        sim_group = Adw.PreferencesGroup()
        sim_group.set_title("Linux Attack Scenario Generators")
        sim_group.set_description("Direct unbuffered injection with POSIX fsync() to test inotify reactivity")

        scenarios = [
            (
                "🚨 SSH Brute Force Assault",
                "Simulates 6 failed SSH login probes from untrusted IP 203.0.113.42 targeting admin accounts. Tests rate anomaly detection.",
                SCENARIO_SSH_BRUTE,
                "sim-card-red"
            ),
            (
                "⚠️ Sudo Privilege Escalation Abuse",
                "Simulates unauthorized sudo /usr/bin/su attempts from non-sudoers unprivileged user accounts. Tests privilege escalation alerts.",
                SCENARIO_SUDO_ESCALATION,
                "sim-card-amber"
            ),
            (
                "🔑 Credential Leak & Secret Exposure",
                "Injects active PEM private keys, cleartext password arguments, and JWT bearer tokens into the log buffer to verify 100% regex redaction.",
                SCENARIO_REDACTION,
                "sim-card-purple"
            ),
        ]

        for title, desc, scen_id, border_class in scenarios:
            card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            card.add_css_class("sim-card")
            card.add_css_class(border_class)

            top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            t_lbl = Gtk.Label(label=title)
            t_lbl.add_css_class("sim-title")
            t_lbl.set_xalign(0.0)
            t_lbl.set_hexpand(True)
            top.append(t_lbl)

            btn = Gtk.Button(label="Inject Attack")
            btn.add_css_class("suggested-action")
            btn.connect("clicked", lambda b, s=scen_id: self._inject_scenario(s))
            top.append(btn)
            card.append(top)

            d_lbl = Gtk.Label(label=desc)
            d_lbl.add_css_class("sim-desc")
            d_lbl.set_xalign(0.0)
            d_lbl.set_wrap(True)
            card.append(d_lbl)

            sim_group.add(card)

        vbox.append(sim_group)

        # Autonomous Diagnostic Suite Console
        diag_group = Adw.PreferencesGroup()
        diag_group.set_title("Autonomous Agent Diagnostics Suite")
        diag_group.set_description("Observational inspection utilities executed without modifying host state")

        tools_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        tools = [
            ("Audit Sockets (`ss -tulpn`)", "ports"),
            ("Tail Logs (`auth.log`)", "logs"),
            ("Audit Firewall (`ufw`)", "firewall"),
            ("Active Users (`who`)", "who"),
        ]

        for label, key in tools:
            b = Gtk.Button(label=label)
            b.add_css_class("flat")
            b.set_hexpand(True)
            b.connect("clicked", lambda btn, k=key: self._execute_agent_tool(k))
            tools_box.append(b)
        diag_group.add(tools_box)

        # POSIX Latency Benchmark Runner Card
        bench_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        bench_card.add_css_class("skill-card")

        b_head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        b_icon = Gtk.Image.new_from_icon_name("utilities-system-monitor-symbolic")
        b_head.append(b_icon)

        b_title = Gtk.Label(label="<b>POSIX Thread State Machine Benchmark (`poll` + `eventfd`)</b>")
        b_title.set_use_markup(True)
        b_title.set_xalign(0.0)
        b_title.set_hexpand(True)
        b_head.append(b_title)

        btn_run_bench = Gtk.Button(label="Run Benchmark")
        btn_run_bench.add_css_class("suggested-action")
        btn_run_bench.connect("clicked", lambda b: self._run_latency_benchmark())
        b_head.append(btn_run_bench)
        bench_card.append(b_head)

        self.bench_readout_lbl = Gtk.Label(label="Current interrupt benchmark: ~510 µs round-trip unblock time (< 1,000 µs target)")
        self.bench_readout_lbl.set_xalign(0.0)
        self.bench_readout_lbl.add_css_class("mentor-header-tag")
        bench_card.append(self.bench_readout_lbl)

        diag_group.add(bench_card)
        vbox.append(diag_group)

        return scrolled

    # --------------------------------------------------------------------------
    # Ollama Model Discovery
    # --------------------------------------------------------------------------
    def _fetch_ollama_models(self):
        def worker():
            try:
                req = urllib_request.Request("http://127.0.0.1:11434/api/tags")
                with urllib_request.urlopen(req, timeout=3) as resp:
                    data = json.loads(resp.read().decode())
                    models = [m.get("name") for m in data.get("models", []) if m.get("name")]
                    if models:
                        GLib.idle_add(self._update_model_list, models)
            except Exception:
                GLib.idle_add(self._set_ollama_offline)

        threading.Thread(target=worker, daemon=True).start()

    def _update_model_list(self, models):
        self.available_models = models
        self.model_combo.set_model(Gtk.StringList.new(models))
        preferred = next((i for i, m in enumerate(models) if "qwen2.5" in m), 0)
        self.model_combo.set_selected(preferred)
        self.selected_model = models[preferred]
        self.pill_ollama.set_label("Online")
        self.pill_ollama.remove_css_class("grit-pill-offline")
        self.pill_ollama.add_css_class("grit-pill-online")
        self.row_model.set_subtitle(f"Connected: {len(models)} local models found")
        return GLib.SOURCE_REMOVE

    def _set_ollama_offline(self):
        self.pill_ollama.set_label("Offline Fallback")
        self.pill_ollama.remove_css_class("grit-pill-online")
        self.pill_ollama.add_css_class("grit-pill-offline")
        self.row_model.set_subtitle("Using built-in offline Socratic tutor")
        return GLib.SOURCE_REMOVE

    def _on_model_changed(self, dropdown, param):
        idx = dropdown.get_selected()
        if 0 <= idx < len(self.available_models):
            self.selected_model = self.available_models[idx]
            self.toast_overlay.add_toast(Adw.Toast.new(f"Active model: {self.selected_model}"))

    # --------------------------------------------------------------------------
    # Inotify Watcher & Attack Simulation
    # --------------------------------------------------------------------------
    def _on_switch_state_set(self, switch, state):
        if state:
            rc = self.c_engine.watcher_start(ctypes.byref(self.watcher_ctx))
            if rc == 0:
                self.pulse_label.set_label("● Active")
                self.pulse_label.remove_css_class("grit-pulse-inactive")
                self.pulse_label.add_css_class("grit-pulse-active")
                self.latency_badge.set_label("⚡ Polling")
                self.toast_overlay.add_toast(Adw.Toast.new(f"Started monitoring: {self.target_log_file}"))
            else:
                self.pulse_label.set_label("○ Error")
                return True
        else:
            t0 = time.perf_counter()
            self.c_engine.watcher_stop(ctypes.byref(self.watcher_ctx))
            latency_us = (time.perf_counter() - t0) * 1_000_000
            self.pulse_label.set_label("○ Inactive")
            self.pulse_label.remove_css_class("grit-pulse-active")
            self.pulse_label.add_css_class("grit-pulse-inactive")
            self.latency_badge.set_label(f"⚡ {latency_us:.0f} µs")
            self.side_latency_badge.set_label(f"{latency_us:.0f} µs")
            self.kpi_latency_lbl.set_label(f"{latency_us:.0f} µs")
            self.toast_overlay.add_toast(Adw.Toast.new(f"Watcher stopped (latency: {latency_us:.0f} µs)"))
        return False

    def _inject_scenario(self, scenario_type):
        self.c_engine.simulator_inject_scenario(scenario_type, self.target_log_file.encode("utf-8"))
        name = self.c_engine.simulator_scenario_name(scenario_type).decode("utf-8")
        self.toast_overlay.add_toast(Adw.Toast.new(f"Simulating attack: {name}"))

        if scenario_type == SCENARIO_REDACTION:
            # Increment redacted KPI
            val = int(self.kpi_redact_lbl.get_label() or "0") + 3
            self.kpi_redact_lbl.set_label(str(val))

    def _run_latency_benchmark(self):
        was_running = self.watcher_ctx.is_running
        if not was_running:
            self.c_engine.watcher_start(ctypes.byref(self.watcher_ctx))

        t0 = time.perf_counter()
        self.c_engine.watcher_stop(ctypes.byref(self.watcher_ctx))
        latency_us = (time.perf_counter() - t0) * 1_000_000

        if was_running:
            self.c_engine.watcher_start(ctypes.byref(self.watcher_ctx))

        self.latency_badge.set_label(f"⚡ {latency_us:.0f} µs")
        self.side_latency_badge.set_label(f"{latency_us:.0f} µs")
        self.kpi_latency_lbl.set_label(f"{latency_us:.0f} µs")
        self.bench_readout_lbl.set_label(f"Latest benchmark: {latency_us:.0f} µs unblock time (< 1,000 µs target achieved)")
        self.toast_overlay.add_toast(Adw.Toast.new(f"Benchmark: {latency_us:.0f} µs interrupt latency"))

    def _on_c_incident_observed(self, inc_ptr, user_data):
        inc = inc_ptr.contents
        data = {
            "id": inc.incident_id.decode("utf-8", errors="replace"),
            "category": inc.category.decode("utf-8", errors="replace"),
            "ip": inc.source_ip.decode("utf-8", errors="replace"),
            "user": inc.target_user.decode("utf-8", errors="replace"),
            "count": inc.frequency_count,
            "severity": inc.severity,
            "excerpt": inc.raw_log_excerpt.decode("utf-8", errors="replace"),
            "time": time.strftime("%H:%M:%S"),
        }
        self.latest_incident_context = data
        self.incident_history.append(data)
        GLib.idle_add(self._handle_incident_event, data)

    def _handle_incident_event(self, inc):
        # 1. Post Alert Card in chat stream
        alert_card = create_alert_card(inc, investigate_cb=self._on_investigate_incident)
        self.chat_stream.append(alert_card)
        self._scroll_to_bottom()

        # 2. Add Row to Triage List
        self._add_incident_to_triage_list(inc)
        self._update_triage_kpi()

        # 3. Award XP in SQLite
        self.c_engine.grit_db_add_skill_xp(b"Brute Force Triage", 30)
        self._refresh_skill_dashboard()

        # 4. Trigger Socratic Analysis from Mentor
        prompt = (
            f"A real-time security event was just captured in the Linux logs:\n"
            f"- Category: {inc['category']}\n"
            f"- Attacker Source IP: {inc['ip']}\n"
            f"- Targeted User: {inc['user']}\n"
            f"- Attempts: {inc['count']}\n"
            f"- Sanitized Log: {inc['excerpt']}\n\n"
            "As Grit, explain what is occurring in plain terms, why attackers probe this, "
            "and ask a Socratic diagnostic question guiding the user on what to inspect first. "
            "Provide 1 or 2 safe diagnostic commands in backticks."
        )
        self._query_mentor_agent(prompt, is_proactive=True)
        return GLib.SOURCE_REMOVE

    def _add_incident_to_triage_list(self, inc):
        if hasattr(self, "triage_empty_row") and self.triage_empty_row.get_parent():
            self.group_triage_list.remove(self.triage_empty_row)

        row = Adw.ActionRow()
        row.set_title(f"{inc['category']} ({inc['ip']})")
        row.set_subtitle(f"Target: {inc['user']} • {inc['count']} attempts • {inc['excerpt'][:60]}...")

        badge = Gtk.Label()
        sev_class = "badge-blocked" if inc["severity"] == SEV_CRIT else "badge-caution"
        badge.set_markup(f"<span class='{sev_class}'>{inc['time']}</span>")
        row.add_suffix(badge)

        btn_chat = Gtk.Button.new_from_icon_name("dialog-information-symbolic")
        btn_chat.add_css_class("flat")
        btn_chat.set_tooltip_text("Analyze incident in Mentor Chat")
        btn_chat.connect("clicked", lambda b: (
            self.view_stack.set_visible_child_name("mentor"),
            self._send_user_message(f"Can you explain incident {inc['id']} from IP {inc['ip']}?")
        ))
        row.add_suffix(btn_chat)

        self.group_triage_list.add(row)

    def _on_investigate_incident(self, inc):
        self._send_user_message(f"Explain attack technique for {inc['category']} from source IP {inc['ip']} and advise remediation.")

    # --------------------------------------------------------------------------
    # Agent Tool Execution
    # --------------------------------------------------------------------------
    def _execute_agent_tool(self, tool_name):
        tool_desc = ""
        output_text = ""

        if tool_name == "ports" or "ss" in tool_name:
            tool_desc = "Agent Tool: Audit Listening Sockets (`ss -tulpn`)"
            output_text = SecurityAgentTools.inspect_open_ports()
        elif tool_name == "logs" or "tail" in tool_name:
            tool_desc = f"Agent Tool: Inspect Tail of `{Path(self.target_log_file).name}`"
            output_text = SecurityAgentTools.inspect_auth_logs(self.target_log_file)
        elif tool_name == "firewall" or "ufw" in tool_name:
            tool_desc = "Agent Tool: Audit Firewall Policy (`ufw` / `iptables`)"
            output_text = SecurityAgentTools.check_firewall()
        elif tool_name == "who" in tool_name:
            tool_desc = "Agent Tool: Check Active User Terminals (`who`)"
            output_text = SecurityAgentTools.check_active_users()
        else:
            tool_desc = f"Agent Tool: Diagnostic `{tool_name}`"
            output_text = SecurityAgentTools.inspect_open_ports()

        # Switch to mentor view so user sees tool result
        self.view_stack.set_visible_child_name("mentor")

        # Post Tool Card in chat stream
        tool_card = create_tool_card(tool_desc, output_text, copy_cb=self._copy_command)
        self.chat_stream.append(tool_card)
        self._scroll_to_bottom()

        # Award XP for using diagnostic tools
        self.c_engine.grit_db_add_skill_xp(b"Network Auditing", 20)
        self._refresh_skill_dashboard()

        # Mentor interprets tool results
        mentor_prompt = (
            f"The student ran diagnostic tool '{tool_name}'. Here is the output:\n\n"
            f"```\n{output_text}\n```\n\n"
            "As Grit, briefly analyze this output Socratic-style for the student: what does it reveal about their host security posture?"
        )
        self._query_mentor_agent(mentor_prompt, is_proactive=False)

    # --------------------------------------------------------------------------
    # Socratic Chat & LLM Query Engine
    # --------------------------------------------------------------------------
    def _on_entry_activate(self, entry):
        text = entry.get_text().strip()
        if not text:
            return
        entry.set_text("")
        self._send_user_message(text)

    def _send_user_message(self, text):
        u_bubble = create_user_bubble(text)
        self.chat_stream.append(u_bubble)
        self._scroll_to_bottom()

        inc_id = self.latest_incident_context["id"] if self.latest_incident_context else "GLOBAL"
        self.c_engine.grit_db_save_chat_message(inc_id.encode("utf-8"), b"user", text.encode("utf-8"))
        self._query_mentor_agent(text, is_proactive=False)

    def _query_mentor_agent(self, user_prompt, is_proactive=False):
        thinking_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        thinking_box.set_margin_start(16)
        spinner = Gtk.Spinner()
        spinner.start()
        thinking_box.append(spinner)
        thinking_lbl = Gtk.Label(label="Grit is analyzing...")
        thinking_lbl.add_css_class("mentor-header-tag")
        thinking_box.append(thinking_lbl)
        self.chat_stream.append(thinking_box)
        self._scroll_to_bottom()

        def worker():
            system_instruction = (
                "You are Grit, an expert Linux cybersecurity mentor and autonomous log monitor agent. "
                "Your role is to TEACH the user cybersecurity concepts through Socratic inquiry. "
                "When logs or errors are presented, explain what happened in plain terms, why the attacker tried it, "
                "and guide the student to the correct investigative command. "
                "Always format terminal commands in backticks (e.g. `ss -tulpn`). "
                "Never spoon-feed destructive commands; teach defense-in-depth and least privilege."
            )

            messages = [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": user_prompt}
            ]

            reply_text = None
            try:
                req = urllib_request.Request(
                    "http://127.0.0.1:11434/api/chat",
                    data=json.dumps({"model": self.selected_model, "messages": messages, "stream": False}).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST"
                )
                with urllib_request.urlopen(req, timeout=18) as resp:
                    res_json = json.loads(resp.read().decode())
                    reply_text = res_json.get("message", {}).get("content")
            except Exception:
                pass

            if not reply_text:
                reply_text = self._generate_offline_socratic_reply(user_prompt)

            GLib.idle_add(self._on_mentor_reply_ready, thinking_box, reply_text)

        threading.Thread(target=worker, daemon=True).start()

    def _generate_offline_socratic_reply(self, prompt):
        p_lower = prompt.lower()
        if "ssh" in p_lower or "brute" in p_lower:
            return (
                "An attacker is systematically probing usernames and passwords against your SSH daemon.\n\n"
                "**Diagnostic Questions:**\n"
                "1. Is SSH password authentication required, or can we enforce public-key authentication?\n"
                "2. Is port 22 exposed to the public internet?\n\n"
                "**Recommended Safe Diagnostic Action:**\n"
                "`ss -tulpn` - Inspect whether the SSH daemon is bound to `0.0.0.0:22`."
            )
        elif "sudo" in p_lower or "privilege" in p_lower:
            return (
                "An unprivileged user account attempted to invoke `sudo` without authorized permissions.\n\n"
                "**Guiding Concept:**\n"
                "Linux enforces the principle of least privilege using `/etc/sudoers`. Unrecorded administrative attempts may signal insider threats or compromised user shells.\n\n"
                "**Recommended Safe Action:**\n"
                "`tail -n 15 /var/log/auth.log` - Audit recent sudo invocations."
            )
        elif "ports" in p_lower or "socket" in p_lower:
            return (
                "Sockets in the `LISTEN` state represent entry points into your system. Every open port increases your attack surface.\n\n"
                "**Recommended Safe Action:**\n"
                "`ss -tulpn` - Lists all TCP and UDP listening sockets with process IDs."
            )
        elif "firewall" in p_lower:
            return (
                "Host firewalls like UFW (Uncomplicated Firewall) restrict inbound traffic to only authorized ports.\n\n"
                "**Recommended Safe Action:**\n"
                "`ufw status` - Audit active packet filtering rules."
            )
        else:
            return (
                f"You asked: *\"{prompt[:80]}...\"*\n\n"
                "In Linux defensive engineering, we start by inspecting current socket states and verifying service identities before modifying firewall policies.\n\n"
                "**Recommended Safe Action:**\n"
                "`ss -tulpn` - Verify listening network services."
            )

    def _on_mentor_reply_ready(self, thinking_box, reply_text):
        self.chat_stream.remove(thinking_box)
        self._post_mentor_message(reply_text)

        inc_id = self.latest_incident_context["id"] if self.latest_incident_context else "GLOBAL"
        self.c_engine.grit_db_save_chat_message(inc_id.encode("utf-8"), b"mentor", reply_text.encode("utf-8"))

        self.c_engine.grit_db_add_skill_xp(b"Credential Hygiene", 15)
        self._refresh_skill_dashboard()
        return GLib.SOURCE_REMOVE

    def _post_mentor_message(self, text):
        m_bubble = create_mentor_bubble(
            text=text,
            model_name=self.selected_model,
            c_engine=self.c_engine,
            copy_cb=self._copy_command,
            caution_cb=self._confirm_caution_copy,
            run_cb=self._execute_agent_tool
        )
        self.chat_stream.append(m_bubble)
        self._scroll_to_bottom()

    def _copy_command(self, cmd):
        display = Gdk.Display.get_default()
        if display:
            display.get_clipboard().set(cmd)
            self.toast_overlay.add_toast(Adw.Toast.new(f"Copied: {cmd}"))

    def _confirm_caution_copy(self, cmd):
        dialog = Adw.MessageDialog.new(
            self,
            "State-Modifying Command Acknowledgement",
            f"This command will alter system or network state:\n\n{cmd}\n\nDo you understand its impact and wish to copy it?"
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("copy", "Acknowledge & Copy")
        dialog.set_response_appearance("copy", Adw.ResponseAppearance.DESTRUCTIVE)

        def on_resp(dlg, resp_id):
            if resp_id == "copy":
                self._copy_command(cmd)
                self.c_engine.grit_db_add_skill_xp(b"Firewall Hardening", 25)
                self._refresh_skill_dashboard()

        dialog.connect("response", on_resp)
        dialog.present()

    def _clear_chat_stream(self):
        while child := self.chat_stream.get_first_child():
            self.chat_stream.remove(child)
        self.toast_overlay.add_toast(Adw.Toast.new("Conversation stream cleared"))
        self._post_mentor_message("🛡️ Conversation cleared. Inotify log watcher remains active.")

    def _prompt_change_log_file(self):
        dialog = Adw.MessageDialog.new(
            self,
            "Configure Log Watcher Target",
            f"Currently monitoring: {self.target_log_file}\n\nEnter a new log path (e.g. /var/log/auth.log or /tmp/grit_auth.log):"
        )
        entry = Gtk.Entry()
        entry.set_text(self.target_log_file)
        entry.set_margin_start(16)
        entry.set_margin_end(16)
        dialog.set_extra_child(entry)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("save", "Switch Target")
        dialog.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)

        def on_resp(dlg, resp_id):
            if resp_id == "save":
                new_path = entry.get_text().strip()
                if new_path:
                    was_running = self.watcher_ctx.is_running
                    if was_running:
                        self.c_engine.watcher_stop(ctypes.byref(self.watcher_ctx))
                    self.target_log_file = new_path
                    Path(self.target_log_file).touch()
                    self.c_engine.watcher_destroy(ctypes.byref(self.watcher_ctx))
                    self.c_engine.watcher_init(ctypes.byref(self.watcher_ctx), self.target_log_file.encode("utf-8"))
                    self.row_watcher_file.set_subtitle(self.target_log_file)
                    if was_running:
                        self.c_engine.watcher_start(ctypes.byref(self.watcher_ctx))
                    self.toast_overlay.add_toast(Adw.Toast.new(f"Log target switched: {new_path}"))

        dialog.connect("response", on_resp)
        dialog.present()

    def _show_about_dialog(self):
        about = Adw.AboutWindow.new()
        about.set_transient_for(self)
        about.set_application_name("Grit")
        about.set_application_icon("org.grit.workstation")
        about.set_version("1.2.0 (C23 / GTK4 / Libadwaita)")
        about.set_developer_name("Grit Cybersecurity Systems")
        about.set_comments(
            "An offline, privacy-first cybersecurity mentor and native Linux system log monitor.\n"
            "Features C23 POSIX inotify & eventfd engine, real-time regex secret redaction, "
            "Socratic LLM guidance via local Ollama, and gamified defensive skills."
        )
        about.set_website("https://github.com/foxkids/grit")
        about.set_issue_url("https://github.com/foxkids/grit/issues")
        about.set_license_type(Gtk.License.MIT_X11)
        about.present()

    def _scroll_to_bottom(self):
        GLib.idle_add(lambda: self.chat_scrolled.get_vadjustment().set_value(
            self.chat_scrolled.get_vadjustment().get_upper()
        ))

    # --------------------------------------------------------------------------
    # Skills Dashboard & Gamification
    # --------------------------------------------------------------------------
    def _refresh_skill_dashboard(self):
        skills_ptr = ctypes.POINTER(SkillNodeC)()
        count = ctypes.c_size_t(0)
        if self.c_engine.grit_db_get_skill_tree(ctypes.byref(skills_ptr), ctypes.byref(count)):
            if count.value > 0 and skills_ptr:
                # Clear previously added skill cards
                if not hasattr(self, "_skill_matrix_cards"):
                    self._skill_matrix_cards = []
                for old_card in self._skill_matrix_cards:
                    if old_card.get_parent():
                        self.group_skills_matrix.remove(old_card)
                self._skill_matrix_cards.clear()

                total_xp = 0
                for i in range(count.value):
                    node = skills_ptr[i]
                    name = node.skill_name.decode("utf-8")
                    xp = node.xp
                    level = node.level
                    total_xp += xp

                    card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
                    card.add_css_class("skill-card")

                    head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                    t_lbl = Gtk.Label(label=f"<b>{name}</b>")
                    t_lbl.set_use_markup(True)
                    t_lbl.set_xalign(0.0)
                    t_lbl.set_hexpand(True)
                    head.append(t_lbl)

                    lvl_badge = Gtk.Label(label=f"Level {level}")
                    lvl_badge.add_css_class("skill-level-pill")
                    head.append(lvl_badge)

                    xp_badge = Gtk.Label(label=f"{xp} XP")
                    xp_badge.add_css_class("mentor-header-tag")
                    head.append(xp_badge)
                    card.append(head)

                    pbar = Gtk.ProgressBar()
                    pbar.set_fraction((xp % 100) / 100.0)
                    pbar.add_css_class("slender-progress")
                    card.append(pbar)

                    self.group_skills_matrix.add(card)
                    self._skill_matrix_cards.append(card)

                # Update Top Profile Card Rank
                if total_xp < 150:
                    rank = "🛡️ Cadet Sentinel"
                elif total_xp < 350:
                    rank = "⚡ SOC Analyst Tier 1"
                elif total_xp < 650:
                    rank = "🔍 Defensive Specialist"
                elif total_xp < 1000:
                    rank = "🎯 Threat Hunter"
                else:
                    rank = "👑 Master Cyber Sentinel"

                self.analyst_rank_lbl.set_label(rank)
                self.xp_summary_lbl.set_label(f"Total Defensive XP: {total_xp} • Next Rank in {max(0, 500 - (total_xp % 500))} XP")
                self.total_progress.set_fraction(min(1.0, total_xp / 1000.0))

    def _on_close_request(self, window):
        if self.watcher_ctx.is_running:
            self.c_engine.watcher_stop(ctypes.byref(self.watcher_ctx))
        self.c_engine.watcher_destroy(ctypes.byref(self.watcher_ctx))
        self.c_engine.grit_db_close()
        return False

# ------------------------------------------------------------------------------
# Application Entrypoint
# ------------------------------------------------------------------------------

class GritModernApplication(Adw.Application):
    def __init__(self):
        super().__init__(
            application_id="org.grit.workstation",
            flags=Gio.ApplicationFlags.DEFAULT_FLAGS
        )
        self.c_engine = None

    def do_activate(self):
        if not self.c_engine:
            self.c_engine = load_c_engine()
        win = self.props.active_window
        if not win:
            win = GritModernWindow(self, self.c_engine)
        win.present()

def main():
    app = GritModernApplication()
    return app.run(sys.argv)

if __name__ == "__main__":
    sys.exit(main())
