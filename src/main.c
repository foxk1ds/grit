#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include "core/types.h"
#include "core/watcher.h"
#include "core/simulator.h"
#include "mentor/command_guard.h"
#include "mentor/llm_client.h"
#include "db/db.h"

#if __has_include(<gtk/gtk.h>)
#include <gtk/gtk.h>
#define HAVE_GTK4 1
#else
#define HAVE_GTK4 0
#endif

// Global flag for headless signal handling
static volatile sig_atomic_t g_shutdown_requested = 0;

static void handle_sigint(int sig) {
    (void)sig;
    g_shutdown_requested = 1;
}

static void on_headless_incident(const Incident *incident, void *user_data) {
    (void)user_data;
    printf("\n[INCIDENT DETECTED]\n");
    printf("  ID:        %s\n", incident->incident_id);
    printf("  Category:  %s\n", incident->category);
    printf("  Source IP: %s\n", incident->source_ip);
    printf("  Target:    %s\n", incident->target_user);
    printf("  Severity:  %s (%d)\n",
           incident->severity == SEV_CRIT ? "CRITICAL" :
           (incident->severity == SEV_WARN ? "WARNING" : "INFO"),
           (int)incident->severity);
    printf("  Excerpt:   %s\n", incident->raw_log_excerpt);
}

// -----------------------------------------------------------------------------
// CLI Subcommands
// -----------------------------------------------------------------------------

static int run_cli_simulate(const char *scenario_name) {
    ScenarioType type = SCENARIO_SSH_BRUTE_FORCE;
    if (scenario_name && !simulator_parse_type(scenario_name, &type)) {
        fprintf(stderr, "Unknown scenario '%s'. Available: ssh_brute, sudo_abuse, redaction_test\n", scenario_name);
        return 1;
    }

    const char *test_log = "/tmp/grit_test_auth.log";
    // Truncate test file
    FILE *f = fopen(test_log, "w");
    if (f) fclose(f);

    printf("================================================================\n");
    printf("   Grit Scenario Simulation: %s\n", simulator_scenario_name(type));
    printf("================================================================\n");

    grit_db_init(":memory:");

    WatcherContext watcher;
    if (watcher_init(&watcher, test_log) != 0) {
        fprintf(stderr, "Failed to initialize watcher on %s\n", test_log);
        return 1;
    }

    watcher_register_observer(on_headless_incident, NULL);
    watcher_start(&watcher);
    usleep(50000); // 50ms to enter poll()

    printf("[*] Injecting scenario events into %s...\n", test_log);
    bool ok = simulator_inject_scenario(type, test_log);
    if (!ok) {
        fprintf(stderr, "Simulation injection failed.\n");
        watcher_stop(&watcher);
        watcher_destroy(&watcher);
        return 1;
    }

    // Allow inotify to process
    usleep(300000);

    printf("\n[*] Stopping watcher (0ms latency interrupt test)...\n");
    watcher_stop(&watcher);
    watcher_destroy(&watcher);
    grit_db_close();

    printf("[✓] Scenario simulation completed successfully.\n");
    return 0;
}

static int run_cli_headless(const char *target_log) {
    const char *target = (target_log && target_log[0] != '\0') ? target_log : "/var/log/auth.log";
    if (access(target, R_OK) != 0) {
        target = "/tmp/grit_auth.log";
        FILE *f = fopen(target, "a");
        if (f) fclose(f);
    }

    printf("================================================================\n");
    printf("   Grit Headless Daemon Monitoring: %s\n", target);
    printf("   Press Ctrl+C to stop.\n");
    printf("================================================================\n");

    grit_db_init(NULL);

    WatcherContext watcher;
    if (watcher_init(&watcher, target) != 0) {
        fprintf(stderr, "Failed to initialize watcher on %s\n", target);
        grit_db_close();
        return 1;
    }

    watcher_register_observer(on_headless_incident, NULL);
    if (watcher_start(&watcher) != 0) {
        fprintf(stderr, "Failed to start background watcher\n");
        watcher_destroy(&watcher);
        grit_db_close();
        return 1;
    }

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    while (!g_shutdown_requested) {
        pause();
    }

    printf("\n[*] Shutting down watcher via eventfd interrupt...\n");
    watcher_stop(&watcher);
    watcher_destroy(&watcher);
    grit_db_close();
    printf("[✓] Clean exit.\n");
    return 0;
}

// -----------------------------------------------------------------------------
// Native GTK4 Desktop Application GUI
// -----------------------------------------------------------------------------

#if HAVE_GTK4

typedef struct {
    GtkApplication *app;
    GtkWidget *window;
    GtkWidget *watcher_switch;
    GtkWidget *status_label;
    GtkWidget *incidents_box;
    WatcherContext watcher;
} GritApp;

static GritApp g_grit_app;

static gboolean on_switch_state_set(GtkSwitch *sw, gboolean state, gpointer user_data) {
    (void)sw;
    GritApp *app = (GritApp *)user_data;

    if (state) {
        int rc = watcher_start(&app->watcher);
        if (rc == 0) {
            gtk_label_set_markup(GTK_LABEL(app->status_label),
                "<span foreground='#2ec27e' weight='bold'>● WATCHER ACTIVE</span> (poll + eventfd polling)");
        } else {
            gtk_label_set_markup(GTK_LABEL(app->status_label),
                "<span foreground='#e01b24' weight='bold'>● ERROR</span>: Failed to start watcher");
            return TRUE;
        }
    } else {
        watcher_stop(&app->watcher);
        gtk_label_set_markup(GTK_LABEL(app->status_label),
            "<span foreground='#888888' weight='bold'>○ WATCHER STOPPED</span> (0ms latency shutdown)");
    }
    return FALSE;
}

static gboolean on_window_close_request(GtkWindow *window, gpointer user_data) {
    (void)window;
    GritApp *app = (GritApp *)user_data;
    if (atomic_load(&app->watcher.is_running)) {
        watcher_stop(&app->watcher);
    }
    watcher_destroy(&app->watcher);
    grit_db_close();
    return FALSE;
}

static void on_copy_command_clicked(GtkButton *btn, gpointer user_data) {
    (void)btn;
    const char *cmd_text = (const char *)user_data;
    if (!cmd_text) return;

    GdkDisplay *display = gdk_display_get_default();
    if (display) {
        GdkClipboard *clipboard = gdk_display_get_clipboard(display);
        gdk_clipboard_set_text(clipboard, cmd_text);
    }
}

static GtkWidget *create_command_action_row(const SuggestedAction *action) {
    GtkWidget *row_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_margin_top(row_box, 6);
    gtk_widget_set_margin_bottom(row_box, 6);

    GtkWidget *badge = gtk_label_new(NULL);
    CommandSafety safety = evaluate_command_safety(action->command);

    const char *badge_color = "#3584e4";
    const char *badge_text = command_safety_to_string(safety);
    if (safety == CMD_SAFE) {
        badge_color = "#26a269";
    } else if (safety == CMD_CAUTION) {
        badge_color = "#e5a50a";
    } else if (safety == CMD_BLOCKED) {
        badge_color = "#c01c28";
    }

    char badge_markup[256];
    snprintf(badge_markup, sizeof(badge_markup),
             "<span background='%s' foreground='#ffffff' weight='bold'>  %s  </span>",
             badge_color, badge_text);
    gtk_label_set_markup(GTK_LABEL(badge), badge_markup);

    GtkWidget *cmd_label = gtk_label_new(NULL);
    char cmd_markup[512];
    snprintf(cmd_markup, sizeof(cmd_markup), "<tt><b>%s</b></tt> - <span color='#555555'>%s</span>",
             action->command, action->explanation);
    gtk_label_set_markup(GTK_LABEL(cmd_label), cmd_markup);
    gtk_label_set_xalign(GTK_LABEL(cmd_label), 0.0f);
    gtk_widget_set_hexpand(cmd_label, TRUE);

    GtkWidget *copy_btn = gtk_button_new_with_label("Copy");
    g_signal_connect(copy_btn, "clicked", G_CALLBACK(on_copy_command_clicked), (gpointer)action->command);

    gtk_box_append(GTK_BOX(row_box), badge);
    gtk_box_append(GTK_BOX(row_box), cmd_label);
    gtk_box_append(GTK_BOX(row_box), copy_btn);

    return row_box;
}

static void activate(GtkApplication *app, gpointer user_data) {
    GritApp *grit = (GritApp *)user_data;
    grit->app = app;

    grit->window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(grit->window), "Grit - Offline Cybersecurity Mentor");
    gtk_window_set_default_size(GTK_WINDOW(grit->window), 880, 700);
    g_signal_connect(grit->window, "close-request", G_CALLBACK(on_window_close_request), grit);

    GtkWidget *main_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 16);
    gtk_widget_set_margin_top(main_box, 20);
    gtk_widget_set_margin_bottom(main_box, 20);
    gtk_widget_set_margin_start(main_box, 24);
    gtk_widget_set_margin_end(main_box, 24);
    gtk_window_set_child(GTK_WINDOW(grit->window), main_box);

    GtkWidget *title_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title_label),
        "<span size='xx-large' weight='heavy'>🛡️ Grit</span>\n"
        "<span size='small' color='#666666'>Offline Cybersecurity Mentor & Native Linux Log Monitor (C23 / GTK4)</span>");
    gtk_label_set_xalign(GTK_LABEL(title_label), 0.0f);
    gtk_box_append(GTK_BOX(main_box), title_label);

    // Watcher Controller Frame
    GtkWidget *frame = gtk_frame_new("Log Watcher Controller");
    GtkWidget *control_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 16);
    gtk_widget_set_margin_top(control_box, 12);
    gtk_widget_set_margin_bottom(control_box, 12);
    gtk_widget_set_margin_start(control_box, 16);
    gtk_widget_set_margin_end(control_box, 16);
    gtk_frame_set_child(GTK_FRAME(frame), control_box);

    GtkWidget *switch_desc = gtk_label_new("Monitor <tt>/var/log/auth.log</tt> via inotify + eventfd:");
    gtk_label_set_use_markup(GTK_LABEL(switch_desc), TRUE);
    gtk_box_append(GTK_BOX(control_box), switch_desc);

    grit->watcher_switch = gtk_switch_new();
    gtk_widget_set_valign(grit->watcher_switch, GTK_ALIGN_CENTER);
    g_signal_connect(grit->watcher_switch, "state-set", G_CALLBACK(on_switch_state_set), grit);
    gtk_box_append(GTK_BOX(control_box), grit->watcher_switch);

    grit->status_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(grit->status_label),
        "<span foreground='#888888' weight='bold'>○ WATCHER STOPPED</span> (0ms latency shutdown)");
    gtk_widget_set_hexpand(grit->status_label, TRUE);
    gtk_label_set_xalign(GTK_LABEL(grit->status_label), 1.0f);
    gtk_box_append(GTK_BOX(control_box), grit->status_label);

    gtk_box_append(GTK_BOX(main_box), frame);

    // Incident Frame
    GtkWidget *inc_frame = gtk_frame_new("Latest Detected Incident & Sanitized Payload");
    GtkWidget *inc_inner_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_top(inc_inner_box, 12);
    gtk_widget_set_margin_bottom(inc_inner_box, 12);
    gtk_widget_set_margin_start(inc_inner_box, 16);
    gtk_widget_set_margin_end(inc_inner_box, 16);
    gtk_frame_set_child(GTK_FRAME(inc_frame), inc_inner_box);

    Incident sample_inc = {
        .incident_id = "SEC-1704100000-001",
        .category = "SSH Brute Force",
        .source_ip = "192.168.1.50",
        .target_user = "root",
        .frequency_count = 42,
        .first_seen = 1704100000,
        .last_seen = 1704100360,
        .severity = SEV_CRIT
    };
    const char *unredacted = "Failed password for root from 192.168.1.50 port 54321 ssh2: password=SecretP@ssw0rd123!";
    redact_sensitive_data(unredacted, sample_inc.raw_log_excerpt, sizeof(sample_inc.raw_log_excerpt));

    char inc_details[1024];
    snprintf(inc_details, sizeof(inc_details),
        "<b>Incident ID:</b> <tt>%s</tt> | <b>Category:</b> %s | <b>Severity:</b> <span foreground='#c01c28' weight='bold'>CRITICAL (%d)</span>\n"
        "<b>Source IP:</b> <tt>%s</tt> | <b>Target User:</b> <tt>%s</tt> | <b>Attempts:</b> %d\n"
        "<b>Sanitized Excerpt:</b> <tt>%s</tt>",
        sample_inc.incident_id, sample_inc.category, sample_inc.severity,
        sample_inc.source_ip, sample_inc.target_user, sample_inc.frequency_count,
        sample_inc.raw_log_excerpt);

    GtkWidget *inc_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(inc_label), inc_details);
    gtk_label_set_xalign(GTK_LABEL(inc_label), 0.0f);
    gtk_box_append(GTK_BOX(inc_inner_box), inc_label);
    gtk_box_append(GTK_BOX(main_box), inc_frame);

    // Mentor Frame
    GtkWidget *mentor_frame = gtk_frame_new("Socratic Mentor Analysis & Suggested Actions (Command Guard)");
    GtkWidget *mentor_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_top(mentor_box, 12);
    gtk_widget_set_margin_bottom(mentor_box, 12);
    gtk_widget_set_margin_start(mentor_box, 16);
    gtk_widget_set_margin_end(mentor_box, 16);
    gtk_frame_set_child(GTK_FRAME(mentor_frame), mentor_box);

    GtkWidget *mentor_analysis = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(mentor_analysis),
        "<i>\"We notice repeated unauthorized authentication failures from host 192.168.1.50 against the root account.\n"
        "Consider: Is SSH root login necessary on this interface? First inspect current socket states before modifying firewall filters.\"</i>");
    gtk_label_set_xalign(GTK_LABEL(mentor_analysis), 0.0f);
    gtk_box_append(GTK_BOX(mentor_box), mentor_analysis);

    SuggestedAction actions[3] = {
        {
            .command = "ss -tulpn | grep :22",
            .safety_level = CMD_SAFE,
            .explanation = "Inspect listening SSH sockets and bound network interfaces."
        },
        {
            .command = "ufw deny from 192.168.1.50 to any port 22 proto tcp",
            .safety_level = CMD_CAUTION,
            .explanation = "Drop inbound TCP connections from attacker IP via UFW."
        },
        {
            .command = "rm -rf /var/log/auth.log",
            .safety_level = CMD_BLOCKED,
            .explanation = "Destructive log removal attempt - blocked by Command Guard."
        }
    };

    for (int i = 0; i < 3; i++) {
        GtkWidget *act_row = create_command_action_row(&actions[i]);
        gtk_box_append(GTK_BOX(mentor_box), act_row);
    }

    gtk_box_append(GTK_BOX(main_box), mentor_frame);
    gtk_window_present(GTK_WINDOW(grit->window));
}

#endif // HAVE_GTK4

int main(int argc, char **argv) {
    // 1. Process CLI Flags
    if (argc > 1) {
        if (strcmp(argv[1], "--simulate") == 0) {
            const char *scenario = (argc > 2) ? argv[2] : "ssh_brute";
            return run_cli_simulate(scenario);
        }
        if (strcmp(argv[1], "--headless") == 0) {
            const char *log_file = (argc > 2) ? argv[2] : NULL;
            return run_cli_headless(log_file);
        }
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            printf("Usage: grit [OPTIONS]\n\n"
                   "Options:\n"
                   "  --simulate [ssh_brute|sudo_abuse|redaction_test]  Inject realistic attack scenario\n"
                   "  --headless [log_path]                             Run headless log watcher daemon\n"
                   "  --help, -h                                        Show this help message\n");
            return 0;
        }
    }

#if HAVE_GTK4
    memset(&g_grit_app, 0, sizeof(g_grit_app));
    grit_db_init(NULL);

    const char *target = "/var/log/auth.log";
    if (access(target, R_OK) != 0) {
        target = "/tmp/grit_auth.log";
        FILE *f = fopen(target, "a");
        if (f) fclose(f);
    }

    if (watcher_init(&g_grit_app.watcher, target) != 0) {
        fprintf(stderr, "Warning: watcher_init failed for target %s\n", target);
    }

    GtkApplication *app = gtk_application_new("org.grit.cybermentor", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(activate), &g_grit_app);

    int status = g_application_run(G_APPLICATION(app), argc, argv);

    watcher_destroy(&g_grit_app.watcher);
    grit_db_close();
    g_object_unref(app);
    return status;
#else
    printf("[Grit] GTK4 headers not present at C compile time.\n"
           "       Launching headless watcher daemon. For GUI, run './run.sh'.\n");
    return run_cli_headless(NULL);
#endif
}
