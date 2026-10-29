#!/usr/bin/env bash
# ==============================================================================
# Grit Application Runner & Build Script
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

BUILD_DIR="${SCRIPT_DIR}/build"
BIN_NAME="grit"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${BLUE}${BOLD}================================================================${NC}"
    echo -e "${BLUE}${BOLD}   🛡️  Grit - Offline Cybersecurity Mentor & Native Linux Watcher  ${NC}"
    echo -e "${BLUE}${BOLD}================================================================${NC}"
}

setup_local_links() {
    mkdir -p lib include
    if [ -f "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0" ] && [ ! -f "lib/libsqlite3.so" ]; then
        ln -sf /usr/lib/x86_64-linux-gnu/libsqlite3.so.0 lib/libsqlite3.so
    fi
    if [ -f "/usr/lib/x86_64-linux-gnu/libcurl.so.4" ] && [ ! -f "lib/libcurl.so" ]; then
        ln -sf /usr/lib/x86_64-linux-gnu/libcurl.so.4 lib/libcurl.so
    fi
}

check_dependencies() {
    local missing=()

    if ! command -v gcc &>/dev/null && ! command -v clang &>/dev/null; then
        missing+=("build-essential (gcc / clang)")
    fi

    if ! command -v pkg-config &>/dev/null && ! command -v pkgconf &>/dev/null; then
        missing+=("pkg-config")
    fi

    if command -v pkg-config &>/dev/null; then
        if ! pkg-config --exists gtk4 2>/dev/null; then
            missing+=("libgtk-4-dev")
        fi
        if ! pkg-config --exists sqlite3 2>/dev/null; then
            missing+=("libsqlite3-dev")
        fi
        if ! pkg-config --exists libcurl 2>/dev/null; then
            missing+=("libcurl4-openssl-dev")
        fi
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        return 1
    fi
    return 0
}

build_libgrit_shared() {
    setup_local_links
    echo -e "${BLUE}[*] Compiling C23 shared library (libgrit.so)...${NC}"
    local CC="gcc"
    if ! command -v gcc &>/dev/null && command -v clang &>/dev/null; then
        CC="clang"
    fi
    "${CC}" -std=c23 -shared -fPIC -Wall -Wextra -Wpedantic -pthread \
        -Isrc -Iinclude -Llib \
        src/core/watcher.c \
        src/core/simulator.c \
        src/mentor/command_guard.c \
        src/mentor/llm_client.c \
        src/db/db.c \
        -lsqlite3 -lcurl \
        -o libgrit.so
    echo -e "${GREEN}[✓] libgrit.so compiled successfully.${NC}"
}

run_test_suite() {
    setup_local_links
    mkdir -p "${BUILD_DIR}"
    
    local CC="gcc"
    if ! command -v gcc &>/dev/null && command -v clang &>/dev/null; then
        CC="clang"
    fi

    echo -e "${BLUE}[*] Compiling end-to-end architecture pipeline test...${NC}"
    "${CC}" -std=c23 -Wall -Wextra -Wpedantic -pthread \
        -Isrc -Iinclude -Llib \
        tests/test_full_pipeline.c \
        src/core/watcher.c \
        src/core/simulator.c \
        src/mentor/command_guard.c \
        src/mentor/llm_client.c \
        src/db/db.c \
        -lsqlite3 -lcurl \
        -o "${BUILD_DIR}/grit_pipeline_test"

    echo -e "${GREEN}[✓] Binary built: ${BUILD_DIR}/grit_pipeline_test${NC}"
    echo ""
    "${BUILD_DIR}/grit_pipeline_test"

    echo ""
    echo -e "${BLUE}[*] Compiling core watcher & redaction test...${NC}"
    "${CC}" -std=c23 -Wall -Wextra -Wpedantic -pthread \
        -Isrc -Iinclude -Llib \
        tests/test_watcher_guard.c \
        src/core/watcher.c \
        src/mentor/command_guard.c \
        src/db/db.c \
        -lsqlite3 \
        -o "${BUILD_DIR}/grit_test"
    "${BUILD_DIR}/grit_test"

    echo ""
    echo -e "${BLUE}[*] Compiling Ollama LLM client test...${NC}"
    "${CC}" -std=c23 -Wall -Wextra -Wpedantic -pthread \
        -Isrc -Iinclude -Llib \
        tests/test_llm_client.c \
        src/mentor/llm_client.c \
        src/mentor/command_guard.c \
        src/db/db.c \
        -lsqlite3 -lcurl \
        -o "${BUILD_DIR}/grit_llm_test"
    "${BUILD_DIR}/grit_llm_test"

    echo ""
    echo -e "${BLUE}[*] Executing Python GUI Logic & C Engine Verification Suite...${NC}"
    build_libgrit_shared
    python3 tests/test_gui_logic.py
}

build_and_run_gui() {
    mkdir -p "${BUILD_DIR}"
    build_libgrit_shared

    local mode="${1:-agent}"

    if [ "$mode" = "cgui" ]; then
        if check_dependencies; then
            echo -e "${BLUE}[*] Building Grit GTK4 desktop binary from C sources...${NC}"
            local CC="gcc"
            if ! command -v gcc &>/dev/null && command -v clang &>/dev/null; then
                CC="clang"
            fi
            local CFLAGS="$(pkg-config --cflags gtk4 sqlite3 libcurl 2>/dev/null || echo '-Isrc -Iinclude')"
            local LIBS="$(pkg-config --libs gtk4 sqlite3 libcurl 2>/dev/null || echo '-Llib -lsqlite3 -lcurl')"

            "${CC}" -std=c23 -O2 -Wall -Wextra -pthread \
                ${CFLAGS} \
                -Isrc -Iinclude -Llib \
                src/main.c \
                src/core/watcher.c \
                src/core/simulator.c \
                src/mentor/command_guard.c \
                src/mentor/llm_client.c \
                src/db/db.c \
                ${LIBS} \
                -o "${BUILD_DIR}/${BIN_NAME}"

            echo -e "${GREEN}[✓] Build successful: ${BUILD_DIR}/${BIN_NAME}${NC}"
            echo -e "${BLUE}[*] Launching Grit C GTK4 GUI...${NC}"
            echo ""
            exec "${BUILD_DIR}/${BIN_NAME}" "${@:2}"
        else
            echo -e "${YELLOW}[!] Missing GTK4 C development packages (libgtk-4-dev).${NC}"
            echo -e "${BLUE}[*] Launching Grit Socratic Mentor Agent desktop application instead...${NC}"
            echo ""
            exec python3 src/gui/mentor_agent_app.py "${@:2}"
        fi
    elif [ "$mode" = "triage" ]; then
        echo -e "${BLUE}[*] Launching Grit Incident Triage & Tabbed Monitor GUI (app.py)...${NC}"
        echo ""
        exec python3 src/gui/app.py "${@:2}"
    else
        echo -e "${BLUE}[*] Launching Grit Modern GNOME HIG Workstation GUI (app.py)...${NC}"
        echo ""
        exec python3 src/gui/app.py "${@:2}"
    fi
}

run_simulate() {
    setup_local_links
    mkdir -p "${BUILD_DIR}"
    local CC="gcc"
    if ! command -v gcc &>/dev/null && command -v clang &>/dev/null; then
        CC="clang"
    fi
    "${CC}" -std=c23 -O2 -Wall -Wextra -pthread \
        -Isrc -Iinclude -Llib \
        src/main.c \
        src/core/watcher.c \
        src/core/simulator.c \
        src/mentor/command_guard.c \
        src/mentor/llm_client.c \
        src/db/db.c \
        -lsqlite3 -lcurl \
        -o "${BUILD_DIR}/grit_cli"

    local scenario="${1:-ssh_brute}"
    "${BUILD_DIR}/grit_cli" --simulate "${scenario}"
}

run_headless() {
    setup_local_links
    mkdir -p "${BUILD_DIR}"
    local CC="gcc"
    if ! command -v gcc &>/dev/null && command -v clang &>/dev/null; then
        CC="clang"
    fi
    "${CC}" -std=c23 -O2 -Wall -Wextra -pthread \
        -Isrc -Iinclude -Llib \
        src/main.c \
        src/core/watcher.c \
        src/core/simulator.c \
        src/mentor/command_guard.c \
        src/mentor/llm_client.c \
        src/db/db.c \
        -lsqlite3 -lcurl \
        -o "${BUILD_DIR}/${BIN_NAME}_headless"

    echo -e "${GREEN}[✓] Headless daemon built.${NC}"
    exec "${BUILD_DIR}/${BIN_NAME}_headless" --headless "${@:1}"
}

clean_build() {
    echo -e "${YELLOW}[*] Cleaning build artifacts...${NC}"
    rm -rf "${BUILD_DIR}" libgrit.so /tmp/grit_*.log /tmp/grit_*.sqlite
    echo -e "${GREEN}[✓] Clean completed.${NC}"
}

# ------------------------------------------------------------------------------
# Entrypoint
# ------------------------------------------------------------------------------
print_banner

case "${1:-run}" in
    run|"")
        build_and_run_gui "agent" "${@:2}"
        ;;
    agent|--agent)
        build_and_run_gui "agent" "${@:2}"
        ;;
    triage|--triage)
        build_and_run_gui "triage" "${@:2}"
        ;;
    cgui|--cgui)
        build_and_run_gui "cgui" "${@:2}"
        ;;
    simulate|--simulate)
        run_simulate "${2:-ssh_brute}"
        ;;
    headless|--headless)
        run_headless "${@:2}"
        ;;
    test|--test)
        run_test_suite
        ;;
    clean|--clean)
        clean_build
        ;;
    help|--help|-h)
        echo -e "Usage: ./run.sh [command]"
        echo ""
        echo "Commands:"
        echo "  run, agent (default) Launch Grit Socratic Mentor Agent & Log Monitor GUI"
        echo "  triage               Launch classic Incident Triage & Tabbed Monitor GUI"
        echo "  cgui                 Build & run native GTK4 C binary (build/grit)"
        echo "  --simulate <scen>    Inject attack scenario (ssh_brute | sudo_abuse | redaction_test)"
        echo "  --headless [log]     Run headless log monitor daemon without GUI"
        echo "  test, --test         Build and execute complete C23 verification test suite"
        echo "  clean, --clean       Remove build directory and compiled binaries"
        echo "  help, -h             Display this help message"
        ;;
    *)
        echo -e "${RED}[ERROR] Unknown option: $1${NC}"
        echo "Run './run.sh --help' for available commands."
        exit 1
        ;;
esac
