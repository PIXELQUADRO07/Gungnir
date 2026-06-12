#include <algorithm>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include "cli_utils.hpp"
#include "config.hpp"
#include "engine.hpp"
#include "logger.hpp"
#include "shell.hpp"
#include "updater.hpp"

// ─── usage ────────────────────────────────────────────────────────────────────

static void show_usage() {
    std::cout <<
        "\n"
        "  " << GUNGNIR_VERSION << "\n"
        "\n"
        "  Usage:\n"
        "    ./Gungnir                            Launch interactive shell\n"
        "    ./Gungnir <command> <target> [flags] Run a single command\n"
        "\n"
        "  Commands:\n"
        "    scan     <target> [-p ports] [-o file]\n"
        "    dns      <target> [-o file]\n"
        "    whois    <target> [-o file]\n"
        "    scrape   <target>\n"
        "    campaign <target> [-p ports]\n"
        "    threat   <target>\n"
        "    history  [target]\n"
        "    graph    [-o file]\n"
        "    nmap     <target> [-p ports] [-o file]\n"
        "    searchsploit <query> [-o file]\n"
        "    takeover <target>\n"
        "    fuzz     <target>\n"
        "    s3       <target>\n"
        "    breach   <email>\n"
        "\n"
        "  Flags:\n"
        "    -p <ports>       Comma-separated TCP ports (e.g. 22,80,443)\n"
        "    -o <file>        Export result to JSON file\n"
        "    -q, --quiet      Suppress banner and info output (for scripting)\n"
        "    -n, --no-update  Skip update check at startup\n"
        "    -v, --version    Show version and exit\n"
        "    -h, --help       Show this help and exit\n"
        "\n"
        "  Examples:\n"
        "    ./Gungnir scan   example.com\n"
        "    ./Gungnir scan   example.com -p 22,80,443 -o result.json\n"
        "    ./Gungnir dns    example.com\n"
        "    ./Gungnir whois  example.com -o whois.json\n"
        "    ./Gungnir scrape example.com\n"
        "    ./Gungnir campaign example.com -p 80,443\n"
        "    ./Gungnir threat example.com\n"
        "    ./Gungnir history\n"
        "    ./Gungnir history example.com\n"
        "    ./Gungnir graph -o out.json\n"
        "\n"
        "  Config (~/.gungnir.conf):\n"
        "    VT_API_KEY     = <virustotal_key>\n"
        "    SHODAN_API_KEY = <shodan_key>\n"
        "\n"
        "  Legacy flag style (still supported):\n"
        "    ./Gungnir -t example.com -m scan -p 22,80,443\n"
        "\n";
}

// ─── subcommand table ─────────────────────────────────────────────────────────

struct CmdInfo {
    bool ports_ok;
    bool needs_target;
};

static const std::map<std::string, CmdInfo> COMMANDS = {
    {"scan",     {true,  true }},
    {"dns",      {false, true }},
    {"whois",    {false, true }},
    {"scrape",   {false, true }},
    {"campaign", {true,  true }},
    {"threat",   {false, true }},
    {"history",  {false, false}},   // target optional
    {"graph",    {false, false}},   // target unused
    {"nmap",     {true,  true }},
    {"searchsploit", {false, true }},
    {"takeover", {false, true }},
    {"fuzz",     {false, true }},
    {"s3",       {false, true }},
    {"breach",   {false, true }},
};

// ─── legacy flag parsing ──────────────────────────────────────────────────────

struct LegacyArgs {
    std::string      mode, target, output_file;
    std::vector<int> ports;
    bool             valid = false;
};

static LegacyArgs parse_legacy(int argc, char* argv[]) {
    LegacyArgs la;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if      (a == "-m" && i+1<argc) la.mode        = argv[++i];
        else if (a == "-t" && i+1<argc) la.target      = argv[++i];
        else if (a == "-o" && i+1<argc) la.output_file = argv[++i];
        else if (a == "-p" && i+1<argc) la.ports       = parse_ports(argv[++i]);
        else Logger::warn("Unknown flag: " + a + ". Use -h for help.");
    }
    la.valid = !la.mode.empty() && !la.target.empty();
    return la;
}

// ─── main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    // Pre-scan for global modifiers before printing anything
    bool no_update = false;
    bool quiet     = false;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "-n" || a == "--no-update") no_update = true;
        if (a == "-q" || a == "--quiet")     quiet     = true;
    }
    Logger::quiet_mode = quiet;

    if (!quiet) Logger::print_banner();
    if (!quiet && !no_update) Updater::check();

    // Inform user about API key status once at startup
    if (!quiet) {
        const Config& cfg = Config::instance();
        if (cfg.get_vt_api_key().empty() && cfg.get_shodan_api_key().empty())
            Logger::info("Threat Intel: no API keys configured — "
                         "add VT_API_KEY / SHODAN_API_KEY to ~/.gungnir.conf");
    }

    // No arguments → interactive shell
    if (argc == 1) {
        Shell shell;
        shell.run();
        return 0;
    }

    const std::string first = argv[1];

    // ── global flags ──────────────────────────────────────────────────────────
    if (first == "-h" || first == "--help")    { show_usage(); return 0; }
    if (first == "-v" || first == "--version") {
        std::cout << GUNGNIR_VERSION << "\n";
        return 0;
    }
    if (first == "-i" || first == "--interactive") {
        Shell shell;
        shell.run();
        return 0;
    }
    // -q / -n already consumed above; skip them as first arg
    if (first == "-q" || first == "--quiet" ||
        first == "-n" || first == "--no-update") {
        // If that was the only arg, launch the shell
        if (argc == 2) { Shell shell; shell.run(); return 0; }
        // Otherwise fall through — the real command follows
    }

    // ── subcommand style: ./Gungnir scan example.com [...] ────────────────────
    auto cmd_it = COMMANDS.find(first);
    if (cmd_it != COMMANDS.end()) {
        const CmdInfo& ci = cmd_it->second;

        // Build token list from argv[2..] and reuse parse_args
        std::vector<std::string> tokens;
        for (int i = 2; i < argc; ++i) tokens.emplace_back(argv[i]);
        const ParsedArgs pa = parse_args(tokens, 0, ci.ports_ok);

        if (ci.needs_target && pa.targets.empty()) {
            Logger::error("Target required.  Usage: ./Gungnir " + first + " <target>");
            return 1;
        }

        Engine engine;
        // For commands without a target (history, graph) pa.targets is empty —
        // engine executors handle that cleanly.
        return engine.execute(first, pa.targets, pa.output_file, pa.ports) ? 0 : 1;
    }

    // ── legacy flag style: ./Gungnir -t example.com -m scan [...] ─────────────
    if (!first.empty() && first[0] == '-') {
        const LegacyArgs la = parse_legacy(argc, argv);
        if (!la.valid) { show_usage(); return 1; }
        Engine engine;
        return engine.execute(la.mode, parse_targets(la.target), la.output_file, la.ports) ? 0 : 1;
    }

    // ── nothing matched ───────────────────────────────────────────────────────
    Logger::error("Unknown command: '" + first + "'. Use -h for help.");
    return 1;
}
