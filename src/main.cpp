#include <algorithm>
#include <iostream>
#include <string>
#include <vector>
#include "cli_utils.hpp"
#include "updater.hpp"
#include "engine.hpp"
#include "shell.hpp"
#include "config.hpp"
#include "logger.hpp"

// ─── usage ────────────────────────────────────────────────────────────────────

static void show_usage() {
    std::cout <<
        "\n"
        "  " << GUNGNIR_VERSION << "\n"
        "\n"
        "  Utilizzo:\n"
        "    ./Gungnir                          Avvia shell interattiva\n"
        "    ./Gungnir <comando> <target> [..]  Esegui direttamente\n"
        "  Comandi:\n"
        "    scan     <target> [-p ports] [-o file]\n"
        "    dns      <target> [-o file]\n"
        "    whois    <target> [-o file]\n"
        "    scrape   <target>\n"
        "    campaign <target> [-p ports]\n"
        "    threat   <target>\n"
        "    history  [target]\n"
        "    graph    [-o output.json]\n"
        "\n"
        "  Flag:\n"
        "    -p <ports>     Porte TCP separate da virgola (es. 22,80,443)\n"
        "    -o <file>      Esporta risultato in JSON\n"
        "    -n, --no-update  Disabilita il controllo aggiornamenti\n"
        "    -v, --version\n"
        "    -h, --help\n"
        "\n"
        "  Esempi:\n"
        "    ./Gungnir scan   example.com\n"
        "    ./Gungnir scan   example.com -p 22,80,443 -o result.json\n"
        "    ./Gungnir dns    example.com\n"
        "    ./Gungnir whois  example.com -o whois.json\n"
        "    ./Gungnir scrape user123\n"
        "    ./Gungnir campaign example.com -p 80,443\n"
        "    ./Gungnir threat example.com\n"
        "    ./Gungnir history\n"
        "    ./Gungnir graph -o out.json\n"
        "\n"
        "  Config (~/.gungnir.conf):\n"
        "    VT_API_KEY      = <chiave_virustotal>\n"
        "    SHODAN_API_KEY  = <chiave_shodan>\n"
        "\n"
        "  Stile legacy (ancora supportato):\n"
        "    ./Gungnir -t example.com -m scan -p 22,80,443\n"
        "\n";
}

// ─── subcommand parsing ───────────────────────────────────────────────────────
// Converts argv[2..] into a token vector and reuses parse_args from cli_utils.

static ParsedArgs parse_subcommand(int argc, char* argv[], bool ports_ok) {
    // rebuild as tokens starting from argv[2] (argv[1] is the command name)
    std::vector<std::string> tokens;
    for (int i = 2; i < argc; ++i)
        tokens.emplace_back(argv[i]);
    return parse_args(tokens, 0, ports_ok);
}

// ─── legacy flag parsing (-t / -m / -p / -o) ─────────────────────────────────

struct LegacyArgs {
    std::string mode, target, output_file;
    std::vector<int> ports;
    bool valid = false;
};

static LegacyArgs parse_legacy(int argc, char* argv[]) {
    LegacyArgs la;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if      (a == "-m" && i+1<argc) { la.mode        = argv[++i]; }
        else if (a == "-t" && i+1<argc) { la.target      = argv[++i]; }
        else if (a == "-o" && i+1<argc) { la.output_file = argv[++i]; }
        else if (a == "-p" && i+1<argc) { la.ports       = parse_ports(argv[++i]); }
        else {
            Logger::warn("Flag non riconosciuta: " + a +
                         ". Usa -h per la lista dei comandi.");
        }
    }
    la.valid = !la.mode.empty() && !la.target.empty();
    return la;
}

// ─── main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    // Pre-check for --no-update before everything else
    bool no_update = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-n" || a == "--no-update") { no_update = true; break; }
    }

    Logger::print_banner();

    if (!no_update) Updater::check();

    // Config banner — inform user about API key status
    const Config& cfg = Config::instance();
    if (cfg.get_vt_api_key().empty() && cfg.get_shodan_api_key().empty()) {
        Logger::info("Threat Intel: nessuna API key — aggiungi VT_API_KEY / SHODAN_API_KEY a ~/.gungnir.conf");
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
    if (first == "-n" || first == "--no-update") {
        // already handled; fall through to next arg
    }
    if (first == "-v" || first == "--version") {
        std::cout << GUNGNIR_VERSION << "\n";
        return 0;
    }
    if (first == "-i" || first == "--interactive") {
        Shell shell;
        shell.run();
        return 0;
    }

    // ── subcommand style:  ./Gungnir scan example.com [...] ───────────────────
    struct CmdInfo { bool ports_ok; };
    const std::map<std::string, CmdInfo> known_commands = {
        {"scan",     {true }},
        {"dns",      {false}},
        {"whois",    {false}},
        {"scrape",   {false}},
        {"campaign", {true }},
        {"threat",   {false}},
        {"history",  {false}},
        {"graph",    {false}},
    };

    auto cmd_it = known_commands.find(first);
    if (cmd_it != known_commands.end()) {
        const ParsedArgs pa = parse_subcommand(argc, argv, cmd_it->second.ports_ok);
        bool needs_target = (first != "graph" && first != "history");
        if (needs_target && pa.target.empty()) {
            Logger::error("Target mancante.  Uso: ./Gungnir " + first + " <target>");
            return 1;
        }
        Engine engine;
        std::string t = pa.target.empty() ? "dummy" : pa.target;
        return engine.execute(first, t, pa.output_file, pa.ports) ? 0 : 1;
    }

    // ── legacy flag style: ./Gungnir -t example.com -m scan [...] ─────────────
    if (first[0] == '-') {
        const LegacyArgs la = parse_legacy(argc, argv);
        if (!la.valid) {
            show_usage();
            return 1;
        }
        Engine engine;
        return engine.execute(la.mode, la.target, la.output_file, la.ports) ? 0 : 1;
    }

    // ── nothing matched ───────────────────────────────────────────────────────
    Logger::error("Comando non riconosciuto: '" + first + "'.");
    show_usage();
    return 1;
}
