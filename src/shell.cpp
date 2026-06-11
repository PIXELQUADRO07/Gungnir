#include "shell.hpp"
#include "cli_utils.hpp"
#include "logger.hpp"

#include <iostream>
#include <set>

#ifdef USE_READLINE
  #include <readline/history.h>
  #include <readline/readline.h>
#endif

// ─── Shell ────────────────────────────────────────────────────────────────────

Shell::Shell() {
    // scan
    register_command("scan", /*ports_ok=*/true,
        "scan <target> [-p ports] [-o file]   TCP port scan",
        [this](const std::vector<std::string>& args) -> bool {
            const auto pa = parse_args(args, 1, /*ports_supported=*/true);
            if (pa.target.empty()) {
                Logger::warn("Uso: scan <target> [-p ports] [-o file]");
                return true;
            }
            engine_.execute("scan", pa.target, pa.output_file, pa.ports);
            return true;
        });

    // dns
    register_command("dns", /*ports_ok=*/false,
        "dns  <target> [-o file]              DNS lookup",
        [this](const std::vector<std::string>& args) -> bool {
            const auto pa = parse_args(args, 1, /*ports_supported=*/false);
            if (pa.target.empty()) {
                Logger::warn("Uso: dns <target> [-o file]");
                return true;
            }
            engine_.execute("dns", pa.target, pa.output_file, {});
            return true;
        });

    // whois
    register_command("whois", /*ports_ok=*/false,
        "whois <target> [-o file]             WHOIS lookup",
        [this](const std::vector<std::string>& args) -> bool {
            const auto pa = parse_args(args, 1, /*ports_supported=*/false);
            if (pa.target.empty()) {
                Logger::warn("Uso: whois <target> [-o file]");
                return true;
            }
            engine_.execute("whois", pa.target, pa.output_file, {});
            return true;
        });

    // scrape
    register_command("scrape", /*ports_ok=*/false,
        "scrape <target>                      OSINT scraping",
        [this](const std::vector<std::string>& args) -> bool {
            const auto pa = parse_args(args, 1, /*ports_supported=*/false);
            if (pa.target.empty()) {
                Logger::warn("Uso: scrape <target>");
                return true;
            }
            engine_.execute("scrape", pa.target, {}, {});
            return true;
        });

    // use — set active module; list derived from registered recon commands
    register_command("use", /*ports_ok=*/false,
        "use <modulo>                         Imposta modulo attivo",
        [this](const std::vector<std::string>& args) -> bool {
            if (args.size() < 2) {
                Logger::warn("Uso: use <modulo>  (" + recon_modules_list() + ")");
                return true;
            }
            const std::string& mod = args[1];
            if (recon_modules_.find(mod) == recon_modules_.end()) {
                Logger::warn("Modulo sconosciuto: " + mod +
                             ".  Disponibili: " + recon_modules_list());
                return true;
            }
            current_context_ = mod;
            Logger::info("Modulo attivo: " + mod +
                         ". Digita 'run <target>' per eseguire.");
            return true;
        });

    // run — execute current context
    register_command("run", /*ports_ok=*/true,
        "run <target> [flags]                 Esegui modulo attivo",
        [this](const std::vector<std::string>& args) -> bool {
            if (current_context_.empty()) {
                Logger::warn("Nessun modulo attivo. Usa 'use <modulo>' prima di 'run'.");
                return true;
            }
            const bool ports_ok = recon_modules_.count(current_context_) &&
                                  recon_modules_.at(current_context_);
            const auto pa = parse_args(args, 1, ports_ok);
            if (pa.target.empty()) {
                Logger::warn("Uso: run <target>");
                return true;
            }
            engine_.execute(current_context_, pa.target, pa.output_file, pa.ports);
            return true;
        });

    // banner
    register_command("banner", /*ports_ok=*/false, "banner                               Mostra banner ASCII",
        [](const std::vector<std::string>&) -> bool {
            Logger::print_banner();
            return true;
        });

    // clear
    register_command("clear", /*ports_ok=*/false, "clear                                Pulisci schermo",
        [](const std::vector<std::string>&) -> bool {
            std::cout << "\033[2J\033[H" << std::flush;
            Logger::print_banner();
            return true;
        });

    // version
    register_command("version", /*ports_ok=*/false, "version                              Mostra versione",
        [](const std::vector<std::string>&) -> bool {
            std::cout << GUNGNIR_VERSION << "\n";
            return true;
        });

    // help / ?
    auto help_fn = [this](const std::vector<std::string>&) -> bool {
        show_help();
        return true;
    };
    register_command("help", /*ports_ok=*/false, "help / ?                             Questo messaggio", help_fn);
    register_command("?",    /*ports_ok=*/false, "", help_fn);   // alias, hidden from help

    // exit / quit
    auto exit_fn = [](const std::vector<std::string>&) -> bool { return false; };
    register_command("exit", /*ports_ok=*/false, "exit / quit                          Esci", exit_fn);
    register_command("quit", /*ports_ok=*/false, "", exit_fn);   // alias, hidden
}

// ─── registration helpers ─────────────────────────────────────────────────────

void Shell::register_command(
    const std::string& name,
    bool ports_ok,
    const std::string& help_line,
    CommandFn fn
) {
    commands_[name] = std::move(fn);
    if (!help_line.empty())
        help_lines_.push_back("  " + help_line);

    // track recon modules (those with actual targets)
    const std::set<std::string> recon = {"scan","dns","whois","scrape"};
    if (recon.count(name))
        recon_modules_[name] = ports_ok;
}

std::string Shell::recon_modules_list() const {
    std::string list;
    for (const auto& [name, _] : recon_modules_) {
        if (!list.empty()) list += ", ";
        list += name;
    }
    return list;
}

// ─── dispatch ─────────────────────────────────────────────────────────────────

bool Shell::dispatch(const std::vector<std::string>& tokens) {
    if (tokens.empty()) return true;
    auto it = commands_.find(tokens.front());
    if (it == commands_.end()) {
        Logger::warn("Comando non riconosciuto: '" + tokens.front() +
                     "'. Digita 'help' per la lista.");
        return true;
    }
    return it->second(tokens);
}

// ─── help ─────────────────────────────────────────────────────────────────────

void Shell::show_help() const {
    std::cout << "\n  Comandi disponibili:\n"
                 "  ────────────────────────────────────────────────────────\n";
    for (const auto& line : help_lines_)
        std::cout << line << "\n";
    std::cout << "\n";
}

// ─── prompt ───────────────────────────────────────────────────────────────────

std::string Shell::prompt() const {
    if (current_context_.empty())
        return "Gungnir > ";
    return "gungnir(" + current_context_ + ") > ";
}

// ─── run loop ─────────────────────────────────────────────────────────────────

void Shell::run() {
    Logger::info("Modalità interattiva. Digita 'help' per i comandi.");

#ifdef USE_READLINE
    using_history();
#endif

    while (true) {
        const std::string pr = prompt();
        std::string line;

#ifdef USE_READLINE
        char* raw = readline(pr.c_str());
        if (!raw) { std::cout << "\n"; break; }   // Ctrl+D
        line = raw;
        if (!line.empty()) add_history(raw);
        free(raw);
#else
        std::cout << pr << std::flush;
        if (!std::getline(std::cin, line)) { std::cout << "\n"; break; }
#endif

        // strip leading/trailing whitespace
        const auto b = line.find_first_not_of(" \t\r\n");
        if (b == std::string::npos) continue;
        const auto e = line.find_last_not_of(" \t\r\n");
        line = line.substr(b, e - b + 1);

        if (!dispatch(tokenize(line))) break;
    }

    std::cout << "Arrivederci.\n";
}
