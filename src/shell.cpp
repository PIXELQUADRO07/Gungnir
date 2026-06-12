#include "shell.hpp"
#include "cli_utils.hpp"
#include "logger.hpp"

#include <iostream>
#include <set>
#include <dirent.h>

#ifdef USE_READLINE
  #include <readline/history.h>
  #include <readline/readline.h>
#endif

// ─── Shell ────────────────────────────────────────────────────────────────────

Shell::Shell() {
    current_workspace_ = "default";

    // shell-only commands
    register_command("workspace", /*ports_ok=*/false,
        "workspace <list|create|load> [name]  Gestione workspace",
        [this](const std::vector<std::string>& args) -> bool {
            if (args.size() < 2) {
                Logger::warn("Usage: workspace <list|create|load> [name]");
                return true;
            }
            std::string sub = args[1];
            if (sub == "list") {
                std::string path = get_gungnir_data_dir() + "/workspaces";
                Logger::info("Workspace disponibili:");
                std::cout << "  - default (implicito)\n";
                DIR* dir = opendir(path.c_str());
                if (dir) {
                    struct dirent* ent;
                    while ((ent = readdir(dir)) != NULL) {
                        if (ent->d_type == DT_DIR) {
                            std::string name = ent->d_name;
                            if (name != "." && name != "..")
                                std::cout << "  - " << name << "\n";
                        }
                    }
                    closedir(dir);
                }
            } else if (sub == "create" && args.size() > 2) {
                engine_.set_workspace(Workspace::create(args[2]));
                current_workspace_ = args[2];
                Logger::success("Workspace creato e caricato: " + current_workspace_);
            } else if (sub == "load" && args.size() > 2) {
                auto ws = Workspace::load(args[2]);
                if (ws) {
                    engine_.set_workspace(std::move(ws));
                    current_workspace_ = args[2];
                    Logger::success("Workspace caricato: " + current_workspace_);
                }
            } else {
                Logger::warn("Utilizzo: workspace <list|create|load> [name]");
            }
            return true;
        });

    // Auto-register engine modules
    for (Module* m : engine_.registry().all()) {
        std::string name = m->name();
        std::string help = m->help();
        bool ports = m->supports_ports();

        // Padding per allineamento help
        std::string padded_name = name;
        if (padded_name.size() < 12) padded_name.append(12 - padded_name.size(), ' ');

        register_command(name, ports,
            padded_name + "<target> ... " + help,
            [this, name, ports](const std::vector<std::string>& args) -> bool {
                const auto pa = parse_args(args, 1, ports);
                if (pa.targets.empty() && name != "history" && name != "graph") {
                    Logger::warn("Usage: " + name + " <target> [flags]");
                    return true;
                }
                engine_.execute(name, pa.targets, pa.output_file, pa.ports);
                return true;
            });
    }

    // use — set active module
    register_command("use", /*ports_ok=*/false,
        "use         <module>                 Set active module",
        [this](const std::vector<std::string>& args) -> bool {
            if (args.size() < 2) {
                Logger::warn("Usage: use <module>  (" + recon_modules_list() + ")");
                return true;
            }
            const std::string& mod = args[1];
            if (recon_modules_.find(mod) == recon_modules_.end()) {
                Logger::warn("Unknown module: " + mod +
                             ".  Available: " + recon_modules_list());
                return true;
            }
            current_context_ = mod;
            Logger::info("Active module: " + mod +
                         ". Type 'run <target>' to execute.");
            return true;
        });

    // run — execute current context
    register_command("run", /*ports_ok=*/true,
        "run <target> [flags]                 Execute active module",
        [this](const std::vector<std::string>& args) -> bool {
            if (current_context_.empty()) {
                Logger::warn("No active module. Use 'use <module>' before 'run'.");
                return true;
            }
            const bool ports_ok = recon_modules_.count(current_context_) &&
                                  recon_modules_.at(current_context_);
            const auto pa = parse_args(args, 1, ports_ok);
            if (pa.targets.empty()) {
                Logger::warn("Usage: run <target>");
                return true;
            }
            engine_.execute(current_context_, pa.targets, pa.output_file, pa.ports);
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
    // Se il comando esiste nel registry dell'engine, lo consideriamo un modulo recon
    if (engine_.registry().find(name))
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
        Logger::warn("Unknown command: '" + tokens.front() +
                     "'. Type 'help' for the list.");
        return true;
    }
    return it->second(tokens);
}

// ─── help ─────────────────────────────────────────────────────────────────────

void Shell::show_help() const {
    std::cout << "\n  Available commands:\n"
                 "  ────────────────────────────────────────────────────────\n";
    for (const auto& line : help_lines_)
        std::cout << line << "\n";
    std::cout << "\n";
}

// ─── prompt ───────────────────────────────────────────────────────────────────

std::string Shell::prompt() const {
    std::string p = "gungnir";
    if (current_workspace_ != "default") {
        p += ":" + current_workspace_;
    }
    if (!current_context_.empty()) {
        p += "(" + current_context_ + ")";
    }
    return p + " > ";
}

// ─── run loop ─────────────────────────────────────────────────────────────────

void Shell::run() {
    Logger::info("Interactive shell. Type 'help' for available commands.");

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

    std::cout << "Goodbye.\n";
}
