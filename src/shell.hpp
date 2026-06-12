#pragma once

#include <functional>
#include <map>
#include <string>
#include <vector>
#include "engine.hpp"
#include "cli_utils.hpp"

class Shell {
public:
    Shell();
    void run();

private:
    using CommandFn = std::function<bool(const std::vector<std::string>&)>;

    void register_command(
        const std::string& name,
        bool ports_ok,
        const std::string& help_line,
        CommandFn fn
    );

    bool dispatch(const std::vector<std::string>& tokens);
    void show_help() const;
    std::string prompt() const;
    std::string recon_modules_list() const;

    Engine engine_;
    std::map<std::string, CommandFn> commands_;
    std::map<std::string, bool> recon_modules_;   // name → ports_supported
    std::vector<std::string> help_lines_;          // ordered, for display
    std::string current_context_;
    std::string current_workspace_;
};
