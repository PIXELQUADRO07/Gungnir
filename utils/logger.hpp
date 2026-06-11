#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <string>
#include <mutex>

namespace Logger {
    // Global quiet mode — set to true to suppress all [*] [!] [-] [+] output
    extern bool quiet_mode;

    void print_banner();
    void info   (const std::string& msg);
    void success(const std::string& msg);
    void warn   (const std::string& msg);
    void error  (const std::string& msg);

    // Raw output that always prints regardless of quiet_mode (used for results)
    void result(const std::string& msg);
}

#endif