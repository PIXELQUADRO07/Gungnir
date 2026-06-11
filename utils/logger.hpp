#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <string>

namespace Logger {
    void print_banner();
    void info(const std::string& msg);
    void success(const std::string& msg);
    void warn(const std::string& msg);
    void error(const std::string& msg);
}

#endif