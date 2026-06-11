#include "logger.hpp"
#include "cli_utils.hpp"
#include <iostream>
#include <mutex>

// ─── thread-safety ────────────────────────────────────────────────────────────
static std::mutex s_log_mutex;

// ─── global state ─────────────────────────────────────────────────────────────
bool Logger::quiet_mode = false;

// ─── ANSI colours ─────────────────────────────────────────────────────────────
static const char* RESET  = "\033[0m";
static const char* CYAN   = "\033[36m";
static const char* RED    = "\033[31m";
static const char* GREEN  = "\033[32m";
static const char* BLUE   = "\033[34m";

void Logger::print_banner() {
    std::lock_guard<std::mutex> lk(s_log_mutex);
    // banner version is read from GUNGNIR_VERSION (defined in cli_utils.hpp)
    std::cout << R"BANNER(
                                ,-. 
                               ("O_)
                              / `-/
                             /-. /
                            /   )
                           /   /
              _           /-. /
             (_)"-._     /   )
               "-._ "-'""( )/
                   "-/"-._" `.
                    /     "-.'._
                   /\       /-._"-._
    _,---...__    /  ) _,-"/    "-(_)
___<__(|) _   ""-/  / /   /
 '  `----' ""-.   \/ /   /
               )  ] /   /
       ____..-'   //   /                       )
   ,-""      __.,'/   /   ___                 /,
  /    ,--""/  / /   /,-""   """-.          ,'/
 [    (    /  / /   /  ,.---,_   `._   _,-','
  \    `-./  / /   /  /       `-._  """ ,-'
   `-._  /  / /   /_,'            ""--"
       "/  / /   /
       /  / /   /
      /  / /   /  o!O
     /  |,'   /
    :   /    /
    [  /    ,'   ")BANNER"
        << "\"" << GUNGNIR_VERSION << "\"\n"
        << R"BANNER(     `-._  /
     `-._ /
    | / ,'
    |,-'
    P'
)BANNER";
}

void Logger::info(const std::string& msg) {
    if (quiet_mode) return;
    std::lock_guard<std::mutex> lk(s_log_mutex);
    std::cout << "[" << BLUE << "*" << RESET << "] " << msg << "\n";
}

void Logger::success(const std::string& msg) {
    if (quiet_mode) return;
    std::lock_guard<std::mutex> lk(s_log_mutex);
    std::cout << "[" << GREEN << "+" << RESET << "] " << msg << "\n";
}

void Logger::warn(const std::string& msg) {
    if (quiet_mode) return;
    std::lock_guard<std::mutex> lk(s_log_mutex);
    std::cout << "[" << CYAN << "!" << RESET << "] " << msg << "\n";
}

void Logger::error(const std::string& msg) {
    // errors always print, even in quiet mode
    std::lock_guard<std::mutex> lk(s_log_mutex);
    std::cerr << "[" << RED << "-" << RESET << "] " << msg << "\n";
}

void Logger::result(const std::string& msg) {
    // result always prints (used for final data output, piping, scripting)
    std::lock_guard<std::mutex> lk(s_log_mutex);
    std::cout << msg << "\n";
}
