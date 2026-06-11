#include "logger.hpp"
#include <iostream>


const std::string RESET   = "\033[0m";
const std::string CYAN    = "\033[36m";
const std::string RED     = "\033[31m";
const std::string GREEN   = "\033[32m";
const std::string BLUE    = "\033[34m";
const std::string GRAY    = "\033[90m";

void Logger::print_banner() {
    const std::string spear = R"GNRSPEAR(
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
    [  /    ,'   "GUNGNIR V1.0"
     `-._  /
     `-._ /
    | / ,'
    |,-'
    P'
)GNRSPEAR";


    std::cout << spear << std::endl;
}

void Logger::info(const std::string& msg) {
    std::cout << "[" << BLUE << "*" << RESET << "] " << msg << std::endl;
}

void Logger::success(const std::string& msg) {
    std::cout << "[" << GREEN << "+" << RESET << "] " << msg << std::endl;
}

void Logger::warn(const std::string& msg) {
    std::cout << "[" << CYAN << "!" << RESET << "] " << msg << std::endl;
}

void Logger::error(const std::string& msg) {
    std::cerr << "[" << RED << "-" << RESET << "] Error: " << msg << std::endl;
}
