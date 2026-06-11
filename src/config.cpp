#include "config.hpp"
#include <cstdlib>
#include <fstream>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

Config::Config() {
    load_from_file();
    load_from_env(); // Env var ha priorita'
}

std::string Config::get_vt_api_key() const {
    return vt_api_key_;
}

std::string Config::get_shodan_api_key() const {
    return shodan_api_key_;
}

void Config::load_from_env() {
    if (const char* vt = std::getenv("VT_API_KEY")) {
        vt_api_key_ = vt;
    }
    if (const char* shodan = std::getenv("SHODAN_API_KEY")) {
        shodan_api_key_ = shodan;
    }
}

void Config::load_from_file() {
    const char* homedir;
    if ((homedir = std::getenv("HOME")) == nullptr) {
        homedir = getpwuid(getuid())->pw_dir;
    }
    
    if (!homedir) return;
    
    std::string conf_path = std::string(homedir) + "/.gungnir.conf";
    std::ifstream file(conf_path);
    if (!file.is_open()) return;
    
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto pos = line.find('=');
        if (pos != std::string::npos) {
            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 1);
            
            // Trim
            auto trim = [](std::string& s) {
                if (s.empty()) return;
                s.erase(0, s.find_first_not_of(" \t\r\n"));
                s.erase(s.find_last_not_of(" \t\r\n") + 1);
            };
            trim(key);
            trim(value);
            
            if (key == "VT_API_KEY") vt_api_key_ = value;
            else if (key == "SHODAN_API_KEY") shodan_api_key_ = value;
        }
    }
}
