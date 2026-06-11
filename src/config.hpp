#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <string>

class Config {
public:
    static Config& instance() {
        static Config instance;
        return instance;
    }

    std::string get_vt_api_key() const;
    std::string get_shodan_api_key() const;

private:
    Config(); // Private constructor per Singleton
    
    std::string vt_api_key_;
    std::string shodan_api_key_;

    void load_from_env();
    void load_from_file();
};

#endif
