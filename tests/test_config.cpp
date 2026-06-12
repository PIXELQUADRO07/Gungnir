#include <gtest/gtest.h>
#include "config.hpp"

TEST(ConfigTest, SingletonAccess) {
    Config& cfg = Config::instance();
    // Default might be empty, but should be accessible
    std::string vt = cfg.get_vt_api_key();
    std::string shodan = cfg.get_shodan_api_key();
    SUCCEED();
}
