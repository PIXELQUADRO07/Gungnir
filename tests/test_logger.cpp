#include <gtest/gtest.h>
#include "logger.hpp"
#include <sstream>

TEST(LoggerTest, QuietModeToggle) {
    Logger::quiet_mode = true;
    EXPECT_TRUE(Logger::quiet_mode);
    Logger::quiet_mode = false;
    EXPECT_FALSE(Logger::quiet_mode);
}

// Note: Logger outputs to std::cout, which is hard to capture without redirecting streambuf.
// We'll just test that it doesn't crash for now.
TEST(LoggerTest, BasicOutput) {
    Logger::info("Test info");
    Logger::success("Test success");
    Logger::warn("Test warn");
    Logger::error("Test error");
}
