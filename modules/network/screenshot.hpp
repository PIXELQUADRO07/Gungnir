#ifndef SCREENSHOT_HPP
#define SCREENSHOT_HPP

#include <string>

struct ScreenshotResult {
    std::string target;
    std::string output_path;
    bool success = false;
    std::string error;
};

// Captures a screenshot of the given target URL.
ScreenshotResult capture_screenshot(const std::string& target, const std::string& output_dir = "screenshots");

#endif
