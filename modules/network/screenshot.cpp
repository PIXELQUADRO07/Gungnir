#include "screenshot.hpp"
#include "logger.hpp"
#include <iostream>
#include <array>
#include <cstdio>
#include <sys/stat.h>
#include <algorithm>
#include <vector>

namespace {
    std::string run_command(const std::string& cmd) {
        std::string output;
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) return {};
        std::array<char, 4096> buf;
        while (fgets(buf.data(), buf.size(), pipe))
            output += buf.data();
        pclose(pipe);
        return output;
    }

    std::string find_browser() {
        const std::vector<std::string> browsers = {"chromium", "google-chrome", "chromium-browser"};
        for (const auto& b : browsers) {
            std::string path = run_command("which " + b + " 2>/dev/null");
            if (!path.empty()) {
                // trim
                path.erase(std::remove(path.begin(), path.end(), '\n'), path.end());
                path.erase(std::remove(path.begin(), path.end(), '\r'), path.end());
                return path;
            }
        }
        return "";
    }
}

ScreenshotResult capture_screenshot(const std::string& target, const std::string& output_dir) {
    ScreenshotResult result;
    result.target = target;

    std::string browser_path = find_browser();
    if (browser_path.empty()) {
        result.error = "No headless browser found (chromium or google-chrome). Install it with: sudo apt install chromium-browser";
        return result;
    }

    // Create output directory
    mkdir(output_dir.c_str(), 0755);

    std::string filename = target;
    std::replace(filename.begin(), filename.end(), ':', '_');
    std::replace(filename.begin(), filename.end(), '/', '_');
    std::replace(filename.begin(), filename.end(), '.', '_');
    result.output_path = output_dir + "/" + filename + ".png";

    std::string url = target;
    if (url.find("http") != 0) url = "http://" + url;

    // Command for headless screenshot
    std::string cmd = browser_path + " --headless --disable-gpu --screenshot=\"" + result.output_path + "\" --window-size=1280,800 \"" + url + "\" 2>/dev/null";
    
    Logger::info("Capturing screenshot of " + url + "...");
    run_command(cmd);

    struct stat buffer;
    if (stat(result.output_path.c_str(), &buffer) == 0) {
        result.success = true;
    } else {
        result.error = "Screenshot failed (browser exit code non-zero or file not created).";
    }

    return result;
}
