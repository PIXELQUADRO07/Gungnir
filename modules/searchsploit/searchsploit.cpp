#include "searchsploit.hpp"
#include "logger.hpp"
#include "../../vendor/json.hpp"

#include <array>
#include <cstdio>
#include <sstream>
#include <algorithm>

using json = nlohmann::json;

// ─── subprocess helper ────────────────────────────────────────────────────────

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

std::string trim(const std::string& s) {
    const auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    return s.substr(b, s.find_last_not_of(" \t\r\n") - b + 1);
}

// Derives type and platform from the exploit path.
// exploitdb paths look like: exploits/<platform>/<type>/1234.py
// or:                         shellcodes/<platform>/...
void classify_from_path(const std::string& path, std::string& type, std::string& platform) {
    // Split by '/'
    std::vector<std::string> parts;
    std::istringstream ss(path);
    std::string part;
    while (std::getline(ss, part, '/'))
        if (!part.empty()) parts.push_back(part);

    // exploits/<platform>/<type>/file
    if (parts.size() >= 3 && parts[0] == "exploits") {
        platform = parts[1];
        type     = parts[2];
    } else if (parts.size() >= 2 && parts[0] == "shellcodes") {
        platform = parts[1];
        type     = "shellcode";
    } else {
        platform = "unknown";
        type     = "unknown";
    }
}

} // namespace

// ─── public API ───────────────────────────────────────────────────────────────

std::string searchsploit_find() {
    std::string out = run_command("which searchsploit 2>/dev/null");
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r'))
        out.pop_back();
    return out;
}

SearchsploitResult searchsploit_query(const std::string& query, bool exact) {
    SearchsploitResult result;
    result.query = query;

    const std::string bin = searchsploit_find();
    if (bin.empty()) {
        result.error = "searchsploit not found. Install exploitdb: sudo apt install exploitdb";
        return result;
    }

    // Use --json for reliable machine-readable output
    std::string cmd = bin + " --json";
    if (exact) cmd += " --exact";
    cmd += " " + query + " 2>/dev/null";

    Logger::info("Running: " + cmd);
    const std::string raw = run_command(cmd);

    if (raw.empty()) {
        result.error = "searchsploit produced no output.";
        return result;
    }

    // Parse JSON response
    // Format: { "RESULTS_EXPLOIT": [ { "Title": "...", "Path": "..." }, ... ],
    //           "RESULTS_SHELLCODE": [ ... ] }
    try {
        json j = json::parse(raw);

        auto parse_entries = [&](const std::string& key) {
            if (!j.contains(key) || !j[key].is_array()) return;
            for (const auto& entry : j[key]) {
                Exploit ex;
                ex.title = entry.value("Title", "");
                ex.path  = entry.value("Path",  "");

                // Strip leading exploitdb base path if present
                // e.g. "/usr/share/exploitdb/exploits/..." → "exploits/..."
                const std::string prefix = "/usr/share/exploitdb/";
                if (ex.path.rfind(prefix, 0) == 0)
                    ex.path = ex.path.substr(prefix.size());

                classify_from_path(ex.path, ex.type, ex.platform);

                if (!ex.title.empty())
                    result.exploits.push_back(std::move(ex));
            }
        };

        parse_entries("RESULTS_EXPLOIT");
        parse_entries("RESULTS_SHELLCODE");

        result.success = !result.exploits.empty();
        if (!result.success)
            result.error = "No exploits found for: " + query;

    } catch (const json::exception& e) {
        result.error = std::string("JSON parse error: ") + e.what();
    }

    return result;
}
