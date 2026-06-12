#include "updater.hpp"
#include "cli_utils.hpp"
#include "logger.hpp"
#include "http_client.hpp"

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

// ─── helpers ──────────────────────────────────────────────────────────────────

namespace {

// Minimal JSON string-field extractor. Finds the first occurrence of
// "key": "value" and returns the value. Returns empty string if not found.
std::string json_string_field(const std::string& json, const std::string& key) {
    const std::string needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return {};

    pos = json.find('"', pos + needle.size());
    if (pos == std::string::npos) return {};
    ++pos;

    std::string value;
    for (; pos < json.size(); ++pos) {
        if (json[pos] == '\\' && pos + 1 < json.size()) {
            ++pos;
            switch (json[pos]) {
                case '"':  value += '"';  break;
                case '\\': value += '\\'; break;
                case 'n':  value += '\n'; break;
                case 'r':  value += '\r'; break;
                case 't':  value += '\t'; break;
                default:   value += json[pos]; break;
            }
            continue;
        }
        if (json[pos] == '"') break;
        value += json[pos];
    }
    return value;
}

// Returns true if remote semver string is strictly greater than local.
bool is_newer(const std::string& local, const std::string& remote) {
    auto parse = [](const std::string& v) -> std::vector<int> {
        std::vector<int> parts;
        std::istringstream ss(v);
        std::string token;
        while (std::getline(ss, token, '.')) {
            try { parts.push_back(std::stoi(token)); }
            catch (...) { parts.push_back(0); }
        }
        while (parts.size() < 3) parts.push_back(0);
        return parts;
    };
    const auto l = parse(local);
    const auto r = parse(remote);
    for (size_t i = 0; i < 3; ++i) {
        if (r[i] > l[i]) return true;
        if (r[i] < l[i]) return false;
    }
    return false;
}

} // namespace

// ─── public API ───────────────────────────────────────────────────────────────

void Updater::check() {
    // Allow users to opt out via environment variable
    if (std::getenv("GUNGNIR_NO_UPDATE") != nullptr) return;

    // Use HttpClient (libcurl) — same as threat_intel, no raw TLS code needed
    const std::string url =
        std::string("https://api.github.com/repos/") +
        GUNGNIR_REPO_OWNER + "/" + GUNGNIR_REPO_NAME +
        "/releases/latest";

    const std::map<std::string, std::string> headers = {
        {"Accept",     "application/vnd.github+json"},
        {"User-Agent", std::string("Gungnir/") + GUNGNIR_VERSION_NUM},
    };

    // Synchronous check with a short timeout — happens once at startup.
    // Silent on any network failure (firewall, no internet, etc.).
    const HttpResponse resp = HttpClient::get(url, headers, /*timeout_s=*/5);
    if (!resp.success || resp.status_code != 200) return;

    const std::string tag      = json_string_field(resp.body, "tag_name");
    const std::string html_url = json_string_field(resp.body, "html_url");
    if (tag.empty()) return;

    // Strip leading 'v' from tag (e.g. "v1.3.0" → "1.3.0")
    std::string remote_ver = tag;
    if (!remote_ver.empty() && remote_ver[0] == 'v')
        remote_ver.erase(0, 1);

    if (is_newer(GUNGNIR_VERSION_NUM, remote_ver)) {
        std::cout << "\n";
        Logger::warn("New version available: " + tag +
                     "  (current: v" + GUNGNIR_VERSION_NUM + ")");
        Logger::info("Download: " + html_url);
        std::cout << "\n";
    }
}
