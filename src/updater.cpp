#include "updater.hpp"
#include "cli_utils.hpp"
#include "logger.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <sstream>
#include <iostream>
#include <string>
#include <vector>

// ─── internal helpers ─────────────────────────────────────────────────────────

namespace {

// Minimal JSON string extractor: finds the value of `"key": "value"`.
// Returns empty string if not found.
std::string json_string_field(const std::string& json, const std::string& key) {
    const std::string needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return {};

    pos = json.find('"', pos + needle.size());
    if (pos == std::string::npos) return {};
    ++pos;  // skip opening quote

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
        if (json[pos] == '"') break;  // closing quote
        value += json[pos];
    }
    return value;
}

// Compares two semantic version strings (e.g. "1.0.0" vs "1.2.0").
// Returns true if remote > local.
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

// Opens a TCP socket to host:443 and returns the fd, or -1 on error.
int tcp_connect(const std::string& host) {
    addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host.c_str(), "443", &hints, &res) != 0 || !res)
        return -1;

    int fd = -1;
    for (auto* p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

// Performs a GET request over TLS and returns the response body (after headers).
std::string https_get(const std::string& host, const std::string& path) {
    // ── TLS setup ──────────────────────────────────────────────────────────
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return {};

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_default_verify_paths(ctx);

    const int fd = tcp_connect(host);
    if (fd < 0) { SSL_CTX_free(ctx); return {}; }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host.c_str());

    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        return {};
    }

    // ── HTTP/1.1 request ──────────────────────────────────────────────────
    const std::string req =
        "GET " + path + " HTTP/1.1\r\n"
        "Host: " + host + "\r\n"
        "User-Agent: Gungnir/" + GUNGNIR_VERSION_NUM + "\r\n"
        "Accept: application/vnd.github+json\r\n"
        "Connection: close\r\n"
        "\r\n";

    SSL_write(ssl, req.c_str(), static_cast<int>(req.size()));

    // ── read response ─────────────────────────────────────────────────────
    std::string raw;
    char buf[4096];
    int n;
    while ((n = SSL_read(ssl, buf, sizeof(buf))) > 0)
        raw.append(buf, n);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);

    // ── strip HTTP headers (find blank line \r\n\r\n) ─────────────────────
    const auto sep = raw.find("\r\n\r\n");
    if (sep == std::string::npos) return raw;
    return raw.substr(sep + 4);
}

}  // namespace

// ─── public API ───────────────────────────────────────────────────────────────

void Updater::check() {
    const std::string host = "api.github.com";
    const std::string path = std::string("/repos/") +
                             GUNGNIR_REPO_OWNER + "/" +
                             GUNGNIR_REPO_NAME  +
                             "/releases/latest";

    const std::string body = https_get(host, path);
    if (body.empty()) {
        // Silent fail — no network, firewall, etc. Don't spam the user.
        return;
    }

    const std::string tag      = json_string_field(body, "tag_name");
    const std::string html_url = json_string_field(body, "html_url");

    if (tag.empty()) return;

    // Strip leading 'v' from tag (e.g. "v1.2.0" → "1.2.0")
    std::string remote_ver = tag;
    if (!remote_ver.empty() && remote_ver[0] == 'v')
        remote_ver.erase(0, 1);

    if (is_newer(GUNGNIR_VERSION_NUM, remote_ver)) {
        std::cout << "\n";
        Logger::warn("Nuova versione disponibile: " + tag +
                     "  (locale: v" + GUNGNIR_VERSION_NUM + ")");
        Logger::info("Scarica: " + html_url);
        std::cout << "\n";
    }
}
