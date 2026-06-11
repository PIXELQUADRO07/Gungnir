#include "network.hpp"
#include "logger.hpp"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <vector>

// ─── service name table ───────────────────────────────────────────────────────

std::string guess_service(int port) {
    static const std::map<int, const char*> well_known = {
        {21,    "ftp"},    {22,   "ssh"},     {23,   "telnet"},
        {25,    "smtp"},   {53,   "dns"},     {80,   "http"},
        {110,   "pop3"},   {143,  "imap"},    {443,  "https"},
        {465,   "smtps"},  {587,  "smtp"},    {636,  "ldaps"},
        {993,   "imaps"},  {995,  "pop3s"},   {1433, "mssql"},
        {1521,  "oracle"}, {3306, "mysql"},   {3389, "rdp"},
        {5432,  "pgsql"},  {5900, "vnc"},     {6379, "redis"},
        {8080,  "http"},   {8443, "https"},   {8888, "http"},
        {27017, "mongodb"},{9200, "elastic"},
    };
    auto it = well_known.find(port);
    return (it != well_known.end()) ? it->second : "";
}

// ─── internal helpers ─────────────────────────────────────────────────────────

namespace {

bool resolve_target(const std::string& target, sockaddr_in& out_addr) {
    addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* result = nullptr;
    if (getaddrinfo(target.c_str(), nullptr, &hints, &result) != 0 || !result)
        return false;

    out_addr = *reinterpret_cast<sockaddr_in*>(result->ai_addr);
    freeaddrinfo(result);
    return true;
}

// Attempt a brief banner read on an already-connected (blocking) socket.
// Returns empty string on timeout or if the service sends nothing.
std::string grab_banner(const std::string& target, int port, int timeout_ms) {
    // Open a fresh blocking socket for the banner grab
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return {};

    // Set send/recv timeout
    timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(static_cast<uint16_t>(port));

    addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(target.c_str(), nullptr, &hints, &res) != 0 || !res) {
        close(sock);
        return {};
    }
    addr.sin_addr = reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr;
    freeaddrinfo(res);

    if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close(sock);
        return {};
    }

    // Some services (HTTP) need a probe to reply
    const std::string svc = guess_service(port);
    if (svc == "http" || svc == "https") {
        const std::string probe = "HEAD / HTTP/1.0\r\n\r\n";
        send(sock, probe.c_str(), probe.size(), 0);
    }

    char buf[512] = {};
    ssize_t n = recv(sock, buf, sizeof(buf) - 1, 0);
    close(sock);

    if (n <= 0) return {};

    // Strip non-printable control chars except \n \r \t
    std::string banner;
    banner.reserve(static_cast<size_t>(n));
    for (ssize_t i = 0; i < n; ++i) {
        unsigned char c = static_cast<unsigned char>(buf[i]);
        if (c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c < 0x7f))
            banner += static_cast<char>(c);
    }

    // Trim trailing whitespace
    while (!banner.empty() && (banner.back() == '\n' || banner.back() == '\r' ||
                                banner.back() == ' '))
        banner.pop_back();

    return banner;
}

} // namespace

// ─── public API ───────────────────────────────────────────────────────────────

std::vector<PortInfo> start_native_scan(
    const std::string& target,
    const std::vector<int>& ports,
    int timeout_ms
) {
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;

    if (!resolve_target(target, server_addr)) {
        Logger::error("Unable to resolve target: " + target);
        return {};
    }

    std::vector<int> open_raw;
    const size_t CHUNK = 500;

    for (size_t i = 0; i < ports.size(); i += CHUNK) {
        size_t end   = std::min(ports.size(), i + CHUNK);
        size_t count = end - i;

        std::vector<int>     sockets(count, -1);
        std::vector<pollfd>  pfds;
        pfds.reserve(count);

        for (size_t j = 0; j < count; ++j) {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) continue;

            int flags = fcntl(sock, F_GETFL, 0);
            fcntl(sock, F_SETFL, flags | O_NONBLOCK);

            sockaddr_in addr = server_addr;
            addr.sin_port = htons(static_cast<uint16_t>(ports[i + j]));
            connect(sock, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));

            sockets[j] = sock;
            pfds.push_back({sock, POLLOUT, 0});
        }

        if (pfds.empty()) continue;

        int rc = poll(pfds.data(), static_cast<nfds_t>(pfds.size()), timeout_ms);
        if (rc > 0) {
            for (size_t j = 0; j < pfds.size(); ++j) {
                if (pfds[j].revents & (POLLOUT | POLLERR | POLLHUP)) {
                    int err = 0;
                    socklen_t len = sizeof(err);
                    if (getsockopt(pfds[j].fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0
                            && err == 0) {
                        open_raw.push_back(ports[i + j]);
                    }
                }
            }
        }

        for (int sock : sockets)
            if (sock >= 0) close(sock);
    }

    std::sort(open_raw.begin(), open_raw.end());

    // Build PortInfo list — attempt banner grab on each open port
    std::vector<PortInfo> result;
    result.reserve(open_raw.size());
    for (int port : open_raw) {
        PortInfo pi;
        pi.port    = port;
        pi.open    = true;
        pi.service = guess_service(port);
        pi.banner  = grab_banner(target, port, 2000);  // 2 s per banner
        result.push_back(std::move(pi));
    }
    return result;
}
