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
#include <atomic>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

namespace {
    constexpr int MAX_THREADS = 128;

    bool resolve_target(const std::string& target, sockaddr_in& out_addr) {
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        addrinfo* result = nullptr;
        if (getaddrinfo(target.c_str(), nullptr, &hints, &result) != 0) {
            return false;
        }

        if (result == nullptr) {
            return false;
        }

        out_addr = *reinterpret_cast<sockaddr_in*>(result->ai_addr);
        freeaddrinfo(result);
        return true;
    }

    bool connect_with_timeout(int sock, const sockaddr_in& server_addr, int timeout_ms) {
        const int flags = fcntl(sock, F_GETFL, 0);
        if (flags < 0) {
            return false;
        }

        if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
            return false;
        }

        int result = connect(sock, reinterpret_cast<const sockaddr*>(&server_addr), sizeof(server_addr));
        if (result == 0) {
            fcntl(sock, F_SETFL, flags);
            return true;
        }

        if (errno != EINPROGRESS) {
            return false;
        }

        pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLOUT;
        pfd.revents = 0;

        result = poll(&pfd, 1, timeout_ms);
        if (result <= 0) {
            return false;
        }

        int socket_error = 0;
        socklen_t error_length = sizeof(socket_error);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &socket_error, &error_length) < 0) {
            return false;
        }

        fcntl(sock, F_SETFL, flags);
        return socket_error == 0;
    }

    bool check_port(const sockaddr_in& base_addr, int port, int timeout_ms) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            return false;
        }

        sockaddr_in server_addr = base_addr;
        server_addr.sin_port = htons(port);

        const bool open = connect_with_timeout(sock, server_addr, timeout_ms);
        close(sock);
        return open;
    }
}

std::vector<int> start_native_scan(
    const std::string& target,
    const std::vector<int>& ports,
    int timeout_ms
) {
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;

    if (!resolve_target(target, server_addr)) {
        Logger::error("Impossibile risolvere il target: " + target);
        return {};
    }

    const size_t thread_count = std::min(static_cast<size_t>(MAX_THREADS), ports.size());
    std::atomic<size_t> next_index{0};
    std::vector<int> open_ports;
    std::mutex result_mutex;
    std::vector<std::thread> workers;
    workers.reserve(thread_count);

    for (size_t i = 0; i < thread_count; ++i) {
        workers.emplace_back([&] {
            while (true) {
                const size_t index = next_index.fetch_add(1, std::memory_order_relaxed);
                if (index >= ports.size()) {
                    break;
                }

                const int port = ports[index];
                if (check_port(server_addr, port, timeout_ms)) {
                    std::lock_guard<std::mutex> lock(result_mutex);
                    open_ports.push_back(port);
                }
            }
        });
    }

    for (auto& worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }

    std::sort(open_ports.begin(), open_ports.end());
    return open_ports;
}
