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

} // namespace

std::vector<int> start_native_scan(
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

        std::vector<int> open_ports;
        const size_t CHUNK_SIZE = 500;

        for (size_t i = 0; i < ports.size(); i += CHUNK_SIZE) {
            size_t end = std::min(ports.size(), i + CHUNK_SIZE);
            size_t current_chunk_size = end - i;

            std::vector<int> sockets(current_chunk_size, -1);
            std::vector<pollfd> pfds;
            pfds.reserve(current_chunk_size);

            for (size_t j = 0; j < current_chunk_size; ++j) {
                int sock = socket(AF_INET, SOCK_STREAM, 0);
                if (sock < 0) continue;

                int flags = fcntl(sock, F_GETFL, 0);
                fcntl(sock, F_SETFL, flags | O_NONBLOCK);

                sockaddr_in addr = server_addr;
                addr.sin_port = htons(ports[i + j]);

                connect(sock, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));

                sockets[j] = sock;
                pfds.push_back({sock, POLLOUT, 0});
            }

            if (pfds.empty()) continue;

            int rc = poll(pfds.data(), pfds.size(), timeout_ms);
            if (rc > 0) {
                for (size_t j = 0; j < pfds.size(); ++j) {
                    if (pfds[j].revents & (POLLOUT | POLLERR | POLLHUP)) {
                        int error = 0;
                        socklen_t len = sizeof(error);
                        if (getsockopt(pfds[j].fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0) {
                            open_ports.push_back(ports[i + j]);
                        }
                    }
                }
            }

            for (int sock : sockets) {
                if (sock >= 0) close(sock);
            }
        }

        std::sort(open_ports.begin(), open_ports.end());
        return open_ports;
    }
