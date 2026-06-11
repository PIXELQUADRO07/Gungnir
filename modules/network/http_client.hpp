#ifndef HTTP_CLIENT_HPP
#define HTTP_CLIENT_HPP

#include <string>
#include <map>

struct HttpResponse {
    int status_code = 0;
    std::string body;
    std::map<std::string, std::string> headers;
    bool success = false;
};

class HttpClient {
public:
    static HttpResponse get(
        const std::string& url,
        const std::map<std::string, std::string>& custom_headers = {},
        int timeout_s = 10
    );
};

#endif
