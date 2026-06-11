#include "http_client.hpp"
#include <curl/curl.h>

namespace {
    size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
        size_t realsize = size * nmemb;
        auto* str = static_cast<std::string*>(userp);
        str->append(static_cast<char*>(contents), realsize);
        return realsize;
    }

    size_t header_callback(char* buffer, size_t size, size_t nitems, void* userdata) {
        size_t realsize = size * nitems;
        auto* headers = static_cast<std::map<std::string, std::string>*>(userdata);
        std::string header(buffer, realsize);
        auto pos = header.find(':');
        if (pos != std::string::npos) {
            std::string key = header.substr(0, pos);
            std::string value = header.substr(pos + 1);
            auto begin = value.find_first_not_of(" \r\n\t");
            if (begin != std::string::npos) {
                auto end = value.find_last_not_of(" \r\n\t");
                value = value.substr(begin, end - begin + 1);
            }
            (*headers)[key] = value;
        }
        return realsize;
    }
}

HttpResponse HttpClient::get(const std::string& url) {
    HttpResponse response;
    CURL* curl = curl_easy_init();
    if (!curl) return response;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response.body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response.headers);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status_code);
        response.success = true;
    }

    curl_easy_cleanup(curl);
    return response;
}
