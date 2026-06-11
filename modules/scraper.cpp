#include "scraper.hpp"
#include "logger.hpp"
#include "http_client.hpp"
#include <regex>
#include <iostream>

ScrapeResult start_web_scrape(const std::string& target) {
    ScrapeResult result;
    std::string url = target;
    if (url.find("http://") != 0 && url.find("https://") != 0) {
        url = "http://" + url;
    }

    Logger::info("Scraping " + url + " ...");
    HttpResponse resp = HttpClient::get(url);

    if (!resp.success) {
        Logger::error("Failed to connect to " + url);
        return result;
    }

    result.success = true;

    // Extract Server header
    for (const auto& header : resp.headers) {
        std::string key = header.first;
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        if (key == "server") {
            result.server_header = header.second;
            break;
        }
    }

    // Extract Title
    std::regex title_regex("<title>([^<]+)</title>", std::regex_constants::icase);
    std::smatch title_match;
    if (std::regex_search(resp.body, title_match, title_regex) && title_match.size() > 1) {
        result.title = title_match[1].str();
    }

    // Extract Emails
    std::regex email_regex(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
    auto words_begin = std::sregex_iterator(resp.body.begin(), resp.body.end(), email_regex);
    auto words_end = std::sregex_iterator();
    
    for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
        std::string match_str = (*i).str();
        if (std::find(result.emails.begin(), result.emails.end(), match_str) == result.emails.end()) {
            result.emails.push_back(match_str);
        }
    }

    return result;
}
