#include "scraper.hpp"
#include "logger.hpp"
#include "http_client.hpp"
#include "json.hpp"
#include <regex>
#include <iostream>
#include <algorithm>
#include <set>

namespace {

void extract_social_links(const std::string& body, std::vector<std::string>& links) {
    std::set<std::string> found;
    std::vector<std::string> patterns = {
        R"(https?://(?:www\.)?facebook\.com/[a-zA-Z0-9.]+)",
        R"(https?://(?:www\.)?twitter\.com/[a-zA-Z0-9_]+)",
        R"(https?://(?:www\.)?instagram\.com/[a-zA-Z0-9_.]+)",
        R"(https?://(?:www\.)?linkedin\.com/(?:in|company)/[a-zA-Z0-9_-]+)",
        R"(https?://(?:www\.)?github\.com/[a-zA-Z0-9_-]+)"
    };

    for (const auto& p : patterns) {
        std::regex re(p, std::regex_constants::icase);
        auto words_begin = std::sregex_iterator(body.begin(), body.end(), re);
        auto words_end = std::sregex_iterator();
        for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
            found.insert((*i).str());
        }
    }
    for (const auto& l : found) links.push_back(l);
}

void extract_phones(const std::string& body, std::vector<std::string>& phones) {
    std::set<std::string> found;
    // Simple international phone pattern
    std::regex re(R"(\+?\d{1,3}[-.\s]?\(?\d{1,4}?\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9})");
    auto words_begin = std::sregex_iterator(body.begin(), body.end(), re);
    auto words_end = std::sregex_iterator();
    for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
        std::string s = (*i).str();
        if (s.length() > 8) found.insert(s); // Avoid small numbers
    }
    for (const auto& p : found) phones.push_back(p);
}

std::string detect_cms(const std::string& body) {
    if (body.find("wp-content") != std::string::npos) return "WordPress";
    if (body.find("Joomla!") != std::string::npos) return "Joomla";
    if (body.find("drupal.org") != std::string::npos) return "Drupal";
    if (body.find("_ghost") != std::string::npos) return "Ghost";
    return "";
}

void fetch_robots(const std::string& base_url, std::vector<std::string>& entries) {
    std::string url = base_url;
    if (url.back() == '/') url.pop_back();
    url += "/robots.txt";

    HttpResponse resp = HttpClient::get(url);
    if (resp.success) {
        std::istringstream ss(resp.body);
        std::string line;
        while (std::getline(ss, line)) {
            if (line.find("Disallow:") == 0 || line.find("Allow:") == 0) {
                entries.push_back(line);
            }
        }
    }
}

void fetch_wayback_urls(const std::string& domain, std::vector<std::string>& urls) {
    const std::string url = "https://web.archive.org/cdx/search/cdx?url=" + domain + 
                           "/*&output=json&collapse=urlkey&fl=original&limit=50";
    
    HttpResponse resp = HttpClient::get(url);
    if (resp.success) {
        try {
            auto j = nlohmann::json::parse(resp.body);
            bool first = true;
            for (const auto& row : j) {
                if (first) { first = false; continue; } // skip header row
                if (row.is_array() && !row.empty()) {
                    urls.push_back(row[0].get<std::string>());
                }
            }
        } catch (...) {}
    }
}

} // namespace

ScrapeResult start_web_scrape(const std::string& target) {
    ScrapeResult result;
    std::string url = target;
    std::string domain = target;
    
    // Extract domain from target if it's a full URL
    if (domain.find("://") != std::string::npos) {
        domain = domain.substr(domain.find("://") + 3);
    }
    if (domain.find('/') != std::string::npos) {
        domain = domain.substr(0, domain.find('/'));
    }

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
    std::set<std::string> email_set;
    std::regex email_regex(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
    auto email_begin = std::sregex_iterator(resp.body.begin(), resp.body.end(), email_regex);
    auto email_end = std::sregex_iterator();
    for (std::sregex_iterator i = email_begin; i != email_end; ++i) {
        email_set.insert((*i).str());
    }
    for (const auto& e : email_set) result.emails.push_back(e);

    // Advanced Metadata
    extract_social_links(resp.body, result.social_links);
    extract_phones(resp.body, result.phone_numbers);
    result.cms = detect_cms(resp.body);
    fetch_robots(url, result.robots_entries);
    fetch_wayback_urls(domain, result.historical_urls);

    return result;
}
