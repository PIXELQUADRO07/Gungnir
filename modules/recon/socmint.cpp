#include "socmint.hpp"
#include "http_client.hpp"
#include "logger.hpp"
#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <map>

namespace {
    std::string replace_username(std::string template_str, const std::string& username) {
        size_t pos = template_str.find("{}");
        if (pos != std::string::npos) {
            template_str.replace(pos, 2, username);
        }
        return template_str;
    }
}

SocmintResult run_socmint_search(const std::string& username) {
    static const std::vector<SocSite> sites = {
        {"GitHub", "https://github.com/{}"},
        {"Twitter", "https://twitter.com/{}"},
        {"Instagram", "https://www.instagram.com/{}/"},
        {"Reddit", "https://www.reddit.com/user/{}"},
        {"Facebook", "https://www.facebook.com/{}"},
        {"YouTube", "https://www.youtube.com/@{}"},
        {"Twitch", "https://www.twitch.tv/{}"},
        {"Pinterest", "https://www.pinterest.com/{}/"},
        {"Tumblr", "https://{}.tumblr.com"},
        {"SoundCloud", "https://soundcloud.com/{}"},
        {"Steam", "https://steamcommunity.com/id/{}"},
        {"Medium", "https://medium.com/@{}"},
        {"Vimeo", "https://vimeo.com/{}"},
        {"Etsy", "https://www.etsy.com/people/{}"},
        {"eBay", "https://www.ebay.com/usr/{}"},
        {"Slack", "https://{}.slack.com"},
        {"Snapchat", "https://www.snapchat.com/add/{}"},
        {"Telegram", "https://t.me/{}"},
        {"Spotify", "https://open.spotify.com/user/{}"},
        {"Roblox", "https://www.roblox.com/user.aspx?username={}"},
        {"TikTok", "https://www.tiktok.com/@{}"},
        {"LinkedIn", "https://www.linkedin.com/in/{}"},
        {"Bitbucket", "https://bitbucket.org/{}/"},
        {"DailyMotion", "https://www.dailymotion.com/{}"},
        {"Disqus", "https://disqus.com/by/{}/"},
        {"Flickr", "https://www.flickr.com/people/{}/"},
        {"Goodreads", "https://www.goodreads.com/{}"},
        {"Imgur", "https://imgur.com/user/{}"},
        {"Kickstarter", "https://www.kickstarter.com/profile/{}"},
        {"Letterboxd", "https://letterboxd.com/{}/"},
        {"Mixcloud", "https://www.mixcloud.com/{}/"},
        {"Pastebin", "https://pastebin.com/u/{}"},
        {"Patreon", "https://www.patreon.com/{}"},
        {"Quora", "https://www.quora.com/profile/{}"},
        {"SlideShare", "https://www.slideshare.net/{}"},
        {"Spotify", "https://open.spotify.com/user/{}"},
        {"Vero", "https://vero.co/{}"},
        {"Wattpad", "https://www.wattpad.com/user/{}"},
        {"WordPress", "https://{}.wordpress.com/"}
    };

    SocmintResult result;
    result.username = username;
    std::mutex mtx;
    std::atomic<size_t> current_site{0};
    
    Logger::info("SOCMINT: Searching for username '" + username + "' across " + std::to_string(sites.size()) + " platforms...");

    // Increased thread count for ultra-fast parallel search
    const size_t num_threads = std::min(static_cast<size_t>(20), sites.size());
    std::vector<std::thread> workers;

    for (size_t i = 0; i < num_threads; ++i) {
        workers.emplace_back([&]() {
            while (true) {
                size_t idx = current_site.fetch_add(1);
                if (idx >= sites.size()) break;

                const auto& site = sites[idx];
                std::string url = replace_username(site.url_template, username);
                
                // Use a realistic User-Agent to avoid being blocked
                std::map<std::string, std::string> headers = {
                    {"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"}
                };

                HttpResponse resp = HttpClient::get(url, headers, 10);
                
                if (resp.status_code == 200) {
                    // Basic heuristic: check if body is too small or contains "not found" style text
                    // for sites that return 200 for missing pages.
                    bool invalid = false;
                    std::string body_lower = resp.body;
                    std::transform(body_lower.begin(), body_lower.end(), body_lower.begin(), ::tolower);
                    
                    if (body_lower.find("page not found") != std::string::npos || 
                        body_lower.find("user not found") != std::string::npos ||
                        body_lower.find("404 not found") != std::string::npos) {
                        invalid = true;
                    }

                    if (!invalid) {
                        std::lock_guard<std::mutex> lock(mtx);
                        result.matches.push_back({site.name, url});
                    }
                }
            }
        });
    }

    for (auto& w : workers) {
        if (w.joinable()) w.join();
    }

    std::sort(result.matches.begin(), result.matches.end(), [](const auto& a, const auto& b) {
        return a.name < b.name;
    });

    return result;
}
