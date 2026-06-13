#include "ssl_geoip.hpp"
#include "http_client.hpp"
#include "logger.hpp"
#include "json.hpp"
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <ctime>

namespace {
    std::string asn1_time_to_string(const ASN1_TIME* time) {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) return "";
        ASN1_TIME_print(bio, time);
        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        std::string res(data, len);
        BIO_free(bio);
        return res;
    }
}

SslInfo get_ssl_info(const std::string& target, int port) {
    SslInfo result;
    
    SSL_library_init();
    SSL_load_error_strings();
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) return result;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        SSL_CTX_free(ctx);
        return result;
    }

    struct hostent* host = gethostbyname(target.c_str());
    if (!host) {
        close(sock);
        SSL_CTX_free(ctx);
        return result;
    }

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)host->h_addr;

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(sock);
        SSL_CTX_free(ctx);
        return result;
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return result;
    }

    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        result.success = true;
        
        char buf[1024];
        X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));
        result.subject = buf;
        
        X509_NAME_oneline(X509_get_issuer_name(cert), buf, sizeof(buf));
        result.issuer = buf;

        result.valid_from = asn1_time_to_string(X509_get0_notBefore(cert));
        result.valid_until = asn1_time_to_string(X509_get0_notAfter(cert));

        // Extract SAN
        STACK_OF(GENERAL_NAME)* san_names = (STACK_OF(GENERAL_NAME)*)X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr);
        if (san_names) {
            int count = sk_GENERAL_NAME_num(san_names);
            for (int i = 0; i < count; ++i) {
                const GENERAL_NAME* name = sk_GENERAL_NAME_value(san_names, i);
                if (name->type == GEN_DNS) {
                    char* dns = (char*)ASN1_STRING_get0_data(name->d.dNSName);
                    result.san.push_back(dns);
                }
            }
            sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
        }

        X509_free(cert);
    }

    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    return result;
}

GeoIpInfo get_geoip_info(const std::string& ip) {
    GeoIpInfo result;
    result.ip = ip;

    std::string url = "http://ip-api.com/json/" + ip;
    HttpResponse resp = HttpClient::get(url);

    if (resp.success) {
        try {
            auto j = nlohmann::json::parse(resp.body);
            if (j.contains("status") && j["status"] == "success") {
                result.success = true;
                result.country = j.value("country", "");
                result.region = j.value("regionName", "");
                result.city = j.value("city", "");
                result.isp = j.value("isp", "");
                result.timezone = j.value("timezone", "");
                result.lat = j.value("lat", 0.0);
                result.lon = j.value("lon", 0.0);
            }
        } catch (...) {}
    }
    return result;
}
