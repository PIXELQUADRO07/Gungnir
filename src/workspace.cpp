#include "workspace.hpp"
#include "logger.hpp"
#include <cctype>
#include <sys/stat.h>
#include <unistd.h>
#include <iostream>

Workspace::Workspace(const std::string& name, const std::string& root_path)
    : name_(name), root_path_(root_path) {
    ensure_dir(root_path_);
    ensure_dir(exports_dir());
    ensure_dir(logs_dir());
    db_ = std::make_unique<Database>(root_path + "/recon.db");
    db_->init();
}

std::string Workspace::sanitize_name(const std::string& name) {
    std::string out;
    out.reserve(name.size());
    for (char c : name) {
        if (std::isalnum(static_cast<unsigned char>(c)) ||
            c == '-' || c == '_' || c == '.') {
            out += c;
        } else {
            out += '_';
        }
    }
    // Collapse any leading run of dots so "..", "....", etc. can never be
    // mistaken for "go up a directory" when joined onto workspaces_dir.
    size_t first_non_dot = out.find_first_not_of('.');
    if (first_non_dot == std::string::npos) return "default";
    if (first_non_dot > 0) out = out.substr(first_non_dot);
    return out.empty() ? "default" : out;
}

std::unique_ptr<Workspace> Workspace::create(const std::string& name) {
    const std::string safe_name = sanitize_name(name);
    std::string workspaces_dir = get_gungnir_data_dir() + "/workspaces";
    ensure_dir(workspaces_dir);
    std::string base = workspaces_dir + "/" + safe_name;
    ensure_dir(base);
    return std::make_unique<Workspace>(safe_name, base);
}

std::unique_ptr<Workspace> Workspace::load(const std::string& name) {
    const std::string safe_name = sanitize_name(name);
    std::string base = get_gungnir_data_dir() + "/workspaces/" + safe_name;
    if (access(base.c_str(), F_OK) == -1) {
        Logger::error("Workspace non trovato: " + safe_name);
        return nullptr;
    }
    return std::make_unique<Workspace>(safe_name, base);
}

std::unique_ptr<Workspace> Workspace::load_default() {
    std::string base = get_gungnir_data_dir() + "/default";
    ensure_dir(base);
    return std::make_unique<Workspace>("default", base);
}

std::string Workspace::root() const {
    return root_path_;
}

std::string Workspace::db_path() const {
    return root_path_ + "/recon.db";
}

std::string Workspace::exports_dir() const {
    return root_path_ + "/exports";
}

std::string Workspace::logs_dir() const {
    return root_path_ + "/logs";
}

void Workspace::ensure_dir(const std::string& path) {
    mkdir(path.c_str(), 0700);
}
