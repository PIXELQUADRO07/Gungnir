#include "workspace.hpp"
#include "logger.hpp"
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

std::unique_ptr<Workspace> Workspace::create(const std::string& name) {
    std::string workspaces_dir = get_gungnir_data_dir() + "/workspaces";
    ensure_dir(workspaces_dir);
    std::string base = workspaces_dir + "/" + name;
    ensure_dir(base);
    return std::make_unique<Workspace>(name, base);
}

std::unique_ptr<Workspace> Workspace::load(const std::string& name) {
    std::string base = get_gungnir_data_dir() + "/workspaces/" + name;
    if (access(base.c_str(), F_OK) == -1) {
        Logger::error("Workspace non trovato: " + name);
        return nullptr;
    }
    return std::make_unique<Workspace>(name, base);
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
