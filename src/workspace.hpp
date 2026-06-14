#ifndef WORKSPACE_HPP
#define WORKSPACE_HPP

#include <string>
#include <memory>
#include "database.hpp"

class Workspace {
public:
    static std::unique_ptr<Workspace> create(const std::string& name);
    static std::unique_ptr<Workspace> load(const std::string& name);
    static std::unique_ptr<Workspace> load_default();

    Workspace(const std::string& name, const std::string& root_path);

    std::string name() const { return name_; }
    std::string root() const;
    std::string db_path() const;
    std::string exports_dir() const;
    std::string logs_dir() const;

    Database& db() { return *db_; }

private:
    std::string name_;
    std::string root_path_;
    std::unique_ptr<Database> db_;

    static void ensure_dir(const std::string& path);

    // Replaces characters that are unsafe as a single path component
    // (/, \, and any leading run of '.') with '_', so a workspace name
    // like "../../etc" can't escape ~/.gungnir/workspaces/.
    static std::string sanitize_name(const std::string& name);
};

#endif
