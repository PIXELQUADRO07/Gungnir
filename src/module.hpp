#ifndef MODULE_HPP
#define MODULE_HPP

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include "database.hpp"
#include "config.hpp"
#include "logger.hpp"
#include "workspace.hpp"

struct Context {
    std::string target;
    std::vector<int> ports;
    std::string output_file;
    Database& db;
    Config& config;
    Workspace& workspace;
    // Logger è statico ma potremmo volerlo passare se volessimo logger diversi
};

class Module {
public:
    virtual ~Module() = default;
    virtual std::string name() const = 0;
    virtual std::string help() const = 0;
    virtual bool supports_ports() const { return false; }
    virtual bool run(Context& ctx) = 0;
};

class ModuleRegistry {
public:
    void register_module(std::unique_ptr<Module> m) {
        modules_[m->name()] = std::move(m);
    }

    Module* find(const std::string& name) {
        auto it = modules_.find(name);
        return (it != modules_.end()) ? it->second.get() : nullptr;
    }

    bool execute(const std::string& name, Context& ctx) {
        Module* m = find(name);
        if (!m) return false;
        return m->run(ctx);
    }

    std::vector<Module*> all() const {
        std::vector<Module*> res;
        for (auto& [_, m] : modules_) res.push_back(m.get());
        return res;
    }

private:
    std::unordered_map<std::string, std::unique_ptr<Module>> modules_;
};

#endif
