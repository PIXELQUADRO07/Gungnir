#ifndef MODULES_IMPL_HPP
#define MODULES_IMPL_HPP

#include "module.hpp"
#include "engine.hpp"

// Forward declaration of Engine methods if needed, or just use Engine functions.
// Actually, since Engine already has the run_* methods, we can make them public or
// have the modules call them. But the goal is to MOVE the logic out of Engine.
// For now, let's make them call Engine methods to avoid a massive rewrite.

class ScanModule : public Module {
public:
    ScanModule(Engine& engine) : engine_(engine) {}
    std::string name() const override { return "scan"; }
    std::string help() const override { return "TCP port scan"; }
    bool supports_ports() const override { return true; }
    bool run(Context& ctx) override {
        // Qui chiamiamo la logica originale, che per ora è ancora in Engine
        // In futuro la sposteremo qui.
        return engine_.execute_scan(ctx);
    }
private:
    Engine& engine_;
};

// ... e così via per gli altri ...

#endif
