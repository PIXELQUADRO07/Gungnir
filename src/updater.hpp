#pragma once

// Checks the latest GitHub release against the local version.
// Prints a one-line notification if an update is available.
// Silent on any network failure. Respects GUNGNIR_NO_UPDATE env var.

namespace Updater {
    void check();
}
