#pragma once

// Checks the latest GitHub release against the local version and prints a
// notification if an update is available.  Network-only, no download.

namespace Updater {
    void check();
}
