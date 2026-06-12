# Gungnir

![Gungnir Logo](Gungnir.png)

**Gungnir** is a fast, modular OSINT framework written in **C++20**.
It provides port scanning, DNS and WHOIS reconnaissance, command-line subcommands, and an interactive shell for iterative investigation.

## 🚀 Highlights

- Native TCP scanner with fixed worker thread pool
- Flexible port selection via `-p`
- DNS lookup module for A, AAAA, NS, MX, TXT, SOA, and CNAME
- WHOIS resolution with referral chasing through IANA, registry, and registrar servers
- HTML and JSON report generation
- Integration with Nmap and Searchsploit
- Interactive shell with module context, history support, and command registry
- SQLite3 persistence for all scan results

## 📦 Build & Install

### Dependencies

- **C++20** compiler (GCC 10+ or Clang 10+)
- **CMake** 3.15+
- **libcurl**
- **sqlite3**
- **readline** (optional, for shell history)
- **nmap** (optional, for service detection)
- **exploitdb** (optional, for searchsploit)

On Debian/Ubuntu, you can use the provided setup script:

```bash
sudo ./setup.sh
```

### Compilation

```bash
cmake -B build
cmake --build build
```

### Installation

```bash
sudo cmake --install build
```

## ⚙️ Configuration

Gungnir looks for a configuration file at `~/.gungnir.conf`. Example format:

```ini
VT_API_KEY     = your_virustotal_key
SHODAN_API_KEY = your_shodan_key
```

## 💡 Usage

### Direct subcommand style

```bash
./Gungnir scan   example.com
./Gungnir nmap   example.com -p 80,443
./Gungnir dns    example.com
./Gungnir report example.com -o report.html
./Gungnir searchsploit "apache 2.4"
```

### Interactive shell

Start the shell with no arguments:

```bash
./Gungnir
```

## 🧭 Commands

| Command | Description |
|---------|-------------|
| `scan <target>` | Fast TCP port scan |
| `nmap <target>` | Nmap service detection (requires nmap) |
| `dns <target>` | Perform DNS lookup |
| `whois <target>`| Perform WHOIS lookup |
| `threat <target>`| Threat Intel (requires API keys) |
| `report <target>`| Generate HTML/JSON report |
| `history` | Show scan history |
| `graph` | Export JSON graph for visualization |

## 🛠 Developer Guide

### Adding a Module

1. Create your module implementation in `modules/`.
2. Inherit from the `Module` class (see `src/module.hpp`).
3. Register your module in `src/engine.cpp`.
4. Add your `.cpp` file to `CMakeLists.txt`.

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.
