<div align="center">

<img src="Gungnir.png" width="220"/>

# Gungnir

### Fast • Modular • Local-first OSINT Framework written in C++20

![Build](https://img.shields.io/github/actions/workflow/status/YOUR_USER/Gungnir/cmake.yml)
![License](https://img.shields.io/github/license/YOUR_USER/Gungnir)
![Stars](https://img.shields.io/github/stars/YOUR_USER/Gungnir)

Recon • Scan • Threat Intel • Reports

</div>

---

## Overview

Gungnir is a modular OSINT framework built in modern C++.

It combines reconnaissance, network scanning, service discovery, threat intelligence, and reporting into a single interactive CLI.

Designed for:

* Speed
* Modularity
* Local-first workflows
* Interactive investigation

---

## Features

* Multi-threaded TCP scanning
* DNS Recon
* WHOIS lookup
* Nmap integration
* Searchsploit integration
* Threat Intelligence
* HTML & JSON reports
* Interactive shell
* SQLite persistence
* Docker support
* Multi-target workflows

---

## Demo

```bash
./Gungnir

Gungnir > scan example.com
Gungnir > dns example.com
Gungnir > nmap example.com
Gungnir > report example.com
```

*(add GIF later)*

---

## Architecture

```text
Target
↓
Recon
↓
Scan
↓
Nmap
↓
Threat Intel
↓
Searchsploit
↓
Report
```

---

## Quick Start

Build:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Run:

```bash
./build/Gungnir
```

---

## Dependencies

Required:

* C++20
* CMake
* libcurl
* sqlite3

Optional:

* readline
* nmap
* searchsploit

Install:

```bash
sudo ./setup.sh
```

---

## Configuration

```ini
VT_API_KEY=...
SHODAN_API_KEY=...
```

---

## Commands

| Command | Description       |
| ------- | ----------------- |
| scan    | Fast TCP scan     |
| dns     | DNS lookup        |
| whois   | WHOIS lookup      |
| nmap    | Service detection |
| threat  | Threat intel      |
| report  | Generate reports  |
| history | Scan history      |
| graph   | Export graph      |

---

## Roadmap

* [x] Interactive CLI
* [x] Reports
* [x] Docker
* [x] Multi-target
* [ ] Plugin system
* [ ] Distributed execution

---

## License

MIT
