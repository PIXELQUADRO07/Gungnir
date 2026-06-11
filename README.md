# Gungnir

![Gungnir Logo](Gungnir.png)

**Gungnir** is a fast, modular OSINT framework written in **C++20**.
It provides port scanning, DNS and WHOIS reconnaissance, command-line subcommands, and an interactive shell for iterative investigation.

## 🚀 Highlights

- Native TCP scanner with fixed worker thread pool
- Flexible port selection via `-p`
- DNS lookup module for A, AAAA, NS, MX, TXT, SOA, and CNAME
- WHOIS resolution with referral chasing through IANA, registry, and registrar servers
- JSON export support via `-o`
- Extensible OSINT scraping skeleton
- Colored logging and progress feedback
- Interactive shell with module context, history support, and command registry
- Subcommand CLI pattern for clean commands like `./Gungnir scan example.com`

## 📦 Build

```bash
cmake -B build
cmake --build build
```

Optional: enable readline support for shell history and line editing.

```bash
sudo apt install libreadline-dev
cmake -B build && cmake --build build
```

## 💡 Usage

### Direct subcommand style

```bash
./Gungnir scan   example.com
./Gungnir scan   example.com -p 22,80,443
./Gungnir scan   example.com -p 22,80,443 -o result.json
./Gungnir dns    example.com
./Gungnir dns    example.com -o dns.json
./Gungnir whois  example.com
./Gungnir whois  example.com -o whois.json
./Gungnir scrape user123
```

### Interactive shell

Start the shell with no arguments or `-i`:

```bash
./Gungnir
./Gungnir -i
```

Example shell session:

```text
Gungnir > scan example.com -p 80,443
Gungnir > dns example.com
Gungnir > whois example.com -o out.json
Gungnir > scrape user123

Gungnir > use scan
gungnir(scan) > run example.com -p 22,80,443
gungnir(scan) > run 192.168.1.1

Gungnir > help
Gungnir > clear
Gungnir > version
Gungnir > exit
```

## 🧭 Shell commands

| Command | Description |
|---------|-------------|
| `scan <target> [-p ports] [-o file]` | Run a TCP port scan |
| `dns <target> [-o file]` | Perform DNS lookup |
| `whois <target> [-o file]` | Perform WHOIS lookup |
| `scrape <target>` | Execute OSINT scraping flow |
| `use <module>` | Select active module (scan, dns, whois, scrape) |
| `run <target> [flags]` | Run the selected module |
| `banner` | Display the banner |
| `clear` | Clear the terminal screen |
| `version` | Show version information |
| `help` / `?` | Show help list |
| `exit` / `quit` | Exit the shell |

## 🧪 Legacy flag style

The legacy flag-style interface is still supported:

```bash
./Gungnir -t example.com -m scan -p 22,80,443 -o result.json
./Gungnir -t example.com -m dns
./Gungnir -t example.com -m whois -o whois.json
```

## 📌 Notes

- `scan` uses a default port list when `-p` is omitted.
- `scan`, `dns`, and `whois` report elapsed time on completion.
- `dns` queries A, AAAA, NS, MX, TXT, and SOA records, with CNAME as fallback.
- `whois` follows referrals from IANA → registry → registrar.
- `whois` requires outbound TCP on port 43.
- `scrape` is currently a scaffold for future OSINT modules.
- Readline support adds shell history, line editing, and reverse search when available.
