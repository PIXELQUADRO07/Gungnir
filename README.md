# Gungnir

![Gungnir Logo](Gungnir.png)

Fast modular OSINT framework in C++20.

## Features

- Native TCP scanner with fixed worker thread pool
- Custom port lists via `-p`
- DNS lookup module (A, AAAA, NS, MX, TXT, SOA, CNAME)
- WHOIS lookup with IANA/registry/registrar referral chasing
- JSON export via `-o`
- OSINT scraping stub (ready for extension)
- Colored logging
- **Interactive shell** with command registry, contextual prompt, and optional readline support
- **Subcommand CLI** — `./Gungnir scan example.com` instead of flag soup

## Build

```bash
cmake -B build
cmake --build build
```

With readline (enables history + line editing in the shell):

```bash
# Debian/Ubuntu
sudo apt install libreadline-dev

cmake -B build && cmake --build build
```

## Usage

### Direct (subcommand style)

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

```bash
./Gungnir        # no arguments → shell
./Gungnir -i
```

Inside the shell:

```
Gungnir > scan example.com -p 80,443
Gungnir > dns  example.com
Gungnir > whois example.com -o out.json
Gungnir > scrape user123

# Module context mode
Gungnir > use scan
gungnir(scan) > run example.com -p 22,80,443
gungnir(scan) > run 192.168.1.1

Gungnir > help
Gungnir > clear
Gungnir > version
Gungnir > exit
```

## Shell commands

| Command | Description |
|---------|-------------|
| `scan <target> [-p ports] [-o file]` | TCP port scan |
| `dns <target> [-o file]` | DNS lookup (A/AAAA/MX/NS/TXT/SOA) |
| `whois <target> [-o file]` | WHOIS lookup |
| `scrape <target>` | OSINT scraping |
| `use <module>` | Set active module (scan/dns/whois/scrape) |
| `run <target> [flags]` | Execute active module |
| `banner` | Show ASCII banner |
| `clear` | Clear screen |
| `version` | Show version |
| `help` / `?` | Command list |
| `exit` / `quit` | Quit |

## Legacy flag style (still supported)

```bash
./Gungnir -t example.com -m scan -p 22,80,443 -o result.json
./Gungnir -t example.com -m dns
./Gungnir -t example.com -m whois -o whois.json
```

## Notes

- `scan` uses a default port list when `-p` is omitted.
- `scan`, `dns`, and `whois` report elapsed time on completion.
- `dns` queries A, AAAA, NS, MX, TXT, and SOA records (CNAME as fallback).
- `whois` follows referrals from IANA → registry → registrar.
- `whois` requires outbound TCP on port 43.
- `scrape` is a scaffold for future OSINT modules.
- readline (if found at build time) enables ↑/↓ history and Ctrl+R search in the shell.
