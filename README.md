<p align="center">
  <img src="Gungnir.png" width="200">
</p>

<h1 align="center">Gungnir</h1>
<p align="center"><strong>OSINT & Network Recon Tool — C++20</strong></p>

---

## Features

| Comando     | Descrizione                                              |
|-------------|----------------------------------------------------------|
| `scan`      | TCP Port Scanner asincrono (batch con `poll`)            |
| `dns`       | DNS Lookup + brute-force sottodomini                     |
| `whois`     | WHOIS con parsing strutturato                            |
| `scrape`    | Web Scraper (titolo, server header, email) via libcurl   |
| `campaign`  | Pipeline completa: DNS → Scan → Scrape → Threat Intel    |
| `threat`    | Threat Intelligence (VirusTotal per domini, Shodan per IP)|
| `history`   | Storico scan dal database locale SQLite                  |
| `graph`     | Esporta le relazioni scoperte in JSON (Nodi + Archi)     |

---

## Installazione

### Dipendenze

```bash
sudo apt-get install libssl-dev libcurl4-openssl-dev libsqlite3-dev
# Opzionale: readline per line-editing nella shell interattiva
sudo apt-get install libreadline-dev
```

### Build

```bash
cmake -B build
cmake --build build
```

---

## Utilizzo

### Modalità interattiva (shell)

```bash
./Gungnir
```

### Modalità diretta

```bash
./Gungnir scan    example.com
./Gungnir scan    example.com -p 22,80,443 -o result.json
./Gungnir dns     example.com
./Gungnir whois   example.com
./Gungnir scrape  example.com
./Gungnir campaign example.com -p 80,443
./Gungnir threat  example.com          # dominio → VirusTotal
./Gungnir threat  93.184.216.34        # IP → Shodan
./Gungnir history                      # tutti gli scan nel DB
./Gungnir history example.com          # scan per un target specifico
./Gungnir graph   -o visual.json       # grafo JSON di relazioni
```

### Flag globali

```
-p <ports>        Porte TCP separate da virgola
-o <file>         Esporta risultato in JSON
-n, --no-update   Disabilita il controllo automatico aggiornamenti
-v, --version     Mostra versione
-h, --help        Mostra questo messaggio
```

---

## Configurazione API Keys

Per abilitare la **Threat Intelligence**, aggiungi le chiavi al file `~/.gungnir.conf`:

```ini
VT_API_KEY     = la_tua_chiave_virustotal
SHODAN_API_KEY = la_tua_chiave_shodan
```

In alternativa, usa variabili d'ambiente (hanno priorità sul file):

```bash
export VT_API_KEY="..."
export SHODAN_API_KEY="..."
```

---

## Database locale

Gungnir salva automaticamente tutti i risultati in `~/.gungnir/data.db` (SQLite). Puoi consultare lo storico con:

```bash
./Gungnir history
./Gungnir history example.com
```

E generare un grafo JSON delle relazioni con:

```bash
./Gungnir graph -o grafo.json
```

Il formato JSON è compatibile con qualsiasi visualizzatore che supporta strutture Nodi/Archi (vis.js, d3.js, ecc.).

---

## Architettura

```
src/
  engine.cpp        — Dispatcher via unordered_map di executors
  database.cpp      — SQLite3 RAII wrapper (~/.gungnir/data.db)
  config.cpp        — Lettura ~/.gungnir.conf + env vars
  shell.cpp         — Shell interattiva con readline
  updater.cpp       — Update check asincrono (thread detached)

modules/
  network/
    network.cpp     — Scanner TCP asincrono con poll()
    http_client.cpp — HTTP(S) client via libcurl
  recon/
    recon.cpp       — DNS enum + WHOIS lookup
    threat_intel.cpp — VirusTotal + Shodan API
  scraper.cpp       — Web Scraper (titolo, header, email)
```

---

## Licenza

Questo progetto è rilasciato sotto licenza MIT.
