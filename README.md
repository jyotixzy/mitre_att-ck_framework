# Purpose: Yeh README project ka poora overview deta hai.
# Isme setup, folder structure, data flow, aur MITRE mapping logic ko Hinglish me explain kiya gaya hai.

## URL Analyzer MITRE Demo

Yeh project email `.eml` file ke andar se URLs nikalta hai, un par heuristic checks chalata hai, aur suspicious behavior ko MITRE ATT&CK Enterprise techniques aur mitigations ke saath map karta hai.

Is module ka goal full production detection banana nahi hai. Yeh ek clean, demo-level implementation hai jisme flow clear rahe, output understandable ho, aur MITRE mapping logically justified ho.

## Why Enterprise ATT&CK?

Hum yahan `MITRE ATT&CK Enterprise` dataset use kar rahe hain kyunki phishing link, malicious link aur user-execution wali techniques isi matrix me defined hoti hain. Email related link abuse ke liye yeh sahi ATT&CK source hai.

## Install

```bash
pip install attackcti pandas
```

## Run

1. Pehle database initialize ya refresh karo:

```bash
python3 main.py init-db
```

2. Phir email analyze karo:

```bash
python3 main.py analyze /path/to/email.eml
```

Example:

```bash
python3 main.py analyze /home/jyoti/Downloads/sample.eml
```

## Folder Structure

- `main.py`
  Project ka top-level entry point hai. User jo command run karta hai, woh yahin se start hoti hai aur CLI module ko handoff hota hai.

- `url_analyzer/config.py`
  Is file me static configuration rakhi gayi hai. Yahin hardcoded heuristic-to-technique mapping, suspicious TLDs, shortener domains, aur payload extensions defined hain.

- `url_analyzer/eml_parser.py`
  Yeh `.eml` file ko read karke email body ke text/plain aur text/html sections se URLs extract karta hai.

- `url_analyzer/heuristics.py`
  Is file me URL par chalne wale heuristic checks hain. Yeh decide karta hai ki kaunsa URL suspicious hai aur uska kaunsa ATT&CK technique mapping hona chahiye.

- `url_analyzer/mitre_loader.py`
  Yeh MITRE ATT&CK Enterprise data fetch karta hai. Phir selected techniques aur unki mitigations ko parse karke SQLite ke liye rows banata hai.

- `url_analyzer/db.py`
  Yeh SQLite database create, replace aur query karne ka kaam karta hai. Saari local ATT&CK mapping storage yahin manage hoti hai.

- `url_analyzer/service.py`
  Yeh orchestration layer hai. Parser, heuristics, MITRE loader aur DB logic ko jodkar actual flow execute karta hai.

- `url_analyzer/cli.py`
  Yeh command-line interface hai. `init-db` aur `analyze` commands ko yeh parse aur run karta hai.

- `tests/test_url_analyzer.py`
  Basic tests hain jo verify karte hain ki `.eml` parsing aur core heuristics sahi kaam kar rahe hain.

## Core Idea

Is project ka sabse important design point yeh hai:

`data_source se technique_id directly discover nahi hota`

Correct flow yeh hai:

1. URL me suspicious pattern detect hota hai
2. Us pattern ko hardcoded rule se ek `technique_id` assign hota hai
3. Usi rule ke saath ek relevant `data_source` bhi attach hota hai
4. Phir ATT&CK dataset se us technique ke linked mitigations nikaale jate hain

Matlab:

`URL behavior -> technique_id + data_source -> mitigations + tactic context`

## Detailed Data Flow

### Phase 1: Database Initialization

Command:

```bash
python3 main.py init-db
```

Is phase me kya hota hai:

1. CLI command `init-db` receive hoti hai.
2. Control `service.py` ke `sync_attack_database()` function ko jata hai.
3. Yeh `mitre_loader.py` ko call karta hai.
4. `mitre_loader.py` pehle `attackcti` se ATT&CK Enterprise data fetch karne ki koshish karta hai.
5. Agar TAXII endpoint fail kare, to code official static Enterprise STIX JSON se fallback load karta hai.
6. Bundle ke andar se teen major object types nikaale jate hain:
   - techniques (`attack-pattern`)
   - mitigations (`course-of-action`)
   - relationships (`relationship`)
7. Sirf wahi techniques select hoti hain jo URL analyzer ke hardcoded heuristic rules me mapped hain.
8. Har selected technique ke saath linked mitigation relationships resolve ki jati hain.
9. Har technique ke liye usse associated hardcoded data sources attach kiye jate hain.
10. Final rows SQLite DB me save hoti hain.

SQLite table columns:

- `tactics`
- `technique_id`
- `technique_name`
- `mitigation_id`
- `mitigation_description`
- `data_source`

## Phase 2: Email Analysis

Command:

```bash
python3 main.py analyze /path/to/file.eml
```

Is phase me flow yeh hai:

1. CLI `analyze` command read karta hai.
2. `service.py` ka `analyze_email()` function call hota hai.
3. Agar SQLite DB empty ho, to code auto-sync try karta hai.
4. `eml_parser.py` email ko parse karta hai.
5. `text/plain` aur `text/html` parts se saare URLs nikale jate hain.
6. Duplicate URLs remove kiye jate hain.
7. `heuristics.py` har URL par suspicious checks chalata hai.
8. Har matched check ke liye:
   - `technique_id`
   - `technique_name`
   - `data_source`
   assign hota hai.
9. Phir detected `(technique_id, data_source)` pairs DB me lookup hote hain.
10. SQLite se us technique ke mitigation rows fetch hoti hain.
11. CLI final grouped JSON output print karta hai.

## Heuristic Detection Flow

Abhi code me yeh heuristics lage hue hain:

- `shortener_domain`
  Agar hostname known shortener ho, jaise `bit.ly` ya `tinyurl.com`

- `ip_literal_host`
  Agar URL hostname direct IP address ho

- `punycode_domain`
  Agar domain me `xn--` present ho

- `suspicious_tld`
  Agar domain suspicious TLD use kare, jaise `.top`, `.xyz`, `.click`

- `credential_lure_keywords`
  Agar URL string me `login`, `verify`, `reset`, `password` jaise keywords ho

- `downloadable_payload`
  Agar URL path `.exe`, `.zip`, `.msi`, `.js` jaise payload extension par end ho

- `redirect_parameter`
  Agar query string me `redirect`, `url`, `target`, `next` jaise parameters ho

## Data Source Ka Role

Data source ka matlab attack nahi hota. Data source bas yeh batata hai ki kis type ke telemetry ya logs se us technique ka evidence mil sakta hai.

Examples:

- `Application Log: Email Gateway`
  Email gateway ya mail security logs me suspicious URL evidence

- `Network Traffic: Network Connection Creation`
  User system ne kis IP/domain se connection banaya

- `Domain Name: Domain Registration`
  Domain khud suspicious ya abnormal registration traits dikhata hai

## Current Output Format

Output grouped JSON me aata hai:

```json
[
  {
    "tactics": "Initial Access",
    "technique_id": "T1566.002",
    "technique_name": "Phishing: Spearphishing Link",
    "data_source": "Application Log: Email Gateway",
    "mitigations": [
      {
        "mitigation_id": "M1017",
        "mitigation_description": "..."
      }
    ]
  }
]
```

Yahan ek technique/data source combination ke andar multiple mitigations grouped hoti hain, isliye output clean aur demo-friendly rehta hai.

## Important Limitation

Yeh tool abhi static heuristic module hai. Isme:

- live URL expansion nahi hai
- WHOIS/domain age lookup nahi hai
- HTML anchor text mismatch check nahi hai
- redirect chain resolution nahi hai
- reputation feeds ka integration nahi hai

Demo ke liye yeh sufficient hai, lekin production-grade URL analyzer ke liye aur layers add karni hongi.

## Summary

Short flow:

`.eml file -> URL extraction -> heuristic checks -> technique mapping -> SQLite mitigation lookup -> grouped JSON output`

Yahi is project ka end-to-end working model hai.
