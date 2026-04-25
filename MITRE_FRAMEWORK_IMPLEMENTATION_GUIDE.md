# Purpose: Yeh document tumhare poore email security system me MITRE ATT&CK framework ko kaise implement karna hai, uska end-to-end guide hai.
# Isme sirf URL analyzer nahi, balki saare 5 modules ke liye recommended checks, technique mappings, data sources aur architecture explain ki gayi hai.
# Yeh document demo-level implementation aur future enterprise-style expansion dono ko dhyan me rakhkar likha gaya hai.

## MITRE Framework Implementation Guide For Email Security System

Yeh document tumhare email security system ke 5 modules ko MITRE ATT&CK Enterprise framework ke saath map karne ka practical guide hai.

Covered modules:

1. `Header Analyzer`
2. `Sender Reputation`
3. `Text Intelligence`
4. `URL Analyzer`
5. `Attachment Scanner`

## Sabse Important Baat

MITRE ATT&CK ko system me directly "install" nahi kiya jata.

Sahi implementation approach yeh hoti hai:

`Email scan -> signals detect karo -> signals ko normalize karo -> unko MITRE techniques se map karo -> mitigations aur tactic context attach karo -> final alert/report banao`

Matlab MITRE ATT&CK tumhare system ka **detection engine** nahi hai.
MITRE ATT&CK tumhare system ka **mapping + enrichment + reporting framework** hai.

## Correct High-Level Flow

1. Email receive hoti hai
2. Saare modules apna-apna scan chalate hain
3. Har module suspicious signals detect karta hai
4. Signals ek common format me normalize hote hain
5. Correlation / scoring engine overall verdict nikalta hai
6. MITRE mapping engine relevant ATT&CK technique IDs assign karta hai
7. Local ATT&CK database se:
   - tactic
   - technique name
   - mitigation IDs
   - mitigation descriptions
   fetch hoti hain
8. Final JSON alert / SOC report / dashboard output banta hai

## Why Enterprise ATT&CK?

Email phishing, malicious links, malicious attachments, social engineering aur user execution se related techniques `MITRE ATT&CK Enterprise` matrix me milti hain. Isliye tumhare email security system ke liye Enterprise ATT&CK sahi matrix hai.

## Demo-Level vs Better Architecture

### Demo-level implementation

Yeh tum abhi kar sakti ho:

- Har module ke checks define karo
- Har check ko hardcoded technique ID se map karo
- ATT&CK dataset se mitigation details local DB me store karo
- Final output me MITRE tactic/technique/mitigation dikhado

### Better implementation

Yeh later phase me kar sakti ho:

- Multiple signals combine karo
- Confidence score do
- Signal correlation ke basis par technique choose karo
- False positive reduction karo

## Recommended Full System Data Flow

```text
Incoming Email (.eml)
        |
        v
--------------------------------------------------
| Header Analyzer | Sender Reputation | Text NLP |
| URL Analyzer    | Attachment Scan           |
--------------------------------------------------
        |
        v
Module-wise Signals / Findings
        |
        v
Signal Normalization Layer
        |
        v
Correlation + Risk Scoring Engine
        |
        v
MITRE Mapping Engine
        |
        v
Local ATT&CK SQLite Database Lookup
        |
        v
Technique + Tactic + Mitigation Enrichment
        |
        v
Final JSON / Dashboard / Analyst Report
```

## After Scanning: Actual Data Flow

Jab saare modules scan complete kar lete hain, tab recommended flow yeh hona chahiye:

```text
Header findings
Sender findings
Text findings
URL findings
Attachment findings
        |
        v
Common findings list
        |
        v
Each finding format:
{
  "module": "...",
  "signal_name": "...",
  "severity": "...",
  "confidence": 0.00,
  "evidence": {...}
}
        |
        v
MITRE signal-to-technique mapping
        |
        v
Fetch technique details and mitigations from SQLite
        |
        v
Return enriched alert
```

## Current URL Analyzer DB Columns

Abhi jo tumne URL analyzer ke liye DB use kiya hai, uske columns yeh hain:

- `tactics`
- `technique_id`
- `technique_name`
- `mitigation_id`
- `mitigation_description`
- `data_source`

Yeh URL-only demo ke liye sufficient hai.

## Recommended Full Email Security DB Schema

Agar tum poore 5-module system ke liye generalized MITRE implementation banana chahti ho, to recommended schema yeh ho sakta hai:

- `module_name`
- `signal_name`
- `signal_description`
- `tactics`
- `technique_id`
- `technique_name`
- `mitigation_id`
- `mitigation_description`
- `data_source`
- `severity`
- `confidence`
- `evidence_example`

Isme:

- `module_name` batayega signal kis module ne generate kiya
- `signal_name` exact detection rule ka naam hoga
- `severity` rule ki seriousness dikhayega
- `confidence` mapping confidence dikhayega
- `evidence_example` sample IOC ya sample finding ho sakti hai

## Core Implementation Logic

Saare modules me recommended MITRE implementation logic same rahega:

1. Module suspicious check run karega
2. Check hit hone par ek normalized signal banega
3. Us signal ko hardcoded rule table ya rule engine ke through MITRE technique assign hogi
4. Technique ID ke basis par local ATT&CK DB se mitigation aur tactic fetch honge
5. Final result output me dikhega

Short formula:

`Check hit -> Signal -> Technique ID -> DB lookup -> Mitigations -> Final output`

## Module 1: Header Analyzer

### Is module ka kaam

Yeh email headers inspect karta hai aur spoofing, sender mismatch, authentication failure aur routing anomalies ko detect karta hai.

### Recommended checks and MITRE mapping

#### 1. `spf_fail`

Meaning:
Sender Policy Framework validation fail hui.

Example:
- Claimed sender: `support@paypal.com`
- Sending IP SPF authorized nahi hai

Suggested MITRE mapping:
- `T1566` - Phishing

Why:
SPF fail directly phishing prove nahi karta, lekin phishing detection context me strong indicator ho sakta hai.

Suggested data source examples:
- `Application Log: Email Gateway`
- `Email Metadata`

#### 2. `dkim_fail`

Meaning:
DKIM signature invalid ya missing hai.

Example:
- Header me DKIM signature present hai but validation fail ho gaya

Suggested MITRE mapping:
- `T1566` - Phishing

Suggested data source examples:
- `Application Log: Email Gateway`
- `Email Metadata`

#### 3. `dmarc_fail`

Meaning:
Sender domain alignment fail hua.

Example:
- `From:` domain aur authentication alignment mismatch

Suggested MITRE mapping:
- `T1566` - Phishing

Suggested data source examples:
- `Application Log: Email Gateway`
- `Email Metadata`

#### 4. `reply_to_mismatch`

Meaning:
`From` address aur `Reply-To` address alag suspicious domains par hain.

Example:
- `From: hr@company.com`
- `Reply-To: hr-team-payroll@outlook-secure.top`

Suggested MITRE mapping:
- `T1566` - Phishing

Suggested data source examples:
- `Email Metadata`
- `Application Log: Email Gateway`

#### 5. `display_name_spoofing`

Meaning:
Display name trusted brand/person jaisa hai but actual email unrelated hai.

Example:
- Display name: `Microsoft Security`
- Email: `alert-center@randomdomain.xyz`

Suggested MITRE mapping:
- `T1036` - Masquerading
- `T1566` - Phishing

Suggested data source examples:
- `Email Metadata`
- `Application Log: Email Gateway`

## Module 2: Sender Reputation

### Is module ka kaam

Yeh sender domain, sender IP aur sending infrastructure ki trustworthiness check karta hai.

### Recommended checks and MITRE mapping

#### 1. `newly_registered_domain`

Meaning:
Sender domain bahut recently register hua hai.

Example:
- Domain age: 2 days

Suggested MITRE mapping:
- `T1583.001` - Acquire Infrastructure: Domains

Why:
Attacker phishing ke liye naya domain acquire karta hai.

Suggested data source examples:
- `Domain Name: Domain Registration`
- `WHOIS / Registrar Data`

#### 2. `low_reputation_sender_domain`

Meaning:
Sender domain suspicious ya poor reputation score par hai.

Example:
- Domain abuse feed me flagged hai

Suggested MITRE mapping:
- `T1583.001` - Acquire Infrastructure: Domains
- `T1566` - Phishing

Suggested data source examples:
- `Domain Name: Domain Registration`
- `Threat Intelligence`

#### 3. `blacklisted_sender_ip`

Meaning:
Mail sending IP blacklist / blocklist me present hai.

Example:
- Sending IP known spam source hai

Suggested MITRE mapping:
- `T1583.005` - Acquire Infrastructure: Botnet
- `T1566` - Phishing

Suggested data source examples:
- `Network Traffic: Network Connection Creation`
- `Threat Intelligence`

#### 4. `lookalike_domain`

Meaning:
Sender domain legit brand jaisa lagta hai but exact nahi hota.

Example:
- `micr0soft-support.com`
- `paypa1-billing.com`

Suggested MITRE mapping:
- `T1036` - Masquerading
- `T1566` - Phishing

Suggested data source examples:
- `Domain Name: Domain Registration`
- `Email Metadata`

## Module 3: Text Intelligence

### Is module ka kaam

Yeh email body text ko inspect karta hai aur social engineering, urgency, credential theft intent ya invoice fraud patterns detect karta hai.

### Recommended checks and MITRE mapping

#### 1. `credential_harvest_language`

Meaning:
Email body me login, password verify, account unlock, reset type language ho.

Example text:
- "Please verify your account immediately"
- "Reset your password to avoid suspension"

Suggested MITRE mapping:
- `T1566` - Phishing
- `T1566.002` - Spearphishing Link, agar URL bhi ho

Suggested data source examples:
- `Application Log: Email Gateway`
- `Email Content`

#### 2. `urgent_action_language`

Meaning:
Body me pressure / urgency wording ho.

Example text:
- "Immediate action required"
- "Respond within 30 minutes"

Suggested MITRE mapping:
- `T1566` - Phishing

Suggested data source examples:
- `Email Content`
- `Application Log: Email Gateway`

#### 3. `invoice_payment_fraud_language`

Meaning:
Invoice, payment release, wire transfer, bank update type suspicious business-email-compromise language.

Example text:
- "Please release payment urgently"
- "Updated bank details attached"

Suggested MITRE mapping:
- `T1656` - Impersonation
- `T1566` - Phishing

Suggested data source examples:
- `Email Content`
- `Application Log: Email Gateway`

#### 4. `brand_impersonation_text`

Meaning:
Trusted brand naam use hua ho to increase trust.

Example text:
- "Microsoft account security alert"
- "PayPal security verification required"

Suggested MITRE mapping:
- `T1036` - Masquerading
- `T1566` - Phishing

Suggested data source examples:
- `Email Content`
- `Email Metadata`

## Module 4: URL Analyzer

### Is module ka kaam

Yeh email ke andar embedded URLs ko inspect karta hai aur suspicious link patterns detect karta hai.

### Current checks and MITRE mapping

#### 1. `shortener_domain`

Example:
- `https://bit.ly/reset-password`

Mapped technique:
- `T1566.002` - Phishing: Spearphishing Link

Data source example:
- `Application Log: Email Gateway`

#### 2. `ip_literal_host`

Example:
- `http://45.67.12.90/login`

Mapped technique:
- `T1566.002` - Phishing: Spearphishing Link

Data source example:
- `Network Traffic: Network Connection Creation`

#### 3. `punycode_domain`

Example:
- `https://xn--pple-43d.com/login`

Mapped technique:
- `T1566.002` - Phishing: Spearphishing Link

Data source example:
- `Domain Name: Domain Registration`

#### 4. `suspicious_tld`

Example:
- `https://secure-login.top/verify`

Mapped technique:
- `T1566.002` - Phishing: Spearphishing Link

Data source example:
- `Application Log: Email Gateway`

#### 5. `credential_lure_keywords`

Example:
- `https://portal.example.com/reset-password`

Mapped technique:
- `T1566.002` - Phishing: Spearphishing Link

Data source example:
- `Application Log: Email Gateway`

#### 6. `downloadable_payload`

Example:
- `http://example.com/update.exe`

Mapped technique:
- `T1204.001` - User Execution: Malicious Link

Data source example:
- `Network Traffic: Network Connection Creation`

#### 7. `redirect_parameter`

Example:
- `https://safe-site.com/login?redirect=http://bad.test`

Mapped technique:
- `T1566.002` - Phishing: Spearphishing Link

Data source example:
- `Network Traffic: Network Connection Creation`

## Module 5: Attachment Scanner

### Is module ka kaam

Yeh email attachments ko inspect karta hai aur suspicious file types, macros, executable content aur evasive packaging detect karta hai.

### Recommended checks and MITRE mapping

#### 1. `macro_enabled_office_file`

Meaning:
Macro-enabled Office document mila.

Example:
- `invoice.xlsm`
- `salary_review.docm`

Suggested MITRE mapping:
- `T1566.001` - Phishing: Spearphishing Attachment
- `T1204.002` - User Execution: Malicious File

Suggested data source examples:
- `File: File Metadata`
- `Application Log: Email Gateway`

#### 2. `executable_attachment`

Meaning:
Attachment direct executable hai.

Example:
- `update.exe`
- `runme.scr`

Suggested MITRE mapping:
- `T1566.001` - Phishing: Spearphishing Attachment
- `T1204.002` - User Execution: Malicious File

Suggested data source examples:
- `File: File Metadata`
- `Application Log: Email Gateway`

#### 3. `password_protected_archive`

Meaning:
Attachment encrypted archive hai jise scanner easily inspect nahi kar sakta.

Example:
- `invoice.zip` with password in email body

Suggested MITRE mapping:
- `T1566.001` - Phishing: Spearphishing Attachment

Suggested data source examples:
- `File: File Metadata`
- `Email Content`

#### 4. `double_extension_filename`

Meaning:
Filename deceptive ho, jaise `.pdf.exe`

Example:
- `invoice.pdf.exe`
- `report.docx.scr`

Suggested MITRE mapping:
- `T1036.007` - Masquerading: Double File Extension

Suggested data source examples:
- `File: File Metadata`
- `Application Log: Email Gateway`

#### 5. `mime_extension_mismatch`

Meaning:
File extension aur actual MIME type mismatch kare.

Example:
- Filename `.pdf`, actual content executable

Suggested MITRE mapping:
- `T1036` - Masquerading
- `T1566.001` - Phishing: Spearphishing Attachment

Suggested data source examples:
- `File: File Metadata`
- `File: File Content`

## Example: Full Multi-Module Signal Collection

Suppose ek email me yeh sab mila:

- SPF fail
- Sender domain newly registered
- Body me "verify account now" text
- URL is `https://bit.ly/reset-password`
- Attachment is `invoice.xlsm`

To module outputs kuch aise honge:

```json
[
  {
    "module": "header_analyzer",
    "signal_name": "spf_fail",
    "severity": "medium",
    "confidence": 0.65
  },
  {
    "module": "sender_reputation",
    "signal_name": "newly_registered_domain",
    "severity": "high",
    "confidence": 0.82
  },
  {
    "module": "text_intelligence",
    "signal_name": "credential_harvest_language",
    "severity": "high",
    "confidence": 0.79
  },
  {
    "module": "url_analyzer",
    "signal_name": "shortener_domain",
    "severity": "high",
    "confidence": 0.88
  },
  {
    "module": "attachment_scanner",
    "signal_name": "macro_enabled_office_file",
    "severity": "critical",
    "confidence": 0.93
  }
]
```

## Example: MITRE Enrichment After Mapping

Above findings ko map karne ke baad final enriched output kuch aisa ho sakta hai:

```json
[
  {
    "module": "url_analyzer",
    "signal_name": "shortener_domain",
    "tactics": "Initial Access",
    "technique_id": "T1566.002",
    "technique_name": "Phishing: Spearphishing Link",
    "data_source": "Application Log: Email Gateway",
    "mitigations": [
      {
        "mitigation_id": "M1017",
        "mitigation_description": "User training to identify social engineering attempts."
      }
    ]
  },
  {
    "module": "attachment_scanner",
    "signal_name": "macro_enabled_office_file",
    "tactics": "Initial Access, Execution",
    "technique_id": "T1566.001",
    "technique_name": "Phishing: Spearphishing Attachment",
    "data_source": "File: File Metadata",
    "mitigations": [
      {
        "mitigation_id": "M1049",
        "mitigation_description": "Antivirus/Antimalware based protection."
      }
    ]
  }
]
```

## How To Implement In Code

Recommended implementation pieces:

1. `module scanners`
   - har module checks run kare

2. `signal normalizer`
   - har finding ko common JSON schema me convert kare

3. `mitre_mapping_config`
   - `signal_name -> technique_id + data_source` mapping rakhe

4. `attack_db_loader`
   - ATT&CK Enterprise se technique, tactic aur mitigations SQLite me store kare

5. `enrichment engine`
   - signal ke technique_id se DB lookup kare

6. `final output formatter`
   - analyst-friendly JSON / dashboard record banaye

## Recommended Mapping Strategy

Abhi tumhare project ke liye best strategy yeh hai:

- Start with hardcoded rule-based mapping
- Har module ke 4-8 strong checks define karo
- Har check ka 1 ya 2 most relevant MITRE techniques choose karo
- Final output me evidence + module + technique + mitigation dikhayo

Yeh approach:

- simple hai
- explainable hai
- viva-friendly hai
- demo ke liye strong hai

## Important Caution

Yeh yaad rakhna:

- Ek signal ka sirf ek hi correct MITRE technique hamesha nahi hota
- MITRE mapping often contextual hoti hai
- Module findings ko blindly ATT&CK se one-to-one treat nahi karna chahiye

Best practice:

- `suggested mapping`
- `most relevant mapping`
- `confidence-based mapping`

yeh language use karo

## Final Summary

Tumhare full email security system me MITRE implementation ka best model yeh hoga:

```text
Email
-> 5 modules scan
-> findings collect
-> normalized signals
-> MITRE technique mapping
-> local ATT&CK DB lookup
-> tactic + mitigation enrichment
-> final report / JSON output
```

