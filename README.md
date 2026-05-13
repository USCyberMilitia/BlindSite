# BlindSite: High-Risk Investigations Platform & Forensic Browser
<img width="2305" height="1397" alt="image" src="https://github.com/user-attachments/assets/e95c6f29-61da-4ee0-9d95-9a2dc4627404" />

**Preserve what investigators should not have to see.**

## Major update: security + performance hardening

BlindSite has received a major security and performance hardening update.

The live capture engine has been reworked so blocked media is no longer processed directly in the browser’s hot request path. Instead, risky media is blocked from display immediately and preserved in the background when enabled. In testing, this improved page-load performance by up to **70%** on media-heavy dynamic sites.

This update also strengthens the custody model with hard-sealed evidence workflows for both Civilian Unknown Master Key mode and Organization hard-sealed media preservation. Sensitive originals can be preserved encrypted in a way that the local vault key cannot decrypt, requiring the correct escrow/reviewer private key for authorized recovery.

A new standalone validation suite is also available to test core technical claims around encrypted storage, hard-sealed custody, wrong-key failure, sealed exports, reviewer recovery, audit-chain tamper detection, and storage-hash tamper detection.

A secure key generator for organizations and those testing BlindSite. It is critical this generator is used only by organization or individuals that understand the risks or those wanting to test out BlindSite. For normal Civilian workflows please use Civilian Unknown Master Key Mode with the prefilled key.

Our public key has changed. Please check below for the correct key though it should be filled in for you automatically for Civilian mode.

This is still early-access software, but this update is a major step toward making BlindSite faster, safer, and easier to verify.

> [!WARNING]
> **Early Access / Use at Your Own Risk**
>
> BlindSite is an early-access public-interest tool and may contain bugs, vulnerabilities, incomplete documentation, or workflow issues that could create legal, operational, forensic, or security risk.
>
> We have tested it against our intended workflows and it performs well for our use cases, but it has not yet undergone independent security review, forensic validation, or legal certification.
>
> Do not use BlindSite for live operations, sensitive investigations, or evidence-handling workflows unless you understand the risks, test it in a controlled environment, and have appropriate legal/organizational authorization.
>
> Use a fresh VM or dedicated investigation machine. Do not run high-risk investigations from a personal device or everyday browser profile.


BlindSite is a forensic browser and encrypted evidence vault for high-risk digital investigations.

It is built for situations where simply visiting a site, viewing media, or manually saving content could create legal, psychological, or operational risk.

BlindSite can capture modern web pages, preserve images/videos/audio as encrypted evidence, block dangerous media from the investigator’s screen, support clear web and darknet workflows, and create sealed evidence packages for authorized reviewers or law enforcement. Think Hunchly but open-source and with more features.

Most tools force investigators into a bad choice:

> **See the content to preserve it, or block it and lose it.**

BlindSite creates a third option:

> **Block it from the user, preserve it encrypted, and reveal it only to authorized reviewers later.**

---

## Why BlindSite matters

BlindSite is designed for journalists, attorneys, investigators, nonprofits, agencies, and public-interest researchers who need to preserve digital evidence safely.

It helps protect:

- investigators from unnecessary exposure;
- evidence from being lost;
- cases from weak custody records;
- review workflows from unsafe remote callbacks;
- organizations from uncontrolled access to sensitive material.

---

## Top features

### 1. Blind / sealed media preservation

Images, videos, and audio can be blocked from the user’s screen while still being preserved encrypted in the evidence vault.

That means investigators can capture high-risk pages without casually viewing or handling sensitive media in plaintext.

---

### 2. Civilian Unknown Master Key mode

In this custody mode, the civilian user does **not** possess the master reveal key.

They can preserve evidence, but they cannot locally reveal, export, or casually view dangerous originals.

The evidence can later be handed off as a sealed package to an authorized reviewer.

---

### 3. Organization-Controlled Key mode

Organizations can control their own master key and decide who can unlock, review, export, or preserve evidence.

This is useful for:

- agencies;
- law firms;
- nonprofits;
- newsrooms;
- internal investigation teams.

---

### 4. Sealed evidence export

BlindSite can export a sealed case package containing:

- encrypted evidence objects;
- metadata;
- hashes;
- audit records;
- page captures;
- blocked-media records;
- wrapped keys.

The ZIP does **not** include plaintext originals by default.

---

### 5. Law-enforcement / cleared reviewer viewer

Authorized reviewers can import a sealed evidence package, decrypt it with the escrow/private key, and browse recovered pages and media in a clean case viewer.

The reviewer can inspect captured pages without manually digging through hundreds of raw files.

---

### 6. Dynamic page capture and reconstruction

BlindSite can capture modern pages with images, video, lazy-loaded content, and dynamic media.

Recovered pages can be rendered locally using saved evidence objects instead of calling back to the live site.

---

### 7. Tor-aware controlled browser sessions

BlindSite supports controlled live browsing workflows, including:

- Tor-based modes;
- manual capture;
- automatic capture;
- media-blocking policies;
- encrypted media preservation.

---

### 8. Audit chain and audit seals

Important actions are logged into an audit chain.

BlindSite can also create audit/storage seals: cryptographic checkpoints showing what the audit log and evidence vault looked like at a specific moment.

This makes later tampering easier to detect.

---

## Install dependencies

Use Python 3.10+.

```bash
python -m pip install --upgrade \
  fastapi \
  "uvicorn[standard]" \
  "requests[socks]" \
  beautifulsoup4 \
  cryptography \
  itsdangerous \
  pillow \
  playwright \
  python-multipart
```

Install Playwright browsers:

```bash
python -m playwright install chromium firefox
```

On some Linux systems, you may also need:

```bash
python -m playwright install-deps
```

---

## Run BlindSite

```bash
python BlindSite.py
```

Default local address:

```text
http://127.0.0.1:8765
```

First-run default login:

```text
Username: admin
Password: change-me-now
```

Change the password during setup.

---

## First-run setup

On first run, BlindSite lets you choose a custody mode.

---

### Organization-Controlled Key

Use this when an organization controls the master reveal key.

Best for:

- agencies;
- legal teams;
- nonprofits;
- newsrooms;
- internal investigation teams.

---

### Civilian Unknown Master Key

For USCM Civilian Unknown Master Key handoff workflows, you MUST use the USCM escrow public key below.

Do **not** use your own key for Civilian Unknown Master Key mode.

The purpose of this mode is that the civilian collector can preserve evidence while lacking the local ability to decrypt or reveal the original material. If you generate or control the private key yourself, that custody separation no longer exists.

If you want the intended Civilian Unknown Master Key workflow, use the USCM escrow public key.

**Never publish or upload your private key.**

```text
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1y8+WnLXjlnuV+HqL/yM
/pGqYkbYzYf0AkoxtUdb8nOjfUPtiDq0dcvMqXkAuHK625lyf1Bq0j8wJai766XG
04ZnZCcK1m4Yw0WMkQEjcn2qlWZB7vniQs07i92pd4EswK9SkCLzCAvDXq3n2xE3
FTLuqGKnjZcr/1uFpUWcsVGUqZ7fYnPIjNtRPiOCUs/i9kJ6ryKsLoOMx7PgvI8f
6HHWwcbh5bdeHXi/P+ntri4EbBPqlnMWdYUeF6SuvlhgLwTt1wSzO9ZHic1iCF4G
hNIoNhbxolBSD41BsuvntXUfebqymWskGbiITLE8plHyrUminzqnZXAkSnOEBqaF
duDHHCiqLxI71KO+rUZ73IbOBy0a0cJCIJ/qeYh7G8NMyW6PfcCw+TTbsXLZkHI6
Vl6hfZaoJvZ43/SPt/YwL7FOq+Aef3GHTqHoX/HTR5txHzvH+gApIDs3kFKjwd7D
yElca3eFGGQM4cijcSpazFVHycZYGOL/DbKxHUjsnYBR5yhPYgDvAz0o+RsKK5ws
SspvPQ4+DFUDQK4zkj/ZAbrsrdsZtQn51yRXcFfNCUrhUCoEivTmJzq8WGOTsIqA
taLsgBIqjLIc+fWr4+CNKSGRnkXAWCe+ebmokCZeDAHpwgX/BrLnjr62v+jJnJ46
cyO7zcKE0wuSAXZ1+tPKP+UCAwEAAQ==
-----END PUBLIC KEY-----
```

When you create a **Sealed LEO Export**, agencies or cleared reviewers can request the decryption/review key from USCM if the USCM escrow public key was used.

Best for:

- civilian handoff workflows;
- sensitive investigations;
- sealed evidence preservation;
- cases where the collector should preserve evidence without being able to reveal it locally.

---

## Basic workflow

1. Create a case.
2. Start a controlled browser session.
3. Browse the target page.
4. Capture the page.
5. BlindSite preserves page data, media records, hashes, and audit events.
6. Blocked media can be preserved encrypted if sealed preservation is enabled.
7. Export a sealed evidence package.
8. Authorized reviewer imports and decrypts the sealed package.
9. Reviewer views recovered pages and media in the local case viewer.

---

## Important safety model

BlindSite is not just a web scraper.

It is built around a custody principle:

> **Preserve first. Expose only when authorized.**

The tool is designed so dangerous media can be:

- blocked from the investigator;
- saved encrypted;
- included in sealed export;
- reviewed later by someone with proper authority and keys.

---

## Project status

BlindSite is an active public-interest forensic safety project.

It is intended for lawful, authorized investigations, evidence preservation, legal review, journalism, nonprofit accountability work, and agency workflows.

The goal is simple:

> **Investigators should not have to be harmed by the evidence they are trying to preserve.**
