# BlindSite
BlindSite: High-Risk Investigations Platform &amp; Forensic Browser

````markdown
# BlindSite: Investigation Vault & Forensic Browser

**Preserve what investigators should not have to see.**

BlindSite is a forensic browser and encrypted evidence vault built for high-risk digital investigations. It can capture modern web pages, preserve images/videos/audio as encrypted evidence, block dangerous media from the investigator’s screen, and create sealed evidence packages for authorized reviewers or law enforcement.

Most tools force investigators into a bad choice:

> **See the content to preserve it, or block it and lose it.**

BlindSite creates a third option:

> **Block it from the user, preserve it encrypted, and reveal it only to authorized reviewers later.**

---

## Why BlindSite matters

BlindSite is designed for journalists, attorneys, investigators, nonprofits, agencies, and public-interest researchers who need to preserve digital evidence safely.

It helps protect:

- the investigator from unnecessary exposure;
- the evidence from being lost;
- the case from weak custody records;
- the review process from remote callbacks and unsafe browsing.

---

## Top features

### 1. Blind / sealed media preservation

Images, videos, and audio can be blocked from the user’s screen while still being preserved encrypted in the evidence vault.

That means investigators can capture high-risk pages without casually viewing or handling sensitive media in plaintext.

---

### 2. Civilian Unknown Master Key mode

In this custody mode, the civilian user does **not** possess the master reveal key.

They can preserve evidence, but they cannot locally reveal, export, or casually view dangerous originals. The evidence can later be handed off as a sealed package to an authorized reviewer.

---

### 3. Organization-Controlled Key mode

Organizations can control their own master key and decide who can unlock, review, export, or preserve evidence.

This is useful for agencies, law firms, nonprofits, newsrooms, and investigation teams that need internal access controls.

---

### 4. Sealed evidence export

BlindSite can export a sealed case package containing encrypted evidence objects, metadata, hashes, audit records, page captures, blocked-media records, and wrapped keys.

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

BlindSite supports controlled live browsing workflows, including Tor-based modes, manual capture, automatic capture, and media-blocking policies.

---

### 8. Audit chain and audit seals

Important actions are logged into an audit chain. BlindSite can also create audit/storage seals: cryptographic checkpoints showing what the audit log and evidence vault looked like at a specific moment.

This makes later tampering easier to detect.

---

## Install dependencies

Use Python 3.10+.

```bash
python -m pip install --upgrade fastapi "uvicorn[standard]" "requests[socks]" beautifulsoup4 cryptography itsdangerous pillow playwright python-multipart
````

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
python blindsite.py
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

On first run, BlindSite lets you choose a custody mode:

### Organization-Controlled Key

Use this when an organization controls the master reveal key.

Best for:

* agencies;
* legal teams;
* nonprofits;
* newsrooms;
* internal investigation teams.

### Civilian Unknown Master Key

Use this when the collector should not know or possess the reveal key. Simply enter the below public key in form.

-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAz/WNWKXWO4DekWR/h3SC
+e7XFKQJezoe6MjQder8dv45j/f3/xy+Qnfk/ojfPn04D12iL3oy1sa98vwpiMY1
+EuGkiutjm0w/3mgzF8DU2wP71eL/Jt1z+6OANzNRGb/WU3nFiqMaPiBW911iRsk
lWAov+kKT6IUF7cTE12f9PuFatjOLIa5rXUShfsiaKSpHWxiLHI1tfBYo+cZw8UH
tf0JW1Ff7gdy+9g6bMf9WGRhxKkdF0hTzhfg7Ol47T8WHy4jqcjtUV2vD41CNtvM
k1N/uGTdYTV0H71gFkLxft/unXB5K5hu4xCQUiyZFx8VUJREy9RKresEX9bsqZ/x
fkKFly1EwxDsHKwVr6PZ7eG+fCs62Q5VzzrM99k0R0vlPEFE0EE1BiIIuGCCA877
6jHBcYudRK8kMFJe68nghAaVzjHjyczLeTr/KfesDTgSwuAYpmYKNaiZNytsmdml
mH3BxBGoOj3TtbI4X8YEtWRROvgKslhy5ctMWkKcWFwKL2jPVICC9vSwUbkH+/wI
XyGnhQjiam67kqy0DZfVzvQu8ACWNzxjblVt0AVXFc6kBrwV+Agz0fTcNeetOP0I
X+dFQEOZXhMVjstoL+UIKK60D7pUPhE0/Na6XDrI8qTBKSJN9lSyoW5groL9mu5S
P6ySgUcZiWET2NW9qQzMKP0CAwEAAQ==
-----END PUBLIC KEY-----

Best for:

* civilian handoff workflows;
* sensitive investigations;
* sealed evidence preservation;
* cases where the collector should preserve evidence without being able to reveal it locally.

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

* blocked from the investigator;
* saved encrypted;
* included in sealed export;
* reviewed later by someone with proper authority and keys.

---

## Project status

BlindSite is an active public-interest forensic safety project.

It is intended for lawful, authorized investigations, evidence preservation, legal review, journalism, nonprofit accountability work, and agency workflows.

The goal is simple:

> **Investigators should not have to be harmed by the evidence they are trying to preserve.**

```
```
