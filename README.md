# BlindSite: High-Risk Investigations Platform & Forensic Browser
<img width="2305" height="1397" alt="image" src="https://github.com/user-attachments/assets/e95c6f29-61da-4ee0-9d95-9a2dc4627404" />

**Preserve what investigators should not have to see.**

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

# 🔥 BlindSite Second Major Update — Faster, Safer, and More Investigator-Ready

BlindSite has received one of its most significant upgrades yet.

First, thank you to everyone who has taken the time to look at the project. BlindSite has now reached **330+ total clones by 138 unique cloners**, which tells us people are paying attention and taking the tool seriously enough to pull the code, inspect it, test it, and see where this project is going.

This update is a major step forward.

Our last update improved general performance by approximately **70%** as well as greatly increasing the security/encryption of the workflow. This new update adds another major performance leap, with Tor/session performance improvements of up to approximately **80%**, depending on workflow, environment, and system resources.

> **Older versions should now be considered deprecated.**  
> BlindSite has moved quickly from early proof-of-concept into a much more serious forensic containment platform.

---

## 🚀 What’s New

### ⚡ Major Performance Improvements

BlindSite is now significantly faster and more responsive during high-risk investigation workflows.

This update improves Tor/session performance, evidence capture responsiveness, handling of larger or dynamic pages, investigator workflow speed, and general stability during longer sessions.

---

### 🌐 Remote Evidence Resource Capture

BlindSite can now better preserve remote resources and callbacks connected to a page.

Modern web evidence is often not just the visible page. It may include media URLs, redirected resources, embedded content, API responses, video/resource pointers, dynamic assets, and files loaded from external domains.

This helps investigators preserve more of the actual evidence environment instead of relying only on screenshots or surface-level page capture.

---

### 🔎 Search and Evidence Discovery

BlindSite now includes stronger search functionality to help investigators quickly find captured evidence, notes, resources, reports, and case materials.

This makes larger investigations easier to work through without manually digging through folders, logs, or scattered files.

---

### 📝 Secure Report Creation

BlindSite now supports stronger secure report workflows for turning captured evidence into organized case material in a secure manner. Encrypted PDF reports can now be prepared by authorized individuals and securely exported.

Reports can help investigators summarize findings, preserve context, document what was captured, and prepare evidence for safer review or handoff.

---

### 🧵 Background Tasks

Longer operations can now run more smoothly in the background instead of freezing the investigator’s workflow.

This is especially important during larger captures, downloads, exports, scans, and evidence-processing tasks.

---

### 📊 Download Progress Bar

BlindSite now includes clearer download progress handling so investigators can see what is happening during resource capture.

This makes the app feel more transparent and usable when dealing with larger files, remote resources, or slower Tor/network sessions.

---

### 💬 Better Dynamic Investigation Support

BlindSite is becoming much stronger for real-world investigations where evidence appears after the page loads.

This matters for public chat sites, forums, live pages, media-heavy pages, high-risk web communities, and other environments where evidence may appear only after interaction. Got a long chat that's taken place over an hour. Capture the full data set with manual capture!

---

## 🧠 Why This Update Matters

BlindSite exists because people doing high-risk investigations often have no good options.

They are forced to choose between directly viewing disturbing material, taking weak screenshots, downloading risky files manually, losing dynamic evidence, relying on tools not designed for custody, or avoiding the investigation altogether.

BlindSite is designed to create a safer middle path.

It helps investigators preserve evidence while reducing unnecessary exposure, improving custody, and making responsible handoff easier.

---

## ✅ Recommended Action

If you cloned an earlier version of BlindSite, we strongly recommend updating.

---

**Thank you to everyone testing, cloning, reviewing, and following the project.**

This second update is a serious upgrade — and we are just getting started. From here on out it's about putting this code through it's paces, validating all the claims, and hardening the code so it can work on any site without fail. People like you who clone and post issues with the code are a critical part of that process! We will reward you with tokens on our website for thoughtful feedback or used feature suggestions so don't be shy.

2 new standalone security and performance validation suites are also available to test core technical and performance claims around encrypted storage, hard-sealed custody, wrong-key failure, sealed exports, reviewer recovery, audit-chain tamper detection, and storage-hash tamper detection. The security evaluator has been updated since we pushed it yesterday.

A secure key generator for organizations and those testing BlindSite is now available. It is critical this generator is used only by organization or individuals that understand the risks or those wanting to test out BlindSite. For normal Civilian workflows please use Civilian Unknown Master Key Mode with the prefilled key.

Our public key has changed. Please check below for the correct key though it should be filled in for you automatically for Civilian mode.

This is still early-access software, but this update is a major step toward making BlindSite faster, safer, and easier to verify.


ABOUT THE PROGRAM:

BlindSite is a forensic browser and encrypted evidence vault for high-risk digital investigations.

It is built for situations where simply visiting a site, viewing media, or manually saving content could create legal, psychological, or operational risk.

BlindSite can capture modern web pages, preserve images/videos/audio as encrypted evidence, block dangerous media from the investigator’s screen, support clear web and darknet workflows, and create sealed evidence packages for authorized reviewers or law enforcement. Think Hunchly but open-source and with more features.

**NOTE: BlindSite is NOT trying to be a Hunchly clone. Hunchly helped define investigative web capture.
BlindSite builds on that idea for a different problem: high-risk evidence containment, restricted custody,
blocked-media preservation, sealed export, and safer handoff. We still feel you should use them or more 
established solutions for sensitive, critical, or high risk investigations! For now ;)**

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
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAscG0PRP92MgUz96g7AQw
3IwP6n7BANUrDJeAt2KToOHru2VslJdnau1UwSNvLvSH54mesrqUwzFN2aMtbtK8
mCJ0Kce25H4kNH7Faav+HplQzE3xG85GrJe3UKqwvWruM2GTALdYFoGdPwhXrFKh
eCefXO++/118PbN6qVliz1knypKDKgxMz6Eu7LVxyiV5la/4UzEpZw1xFlesxudY
dyriu31+0Y7sBDdHs92ThaGSKWaENfPDBtvANVMZM2WFC/jX2Z1/C9f4wb7+s1FH
CGnGGscK1AtpvnHK/YqaFcPqXj7UrAndNynrG2o+ssKO1xdTrvCaKqyk8q7vOiQT
UcQw0I0WMmgUO7r16dHOhph6CjSvx8Sy0X6GeSjWLIxuFUrUVeq0RetqTsEu6z8s
CSoOhou/BDyXHiTkz76uv91KobIAZw/pc0G936ho15GaIqus9FG1cefdCFok/WFc
s4zMFqiOtVDS2yjMPR1azVYpv/o4fPujO5ZxXwelrsNYfeEt7ldGx+NeqcZTYyRU
AX/ylVdwT9xI8H31fQEuemUtSgxNAHCawyBSQL2DXbONevur0xnxTq8MznHy1qlz
YubNBgvNrK9iyGuOcgVSaiXOE5fS/rVMvL2HHO0WPV4zwn0tV+t6owjQOUxxVN3y
jX+9RPguKBS03nI2IId0Vy0CAwEAAQ==
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
