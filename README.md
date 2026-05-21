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

## Latest Major Update: Faster, Safer, More Investigator-Ready

BlindSite has received a major forensic hardening and usability update focused on real-world investigations, darknet workflows, evidence integrity, and safer review.

### New Features

- **Application Genesis Hash**
  - Every new investigation can now be cryptographically tied to the exact BlindSite build/source file that created it.
  - Helps investigators and reviewers verify which version of BlindSite initialized the case.

- **Executable Genesis Seal**
  - Adds an `application_genesis` audit event at the start of new investigation/session audit chains.
  - Records the executable/source hash, app version, custody mode, release metadata when available, and verification warnings.

- **Optional YubiKey / WebAuthn Protection**
  - YubiKey/security-key support is now available as an optional extra layer.
  - It does **not** replace the master reveal key.
  - Users can enable security-key prompts for login and high-risk actions.

- **LE Reviewer YubiKey Protection**
  - Imported reviewer case files can now be protected with a review password and/or YubiKey.
  - Adds safer access control for sensitive recovered evidence.

- **LE Reviewer Import Timeout**
  - Imported reviewer cases can automatically re-lock after inactivity.
  - Reviewers must re-authenticate with password or YubiKey after the timeout expires.

- **Global Tor Status Bar**
  - BlindSite now shows Tor readiness across the app.
  - Displays Tor closed/starting/bootstrapping/ready status with a live percentage indicator.

- **Improved Tor Workflow**
  - Tor startup, diagnostics, bootstrap progress, and managed shutdown are more visible and easier to trust.
  - Helps investigators know whether Tor is actually ready before depending on it.

- **CAPTCHA / Challenge Image Exception**
  - BlindSite can now allow narrow CAPTCHA/challenge images while keeping other media blocked.
  - This helps investigators access sites that require CAPTCHA verification without switching to unsafe “allow all images” mode.

- **Inline/Base64 CAPTCHA Support**
  - Some onion sites embed CAPTCHAs directly as `data:image/png;base64,...`.
  - BlindSite now supports those inline CAPTCHA images when the surrounding page context indicates a challenge/human-verification step.

- **Blocked Media Safety Preserved**
  - CAPTCHA support does **not** allow all images.
  - Video, audio, normal images, and unrelated media remain blocked unless policy allows them.
  - CAPTCHA exceptions are logged for forensic transparency.

- **Smarter Background Media Retry**
  - Background media preservation remains fast and recoverable.
  - Queue-full items are treated as a subset of not-downloaded media, so investigators can retry failed preservation without losing the session.

- **Cleaner Header Hash Display**
  - Events with no captured headers no longer appear as if they have meaningful identical header hashes.
  - BlindSite now makes empty-header events clearer in the UI.

- **Debug / Self-Test / Security Evaluator Updates**
  - Self-test and debug output now include newer forensic/security features.
  - The security evaluator was updated to cover Application Genesis Hash, YubiKey/WebAuthn, sealed custody, reviewer protection, and related claims.

### Why This Matters

This update makes BlindSite more usable in real investigative conditions.

Investigators often need to access fragile, hostile, or darknet sites where:

- Tor must be working correctly
- media must stay blocked
- CAPTCHAs must still be solvable by a human
- evidence must remain sealed and reviewable
- access to recovered evidence must be controlled
- the tool version that created the case must be verifiable

BlindSite is built around a simple principle:

> Preserve what investigators should not have to see.

This update pushes that idea further by making BlindSite safer, more transparent, more verifiable, and more practical for real high-risk investigations.
> **Older versions should now be considered deprecated.**
> 
---

## ✅ Recommended Action

If you cloned an earlier version of BlindSite, we strongly recommend updating.

---

**Thank you to everyone testing, cloning, reviewing, and following the project.**

This fourth update is a serious upgrade — and we are just getting started. From here on out it's about putting this code through it's paces, validating all the claims, and hardening the code so it can work on any site without fail. People like you who clone and post issues with the code are a critical part of that process! We will reward you with tokens on our website for thoughtful feedback or used feature suggestions so don't be shy.

**ABOUT THE PROGRAM:**

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
  pypdf \
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
