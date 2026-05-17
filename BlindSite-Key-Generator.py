#!/usr/bin/env python3
"""
BlindSite Escrow Key Generator

US CYBER MILITIA | BLINDSITE

IMPORTANT CUSTODY WARNING

Do NOT use this generator for USCM Civilian Unknown Master Key mode.

Civilian Unknown Master Key mode only works as intended when the civilian
collector does NOT generate, possess, or control the private reveal key.

For the intended USCM civilian handoff workflow, use the official USCM escrow
public key published in the BlindSite README.

This generator is intended for:

1. Organizations that want to run BlindSite under Organization-Controlled Key mode.
2. Law-enforcement agencies or cleared review teams that control their own keys.
3. Internal testing/demo environments where no real evidence is involved.

If you are a civilian collector using Civilian Unknown Master Key mode, do not
generate your own keypair. Using your own keypair defeats the point of that
mode because you may be able to decrypt the evidence yourself.

Public keys may be shared.
Private keys must NEVER be uploaded, committed to GitHub, emailed casually, or
stored with civilian/public deployments.

Generated private key:
    escrow_private_key.pem

Generated public key:
    escrow_public_key.pem

For USCM Civilian Unknown Master Key handoff workflows:
    Use the USCM public key from the README.

DEPLOYMENT-SAFETY DEFAULTS

This tool does NOT overwrite existing keys by default.

This tool now requires private-key passphrase protection by default. To generate
an unencrypted private key, you must explicitly pass:

    --allow-unencrypted-private-key

Unencrypted private keys are not recommended for real custody workflows.

Each generated keypair is written into its own labeled folder so you can keep
multiple organization, agency, testing, or reviewer keys without accidentally
replacing a key that is needed to decrypt older sealed packages.

If you lose or overwrite a private key, any sealed packages encrypted for that
public key may become permanently unrecoverable.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


APP_NAME = "BlindSite Escrow Key Generator"
APP_VERSION = "1.2-interactive-deployment-safe"
DEFAULT_ROOT = "escrow_keys"


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def slugify(value: str) -> str:
    value = (value or "").strip().lower()
    value = re.sub(r"[^a-z0-9._-]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("._-")
    return value[:80] or "escrow_key"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fingerprint_public_key(public_key) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_bytes(der)


def load_public_key(path: Path):
    return serialization.load_pem_public_key(path.read_bytes())


def load_private_key(path: Path, passphrase: str = ""):
    password = passphrase.encode("utf-8") if passphrase else None
    return serialization.load_pem_private_key(path.read_bytes(), password=password)


def choose_output_dir(root: Path, name: str = "", flat: bool = False, overwrite: bool = False) -> Path:
    root = root.expanduser().resolve()

    if flat:
        out_dir = root
    else:
        label = slugify(name) if name else "escrow"
        suffix = secrets.token_hex(4)
        out_dir = root / f"{label}_{utc_stamp()}_{suffix}"

    if out_dir.exists() and not overwrite:
        existing = list(out_dir.iterdir()) if out_dir.is_dir() else [out_dir]
        if existing:
            raise SystemExit(
                f"Refusing to write into non-empty output location: {out_dir}\n"
                "Use a new --name, a new --out directory, or pass --overwrite only if you "
                "intentionally want to replace files."
            )

    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


def test_roundtrip(public_path: Path, private_path: Path, passphrase: str = "") -> dict[str, Any]:
    public_key = load_public_key(public_path)
    private_key = load_private_key(private_path, passphrase)

    message = b"BlindSite escrow key test message " + secrets.token_bytes(16)
    encrypted = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    decrypted = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    public_fp = fingerprint_public_key(public_key)
    private_fp = fingerprint_public_key(private_key.public_key())

    return {
        "ok": decrypted == message and public_fp == private_fp,
        "tested_at_utc": utc_iso(),
        "public_key": str(public_path),
        "private_key": str(private_path),
        "public_key_fingerprint": public_fp,
        "private_key_public_fingerprint": private_fp,
        "fingerprints_match": public_fp == private_fp,
        "roundtrip_decrypt_ok": decrypted == message,
        "ciphertext_sample_b64": base64.b64encode(encrypted[:32]).decode("ascii") + "...",
    }


def generate_keypair(
    out_root: Path,
    *,
    name: str = "",
    bits: int = 3072,
    passphrase: str = "",
    overwrite: bool = False,
    flat: bool = False,
    allow_unencrypted_private_key: bool = False,
    auto_test: bool = True,
) -> dict[str, Any]:
    if not passphrase and not allow_unencrypted_private_key:
        raise SystemExit(
            "Refusing to generate an unencrypted private key by default.\n"
            "Use --prompt-passphrase or --passphrase to protect the private key.\n"
            "If this is only for a disposable test/demo key, pass --allow-unencrypted-private-key."
        )

    out_dir = choose_output_dir(out_root, name=name, flat=flat, overwrite=overwrite)

    private_path = out_dir / "escrow_private_key.pem"
    public_path = out_dir / "escrow_public_key.pem"
    fingerprint_path = out_dir / "escrow_public_fingerprint.txt"
    info_path = out_dir / "KEY_INFO.json"
    test_path = out_dir / "KEY_TEST_RESULT.json"
    readme_path = out_dir / "README_ESCROW_KEYS.txt"

    if not overwrite:
        existing = [p for p in (private_path, public_path, fingerprint_path, info_path, test_path, readme_path) if p.exists()]
        if existing:
            raise SystemExit(
                "Refusing to overwrite existing key files. "
                "Use --overwrite only if you intentionally want to replace them."
            )

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
    )

    encryption = (
        serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
        if passphrase
        else serialization.NoEncryption()
    )

    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        encryption,
    )

    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    fingerprint = fingerprint_public_key(private_key.public_key())

    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)
    fingerprint_path.write_text(fingerprint + "\n", encoding="utf-8")

    try:
        os.chmod(private_path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass

    key_info = {
        "tool": APP_NAME,
        "version": APP_VERSION,
        "created_at_utc": utc_iso(),
        "key_label": name or out_dir.name,
        "bits": bits,
        "private_key_file": private_path.name,
        "public_key_file": public_path.name,
        "public_key_fingerprint_sha256_der": fingerprint,
        "private_key_encrypted_with_passphrase": bool(passphrase),
        "unencrypted_private_key_explicitly_allowed": bool(allow_unencrypted_private_key and not passphrase),
        "auto_test_enabled": bool(auto_test),
        "custody_warning": (
            "Do not use generated keys for USCM Civilian Unknown Master Key mode. "
            "That mode requires the civilian collector not to possess or control the private reveal key. "
            "Use the official USCM public key from the BlindSite README for USCM civilian handoff workflows."
        ),
        "safe_to_publish": [
            "escrow_public_key.pem",
            "escrow_public_fingerprint.txt",
            "KEY_INFO.json after verifying it contains no private material",
            "KEY_TEST_RESULT.json after verifying it contains no private material",
        ],
        "never_publish": [
            "escrow_private_key.pem",
            "private-key passphrase",
            "sealed evidence packages containing real case data",
        ],
    }

    test_result: dict[str, Any] | None = None
    if auto_test:
        try:
            test_result = test_roundtrip(public_path, private_path, passphrase)
            test_path.write_text(json.dumps(test_result, indent=2), encoding="utf-8")
            key_info["auto_test_result_file"] = test_path.name
            key_info["auto_test_ok"] = bool(test_result.get("ok"))
            if not test_result.get("ok"):
                raise SystemExit("Generated keypair failed roundtrip test. Do not use this keypair.")
        except Exception as exc:
            failure = {
                "ok": False,
                "tested_at_utc": utc_iso(),
                "error": str(exc),
                "warning": "Generated keypair could not be verified. Do not use this keypair until resolved.",
            }
            test_path.write_text(json.dumps(failure, indent=2), encoding="utf-8")
            raise

    info_path.write_text(json.dumps(key_info, indent=2), encoding="utf-8")

    readme_path.write_text(
        "BlindSite escrow keypair\n\n"
        "IMPORTANT:\n"
        "Do NOT use this generated keypair for USCM Civilian Unknown Master Key mode.\n"
        "Civilian Unknown Master Key mode requires that the civilian collector does not\n"
        "generate, possess, or control the private reveal key.\n\n"
        "Use this generated keypair for Organization-Controlled Key mode, agency/reviewer\n"
        "workflows, or testing/demo environments only.\n\n"
        "Files:\n"
        f"- Private key: {private_path.name}   KEEP OFFLINE / NEVER PUBLISH\n"
        f"- Public key:  {public_path.name}    Safe to share\n"
        f"- Fingerprint: {fingerprint_path.name}\n"
        f"- Key info:    {info_path.name}\n"
        f"- Test result: {test_path.name if auto_test else 'not created'}\n\n"
        f"Public key SHA-256 fingerprint: {fingerprint}\n"
        f"Private key encrypted with passphrase: {bool(passphrase)}\n\n"
        "If this private key is unencrypted, protect the folder carefully and consider\n"
        "regenerating with passphrase protection for real custody workflows.\n\n"
        "If you lose this private key, sealed packages encrypted to this public key may\n"
        "be permanently unrecoverable.\n",
        encoding="utf-8",
    )

    return {
        "ok": True,
        "out_dir": str(out_dir),
        "private_key": str(private_path),
        "public_key": str(public_path),
        "public_key_fingerprint": fingerprint,
        "private_key_encrypted": bool(passphrase),
        "bits": bits,
        "key_info": str(info_path),
        "test_result": str(test_path) if auto_test else "",
        "auto_test_ok": bool(test_result.get("ok")) if test_result else None,
        "readme": str(readme_path),
        "warning": "Do not publish or upload escrow_private_key.pem.",
    }


def print_fingerprint(key_path: Path, passphrase: str = "") -> dict[str, Any]:
    data = key_path.read_bytes()
    if b"PRIVATE KEY" in data:
        private_key = load_private_key(key_path, passphrase)
        public_key = private_key.public_key()
    else:
        public_key = load_public_key(key_path)

    return {
        "key": str(key_path),
        "public_key_fingerprint_sha256_der": fingerprint_public_key(public_key),
    }


def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value if value else default


def ask_yes_no(prompt: str, default: bool = False) -> bool:
    default_text = "Y/n" if default else "y/N"
    while True:
        value = input(f"{prompt} [{default_text}]: ").strip().lower()
        if not value:
            return default
        if value in {"y", "yes"}:
            return True
        if value in {"n", "no"}:
            return False
        print("Please answer y or n.")


def ask_choice(prompt: str, choices: list[str], default: str) -> str:
    choice_text = "/".join([c.upper() if c == default else c for c in choices])
    while True:
        value = input(f"{prompt} ({choice_text}): ").strip().lower()
        if not value:
            return default
        if value in choices:
            return value
        print("Invalid choice. Options:", ", ".join(choices))


def print_custody_warning() -> None:
    print("\n" + "=" * 72)
    print("IMPORTANT CUSTODY WARNING")
    print("=" * 72)
    print("Do NOT use this generator for USCM Civilian Unknown Master Key mode.")
    print()
    print("That mode only works as intended when the civilian collector does NOT")
    print("generate, possess, or control the private reveal key.")
    print()
    print("For the intended USCM civilian handoff workflow, use the official")
    print("USCM escrow public key published in the BlindSite README.")
    print()
    print("This generator is for Organization-Controlled Key mode, law-enforcement")
    print("or cleared reviewer key generation, and testing/demo environments.")
    print("=" * 72 + "\n")


def prompt_for_passphrase(required: bool = True) -> str:
    while True:
        p1 = getpass.getpass("Private key passphrase: ")
        p2 = getpass.getpass("Confirm private key passphrase: ")
        if p1 != p2:
            print("Passphrases did not match. Try again.")
            continue
        if required and not p1:
            print("Passphrase is required for deployment-safe key generation.")
            continue
        if p1 and len(p1) < 8:
            if not ask_yes_no("Passphrase is short. Use it anyway?", False):
                continue
        return p1


def interactive_generate() -> None:
    print_custody_warning()
    if not ask_yes_no("Do you understand this generator is NOT for USCM Civilian Unknown Master Key mode?", False):
        print("Cancelled.")
        return

    out_root = Path(ask("Output root folder", DEFAULT_ROOT))
    name = ask("Key label/name, e.g. agency_name or test_key", "organization_key")

    bits_choice = ask_choice("RSA key size", ["2048", "3072", "4096"], "3072")
    bits = int(bits_choice)

    passphrase = ""
    allow_unencrypted = False
    use_passphrase = ask_yes_no("Encrypt private key with a passphrase? Recommended/required for real use.", True)
    if use_passphrase:
        passphrase = prompt_for_passphrase(required=True)
    else:
        print("\nWARNING: Unencrypted private keys are not recommended for real custody workflows.")
        print("Only choose this for disposable test/demo keys or a properly protected offline environment.\n")
        allow_unencrypted = ask_yes_no("Explicitly allow unencrypted private key?", False)
        if not allow_unencrypted:
            print("Cancelled. Re-run and choose passphrase protection.")
            return

    flat = ask_yes_no("Write directly into output folder instead of a unique subfolder? Not recommended.", False)
    overwrite = False
    if flat:
        overwrite = ask_yes_no("Allow overwriting existing key files? Dangerous.", False)

    auto_test = ask_yes_no("Automatically test the generated keypair?", True)

    print("\nGenerating keypair...\n")
    result = generate_keypair(
        out_root=out_root,
        name=name,
        bits=bits,
        passphrase=passphrase,
        overwrite=overwrite,
        flat=flat,
        allow_unencrypted_private_key=allow_unencrypted,
        auto_test=auto_test,
    )
    print(json.dumps(result, indent=2))
    print("\nGenerated successfully.")
    print("PRIVATE KEY: keep offline / never publish.")
    print("PUBLIC KEY: safe to share with the organization-controlled BlindSite setup.")
    if result.get("auto_test_ok"):
        print("Keypair self-test passed.")
    print()


def interactive_fingerprint() -> None:
    key = Path(ask("Path to public or private PEM key"))
    if not key.exists():
        print("File not found:", key)
        return
    passphrase = ""
    if b"PRIVATE KEY" in key.read_bytes() and ask_yes_no("Is this private key passphrase-protected?", False):
        passphrase = getpass.getpass("Private key passphrase: ")
    result = print_fingerprint(key, passphrase)
    print(json.dumps(result, indent=2))


def interactive_test() -> None:
    public_key = Path(ask("Path to public key PEM"))
    private_key = Path(ask("Path to private key PEM"))
    if not public_key.exists():
        print("Public key not found:", public_key)
        return
    if not private_key.exists():
        print("Private key not found:", private_key)
        return
    passphrase = ""
    if ask_yes_no("Is the private key passphrase-protected?", True):
        passphrase = getpass.getpass("Private key passphrase: ")
    result = test_roundtrip(public_key, private_key, passphrase)
    print(json.dumps(result, indent=2))
    if result.get("ok"):
        print("\nKeypair test passed.")
    else:
        print("\nKeypair test failed. Do not use this keypair.")


def interactive_menu() -> int:
    while True:
        print("\nBlindSite Escrow Key Generator")
        print("=" * 36)
        print("1. Generate organization/reviewer escrow keypair")
        print("2. Show fingerprint for a PEM key")
        print("3. Test public/private keypair")
        print("4. Show custody warning")
        print("5. Exit")
        choice = input("\nChoose an option [1-5]: ").strip()

        try:
            if choice == "1":
                interactive_generate()
            elif choice == "2":
                interactive_fingerprint()
            elif choice == "3":
                interactive_test()
            elif choice == "4":
                print_custody_warning()
            elif choice == "5" or choice.lower() in {"q", "quit", "exit"}:
                return 0
            else:
                print("Invalid option.")
        except KeyboardInterrupt:
            print("\nCancelled.")
        except Exception as exc:
            print("\nERROR:", exc)
            print("If this involved a real keypair, do not delete anything until you understand what happened.")


def main() -> int:
    # No arguments = interactive mode.
    if len(sys.argv) == 1:
        return interactive_menu()

    parser = argparse.ArgumentParser(description=f"{APP_NAME} {APP_VERSION}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    gen = sub.add_parser("generate", help="Generate a new escrow RSA keypair")
    gen.add_argument("--out", default=DEFAULT_ROOT, help="Output root directory")
    gen.add_argument("--name", default="", help="Optional key label, e.g. agency_name or test_key")
    gen.add_argument("--bits", type=int, default=3072, choices=[2048, 3072, 4096])
    gen.add_argument(
        "--passphrase",
        default="",
        help="Optional private-key passphrase. Prefer --prompt-passphrase so it is not stored in shell history.",
    )
    gen.add_argument("--prompt-passphrase", action="store_true", help="Prompt for private-key passphrase without echo")
    gen.add_argument(
        "--allow-unencrypted-private-key",
        action="store_true",
        help="Allow generating an unencrypted private key. Not recommended for real custody workflows.",
    )
    gen.add_argument("--overwrite", action="store_true", help="Overwrite existing key files")
    gen.add_argument(
        "--flat",
        action="store_true",
        help=(
            "Write files directly into --out instead of creating a unique subfolder. "
            "Not recommended unless you know what you are doing."
        ),
    )
    gen.add_argument("--no-auto-test", action="store_true", help="Skip automatic keypair roundtrip test")

    fp = sub.add_parser("fingerprint", help="Print public-key fingerprint from PEM key")
    fp.add_argument("--key", required=True, help="Public or private PEM key")
    fp.add_argument("--passphrase", default="", help="Private-key passphrase, if needed")
    fp.add_argument("--prompt-passphrase", action="store_true", help="Prompt for private-key passphrase without echo")

    test = sub.add_parser("test", help="Test encrypt/decrypt roundtrip and public/private match")
    test.add_argument("--public-key", required=True)
    test.add_argument("--private-key", required=True)
    test.add_argument("--passphrase", default="", help="Private-key passphrase, if needed")
    test.add_argument("--prompt-passphrase", action="store_true", help="Prompt for private-key passphrase without echo")

    args = parser.parse_args()

    if args.cmd == "generate":
        passphrase = args.passphrase
        if args.prompt_passphrase:
            passphrase = prompt_for_passphrase(required=True)

        if args.passphrase:
            print(
                "WARNING: Passing a passphrase on the command line may store it in shell history. "
                "Prefer --prompt-passphrase.",
                file=sys.stderr,
            )

        result = generate_keypair(
            out_root=Path(args.out),
            name=args.name,
            bits=args.bits,
            passphrase=passphrase,
            overwrite=args.overwrite,
            flat=args.flat,
            allow_unencrypted_private_key=args.allow_unencrypted_private_key,
            auto_test=not args.no_auto_test,
        )
    elif args.cmd == "fingerprint":
        passphrase = args.passphrase
        if args.prompt_passphrase:
            passphrase = getpass.getpass("Private key passphrase: ")
        result = print_fingerprint(Path(args.key), passphrase)
    elif args.cmd == "test":
        passphrase = args.passphrase
        if args.prompt_passphrase:
            passphrase = getpass.getpass("Private key passphrase: ")
        result = test_roundtrip(Path(args.public_key), Path(args.private_key), passphrase)
    else:
        parser.error("unknown command")

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
