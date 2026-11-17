#!/usr/bin/env python3
"""
cryptoutil: Cryptographic Hash & Key Derivation Utility
========================================================
A command-line tool for secure hashing, key derivation, salt generation,
HMAC computation/verification, and file checksum verification.

Uses ONLY the Python standard library: hashlib, hmac, secrets, argparse.
"""

import argparse
import hashlib
import hmac as hmac_mod
import secrets
import sys
import os
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CHUNK_SIZE = 65536  # 64 KB chunks for streaming file hashing
SUPPORTED_ALGOS = ["sha256", "sha512"]


# ---------------------------------------------------------------------------
# Core logic functions (pure, testable)
# ---------------------------------------------------------------------------

def hash_text(text: str, algo: str = "sha256") -> str:
    """
    Compute a hex digest of a UTF-8 encoded text string.

    Args:
        text: The input string to hash.
        algo: Hash algorithm name ("sha256" or "sha512").

    Returns:
        Lowercase hex digest string.
    """
    h = hashlib.new(algo)
    h.update(text.encode("utf-8"))
    return h.hexdigest()


def hash_file(path: str, algo: str = "sha256") -> str:
    """
    Compute a hex digest of a file, reading in chunks to support large files.

    Args:
        path: Filesystem path to the file.
        algo: Hash algorithm name ("sha256" or "sha512").

    Returns:
        Lowercase hex digest string.

    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If the file cannot be read.
    """
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def generate_salt(num_bytes: int = 16) -> bytes:
    """
    Generate a cryptographically secure random salt.

    Uses secrets.token_bytes (backed by os.urandom / CSPRNG) rather than
    the non-cryptographic random module.

    Args:
        num_bytes: Number of random bytes to generate.

    Returns:
        Raw bytes of the requested length.
    """
    return secrets.token_bytes(num_bytes)


def derive_key(
    password: str,
    salt: bytes,
    iterations: int = 600_000,
    algo: str = "sha256",
    length: int = 32,
) -> bytes:
    """
    Derive a cryptographic key from a password using PBKDF2-HMAC.

    Args:
        password: The input password (plaintext string).
        salt:     The salt as raw bytes.
        iterations: Number of PBKDF2 iterations (higher = slower brute force).
        algo:     Underlying hash ("sha256" or "sha512").
        length:   Desired derived key length in bytes.

    Returns:
        Derived key as raw bytes.
    """
    return hashlib.pbkdf2_hmac(
        hash_name=algo,
        password=password.encode("utf-8"),
        salt=salt,
        iterations=iterations,
        dklen=length,
    )


def compute_hmac(key: bytes, message: bytes, algo: str = "sha256") -> str:
    """
    Compute an HMAC hex digest for a message.

    Args:
        key:     Raw bytes key.
        message: Raw bytes message.
        algo:    Hash algorithm ("sha256" or "sha512").

    Returns:
        Lowercase hex HMAC digest.
    """
    return hmac_mod.new(key, message, digestmod=algo).hexdigest()


def verify_hmac(key: bytes, message: bytes, expected_hex: str, algo: str = "sha256") -> bool:
    """
    Verify an HMAC using constant-time comparison to prevent timing attacks.

    Args:
        key:          Raw bytes key.
        message:      Raw bytes message.
        expected_hex: Hex string of the expected HMAC.
        algo:         Hash algorithm.

    Returns:
        True if the HMAC matches, False otherwise.
    """
    computed = compute_hmac(key, message, algo)
    # hmac.compare_digest prevents timing-based side-channel attacks
    return hmac_mod.compare_digest(computed.lower(), expected_hex.lower())


def verify_checksum(path: str, expected_hex: str, algo: str = "sha256") -> tuple[bool, str]:
    """
    Verify a file's hash against a known checksum (case-insensitive).

    Args:
        path:         Path to the file to verify.
        expected_hex: Expected hex digest string.
        algo:         Hash algorithm.

    Returns:
        Tuple of (match: bool, computed_hex: str).
    """
    computed = hash_file(path, algo)
    match = hmac_mod.compare_digest(computed.lower(), expected_hex.lower())
    return match, computed


# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------

def parse_hex_salt(hex_str: str) -> bytes:
    """
    Parse a hex string into bytes, raising ValueError on invalid input.

    Args:
        hex_str: Hex-encoded salt string.

    Returns:
        Decoded bytes.

    Raises:
        ValueError: If the string is not valid hexadecimal.
    """
    try:
        return bytes.fromhex(hex_str)
    except ValueError:
        raise ValueError(f"Invalid hex salt: '{hex_str}'. Must be a valid hex string.")


def validate_iterations(value: int) -> None:
    """
    Ensure iteration count is a positive integer.

    Args:
        value: The iteration count to validate.

    Raises:
        ValueError: If value is not positive.
    """
    if value < 1:
        raise ValueError(f"Iterations must be a positive integer, got {value}.")


# ---------------------------------------------------------------------------
# Output formatting helpers
# ---------------------------------------------------------------------------

def _header(title: str) -> str:
    """Return a formatted section header string."""
    bar = "─" * 50
    return f"\n{bar}\n  {title}\n{bar}"


def _label(key: str, value: str, width: int = 18) -> str:
    """Return an aligned label: value line."""
    return f"  {key:<{width}} {value}"


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def cmd_hash(args: argparse.Namespace) -> int:
    """Handle the 'hash' subcommand."""
    algo = args.algo

    try:
        if args.text is not None:
            digest = hash_text(args.text, algo)
            source_label = f'"{args.text}"'
            source_type = "Text"
        else:
            digest = hash_file(args.file, algo)
            source_label = args.file
            source_type = "File"
    except FileNotFoundError:
        print(f"Error: File not found: '{args.file}'", file=sys.stderr)
        return 1
    except PermissionError:
        print(f"Error: Permission denied reading: '{args.file}'", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        return 1

    print(_header(f"{algo.upper()} Hash"))
    print(_label("Source type:", source_type))
    print(_label("Input:", source_label))
    print(_label("Algorithm:", algo.upper()))
    print(_label("Digest:", digest))
    print()
    return 0


def cmd_kdf(args: argparse.Namespace) -> int:
    """Handle the 'kdf' subcommand."""
    # Validate iterations
    try:
        validate_iterations(args.iterations)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Resolve salt
    if args.salt:
        try:
            salt_bytes = parse_hex_salt(args.salt)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        salt_source = "provided"
    else:
        salt_bytes = generate_salt(16)
        salt_source = "generated"

    salt_hex = salt_bytes.hex()

    try:
        dk = derive_key(
            password=args.password,
            salt=salt_bytes,
            iterations=args.iterations,
            algo=args.algo,
            length=args.length,
        )
    except Exception as e:
        print(f"Error during key derivation: {e}", file=sys.stderr)
        return 1

    print(_header("PBKDF2-HMAC Key Derivation"))
    print(_label("Algorithm:", f"PBKDF2-HMAC-{args.algo.upper()}"))
    print(_label("Iterations:", str(args.iterations)))
    print(_label("Key length:", f"{args.length} bytes"))
    print(_label("Salt source:", salt_source))
    print(_label("Salt (hex):", salt_hex))
    print(_label("Derived key (hex):", dk.hex()))
    print()
    return 0


def cmd_salt(args: argparse.Namespace) -> int:
    """Handle the 'salt' subcommand."""
    if args.bytes < 1:
        print("Error: --bytes must be a positive integer.", file=sys.stderr)
        return 1

    salt = generate_salt(args.bytes)

    print(_header("Random Salt Generator"))
    print(_label("Length:", f"{args.bytes} bytes"))
    print(_label("Salt (hex):", salt.hex()))
    print()
    return 0


def cmd_hmac(args: argparse.Namespace) -> int:
    """Handle the 'hmac' subcommand."""
    key_bytes = args.key.encode("utf-8")

    # Resolve message bytes
    try:
        if args.message is not None:
            msg_bytes = args.message.encode("utf-8")
            source_label = f'"{args.message}"'
        else:
            with open(args.file, "rb") as f:
                msg_bytes = f.read()
            source_label = args.file
    except FileNotFoundError:
        print(f"Error: File not found: '{args.file}'", file=sys.stderr)
        return 1
    except PermissionError:
        print(f"Error: Permission denied reading: '{args.file}'", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        return 1

    if args.verify:
        # Verify mode
        valid = verify_hmac(key_bytes, msg_bytes, args.verify, args.algo)
        print(_header(f"HMAC-{args.algo.upper()} Verification"))
        print(_label("Source:", source_label))
        print(_label("Algorithm:", f"HMAC-{args.algo.upper()}"))
        print(_label("Expected:", args.verify.lower()))
        computed = compute_hmac(key_bytes, msg_bytes, args.algo)
        print(_label("Computed:", computed))
        if valid:
            print("\n  ✔ VALID: message integrity verified")
            print()
            return 0
        else:
            print("\n  ✘ INVALID: message was altered or key is wrong")
            print()
            return 1
    else:
        # Generate mode
        digest = compute_hmac(key_bytes, msg_bytes, args.algo)
        print(_header(f"HMAC-{args.algo.upper()} Digest"))
        print(_label("Source:", source_label))
        print(_label("Algorithm:", f"HMAC-{args.algo.upper()}"))
        print(_label("HMAC digest:", digest))
        print()
        return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Handle the 'verify' subcommand."""
    try:
        match, computed = verify_checksum(args.file, args.checksum, args.algo)
    except FileNotFoundError:
        print(f"Error: File not found: '{args.file}'", file=sys.stderr)
        return 1
    except PermissionError:
        print(f"Error: Permission denied reading: '{args.file}'", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        return 1

    print(_header(f"{args.algo.upper()} File Verification"))
    print(_label("File:", args.file))
    print(_label("Algorithm:", args.algo.upper()))
    print(_label("Expected:", args.checksum.lower()))
    print(_label("Computed:", computed))

    if match:
        print("\n  ✔ OK: file integrity verified")
        print()
        return 0
    else:
        print("\n  ✘ FAIL: checksum mismatch, file may be corrupted or tampered")
        print()
        return 1


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser for the cryptoutil CLI."""

    root_parser = argparse.ArgumentParser(
        prog="cryptoutil",
        description="Cryptographic Hash & Key Derivation Utility\n"
                    "Uses only the Python standard library (hashlib, hmac, secrets).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Subcommands:\n"
            "  hash    Compute SHA-256/SHA-512 hash of text or a file\n"
            "  kdf     Derive a key with PBKDF2-HMAC\n"
            "  salt    Generate a cryptographically secure random salt\n"
            "  hmac    Compute or verify an HMAC digest\n"
            "  verify  Verify a file against a known checksum\n\n"
            "Run 'cryptoutil <subcommand> --help' for subcommand details."
        ),
    )
    subparsers = root_parser.add_subparsers(dest="command", metavar="<subcommand>")
    subparsers.required = True

    # ---- hash ----
    hash_parser = subparsers.add_parser(
        "hash",
        help="Compute SHA-256/SHA-512 hash of text or a file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Compute a cryptographic hash digest of a text string or file.",
        epilog=(
            "Examples:\n"
            "  cryptoutil hash --text \"hello world\"\n"
            "  cryptoutil hash --text \"hello world\" --algo sha512\n"
            "  cryptoutil hash --file sample_files/sample.txt\n"
            "  cryptoutil hash --file /path/to/large.iso --algo sha512\n"
        ),
    )
    hash_input = hash_parser.add_mutually_exclusive_group(required=True)
    hash_input.add_argument("--text", metavar="STRING", help="Text string to hash")
    hash_input.add_argument("--file", metavar="PATH", help="File path to hash (read in 64 KB chunks)")
    hash_parser.add_argument(
        "--algo",
        choices=SUPPORTED_ALGOS,
        default="sha256",
        help="Hash algorithm (default: sha256)",
    )
    hash_parser.set_defaults(func=cmd_hash)

    # ---- kdf ----
    kdf_parser = subparsers.add_parser(
        "kdf",
        help="Derive a key with PBKDF2-HMAC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Derive a cryptographic key from a password using PBKDF2-HMAC.",
        epilog=(
            "Examples:\n"
            "  cryptoutil kdf --password mysecret\n"
            "  cryptoutil kdf --password mysecret --iterations 600000 --algo sha256\n"
            "  cryptoutil kdf --password mysecret --salt deadbeefcafe0123 --length 64\n"
            "\nNote: NIST recommends >= 600,000 iterations for SHA-256 (2023).\n"
        ),
    )
    kdf_parser.add_argument("--password", required=True, metavar="PASS", help="Input password")
    kdf_parser.add_argument(
        "--salt",
        metavar="HEX",
        default=None,
        help="Salt as hex string (default: randomly generated 16 bytes)",
    )
    kdf_parser.add_argument(
        "--iterations",
        type=int,
        default=600_000,
        metavar="N",
        help="PBKDF2 iteration count (default: 600000)",
    )
    kdf_parser.add_argument(
        "--algo",
        choices=SUPPORTED_ALGOS,
        default="sha256",
        help="Hash algorithm (default: sha256)",
    )
    kdf_parser.add_argument(
        "--length",
        type=int,
        default=32,
        metavar="BYTES",
        help="Derived key length in bytes (default: 32)",
    )
    kdf_parser.set_defaults(func=cmd_kdf)

    # ---- salt ----
    salt_parser = subparsers.add_parser(
        "salt",
        help="Generate a cryptographically secure random salt",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Generate a cryptographically secure random salt using secrets.token_bytes.",
        epilog=(
            "Examples:\n"
            "  cryptoutil salt\n"
            "  cryptoutil salt --bytes 32\n"
            "  cryptoutil salt --bytes 64\n"
        ),
    )
    salt_parser.add_argument(
        "--bytes",
        type=int,
        default=16,
        metavar="N",
        help="Number of random bytes (default: 16)",
    )
    salt_parser.set_defaults(func=cmd_salt)

    # ---- hmac ----
    hmac_parser = subparsers.add_parser(
        "hmac",
        help="Compute or verify an HMAC digest",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Compute or verify an HMAC-SHA256/SHA512 digest.\n\n"
            "Generate mode: provide --key and --message (or --file).\n"
            "Verify mode:   also add --verify <expected_hex>."
        ),
        epilog=(
            "Examples:\n"
            "  # Generate HMAC\n"
            "  cryptoutil hmac --key mykey --message \"hello\"\n"
            "  cryptoutil hmac --key mykey --file sample_files/sample.txt --algo sha512\n\n"
            "  # Verify HMAC (exit 0 on match, 1 on mismatch)\n"
            "  cryptoutil hmac --key mykey --message \"hello\" --verify <expected_hex>\n"
        ),
    )
    hmac_parser.add_argument("--key", required=True, metavar="KEY", help="HMAC secret key (UTF-8 string)")
    hmac_input = hmac_parser.add_mutually_exclusive_group(required=True)
    hmac_input.add_argument("--message", metavar="STRING", help="Message string")
    hmac_input.add_argument("--file", metavar="PATH", help="File path")
    hmac_parser.add_argument(
        "--algo",
        choices=SUPPORTED_ALGOS,
        default="sha256",
        help="Hash algorithm (default: sha256)",
    )
    hmac_parser.add_argument(
        "--verify",
        metavar="HEX",
        default=None,
        help="Expected HMAC hex to verify against (enables verify mode)",
    )
    hmac_parser.set_defaults(func=cmd_hmac)

    # ---- verify ----
    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify a file against a known checksum",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Verify a file's cryptographic hash against a known checksum.\n"
            "Uses constant-time comparison (hmac.compare_digest) to prevent timing attacks."
        ),
        epilog=(
            "Examples:\n"
            "  cryptoutil verify --file sample_files/sample.txt --checksum <hex>\n"
            "  cryptoutil verify --file download.iso --checksum <hex> --algo sha512\n\n"
            "  Exit code 0 = match, 1 = mismatch or error.\n"
        ),
    )
    verify_parser.add_argument("--file", required=True, metavar="PATH", help="File to verify")
    verify_parser.add_argument("--checksum", required=True, metavar="HEX", help="Expected hex checksum")
    verify_parser.add_argument(
        "--algo",
        choices=SUPPORTED_ALGOS,
        default="sha256",
        help="Hash algorithm (default: sha256)",
    )
    verify_parser.set_defaults(func=cmd_verify)

    return root_parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    """Parse arguments and dispatch to the appropriate subcommand handler."""
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
