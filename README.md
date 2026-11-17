# cryptoutil — Cryptographic Hash & Key Derivation Utility

A complete command-line cryptographic utility written in **pure Python** (standard library only: `hashlib`, `hmac`, `secrets`, `argparse`). No third-party packages required.

---

## Table of Contents

1. [Overview & Installation](#1-overview--installation)
2. [Usage Examples](#2-usage-examples)
   - [hash — Compute a hash digest](#21-hash--compute-a-hash-digest)
   - [kdf — PBKDF2 Key Derivation](#22-kdf--pbkdf2-key-derivation)
   - [salt — Generate a random salt](#23-salt--generate-a-random-salt)
   - [hmac — Compute or verify HMAC](#24-hmac--compute-or-verify-hmac)
   - [verify — File checksum verification](#25-verify--file-checksum-verification)
3. [Collision Resistance](#3-collision-resistance)
4. [Salting Principles](#4-salting-principles)
5. [Key Derivation with PBKDF2](#5-key-derivation-with-pbkdf2)
6. [HMAC & Constant-Time Comparison](#6-hmac--constant-time-comparison)
7. [Verification Examples](#7-verification-examples)
8. [Running the Tests](#8-running-the-tests)
9. [Security Notes & Limitations](#9-security-notes--limitations)

---

## 1. Overview & Installation

**Requirements:** Python 3.8 or higher. No external dependencies.

```bash
# Clone or download the project, then run directly:
python3 crypto_util.py --help
```

**File structure:**

```
cryptoutil/
├── crypto_util.py          # Main CLI script
├── test_crypto_util.py     # 57-test unittest suite (NIST/RFC vectors)
├── README.md               # This file
└── sample_files/
    └── sample.txt          # Sample file for README examples
```

> [!NOTE]
> `crypto_util.py` exposes clean, importable functions (`hash_text`, `hash_file`,
> `derive_key`, `generate_salt`, `compute_hmac`, `verify_hmac`, `verify_checksum`)
> so it can be used as a library as well as a CLI.

---

## 2. Usage Examples

### 2.1 `hash` — Compute a hash digest

Computes SHA-256 or SHA-512 of a text string or a file. Files are read in 64 KB chunks so arbitrarily large files never load fully into memory.

**Hash a text string (SHA-256, default):**
```bash
python3 crypto_util.py hash --text "hello world"
```
```
──────────────────────────────────────────────────
  SHA256 Hash
──────────────────────────────────────────────────
  Source type:       Text
  Input:             "hello world"
  Algorithm:         SHA256
  Digest:            b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
```

**Hash a text string with SHA-512:**
```bash
python3 crypto_util.py hash --text "abc" --algo sha512
```
```
──────────────────────────────────────────────────
  SHA512 Hash
──────────────────────────────────────────────────
  Source type:       Text
  Input:             "abc"
  Algorithm:         SHA512
  Digest:            ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f
```

**Hash a file:**
```bash
python3 crypto_util.py hash --file sample_files/sample.txt
```
```
──────────────────────────────────────────────────
  SHA256 Hash
──────────────────────────────────────────────────
  Source type:       File
  Input:             sample_files/sample.txt
  Algorithm:         SHA256
  Digest:            b5f18558e1abe53fac8f0eb58ab41ece3af61e0b8cb6a5beababe321db1ca5a3
```

**Options:**
```
--text STRING     Text string to hash (mutually exclusive with --file)
--file PATH       File path to hash (mutually exclusive with --text)
--algo {sha256,sha512}   Hash algorithm (default: sha256)
```

---

### 2.2 `kdf` — PBKDF2 Key Derivation

Derives a cryptographic key from a password using PBKDF2-HMAC. If no salt is provided, a fresh 16-byte random salt is generated automatically.

**Basic usage (auto-generated salt):**
```bash
python3 crypto_util.py kdf --password mysecret
```
```
──────────────────────────────────────────────────
  PBKDF2-HMAC Key Derivation
──────────────────────────────────────────────────
  Algorithm:         PBKDF2-HMAC-SHA256
  Iterations:        600000
  Key length:        32 bytes
  Salt source:       generated
  Salt (hex):        9d4908650effdd5f76a92e4e706246f5
  Derived key (hex): 3a7f2c1e...
```

**With a specific salt and custom options:**
```bash
python3 crypto_util.py kdf --password mysecret --salt 73616c74 --iterations 1 --algo sha256 --length 32
```
```
──────────────────────────────────────────────────
  PBKDF2-HMAC Key Derivation
──────────────────────────────────────────────────
  Algorithm:         PBKDF2-HMAC-SHA256
  Iterations:        1
  Key length:        32 bytes
  Salt source:       provided
  Salt (hex):        73616c74
  Derived key (hex): 2b6de9393b1cd91be2068e126fbae006f3d18591b3258614564a3ba3692fe1a5
```

> [!IMPORTANT]
> Always store the salt alongside the derived key — you need both the original password
> **and** the same salt to re-derive the same key. The salt does not need to be secret.

**Options:**
```
--password PASS         Input password (required)
--salt HEX              Salt as hex string (optional; random 16 bytes if omitted)
--iterations N          PBKDF2 iteration count (default: 600000)
--algo {sha256,sha512}  Underlying hash (default: sha256)
--length BYTES          Derived key length in bytes (default: 32)
```

---

### 2.3 `salt` — Generate a random salt

Generates a cryptographically secure random salt using `secrets.token_bytes`.

```bash
python3 crypto_util.py salt
```
```
──────────────────────────────────────────────────
  Random Salt Generator
──────────────────────────────────────────────────
  Length:            16 bytes
  Salt (hex):        a3f7bc09e12d45678901abcdef234567
```

```bash
python3 crypto_util.py salt --bytes 32
```
```
──────────────────────────────────────────────────
  Random Salt Generator
──────────────────────────────────────────────────
  Length:            32 bytes
  Salt (hex):        9d4908650effdd5f76a92e4e706246f560a837d52cd042eaf9465ea4fccd7924
```

**Options:**
```
--bytes N   Number of random bytes (default: 16)
```

---

### 2.4 `hmac` — Compute or verify HMAC

**Generate mode** — computes the HMAC digest:
```bash
python3 crypto_util.py hmac --key "Jefe" --message "what do ya want for nothing?"
```
```
──────────────────────────────────────────────────
  HMAC-SHA256 Digest
──────────────────────────────────────────────────
  Source:            "what do ya want for nothing?"
  Algorithm:         HMAC-SHA256
  HMAC digest:       5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
```

**Verify mode** — add `--verify <expected_hex>` (exit code 0 on match, 1 on failure):
```bash
python3 crypto_util.py hmac --key "Jefe" \
    --message "what do ya want for nothing?" \
    --verify 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
```
```
──────────────────────────────────────────────────
  HMAC-SHA256 Verification
──────────────────────────────────────────────────
  Source:            "what do ya want for nothing?"
  Algorithm:         HMAC-SHA256
  Expected:          5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
  Computed:          5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843

  ✔ VALID: message integrity verified
```

**HMAC on a file:**
```bash
python3 crypto_util.py hmac --key mykey --file sample_files/sample.txt --algo sha512
```

**Options:**
```
--key KEY               HMAC secret key (required)
--message STRING        Message string (mutually exclusive with --file)
--file PATH             File path (mutually exclusive with --message)
--algo {sha256,sha512}  Hash algorithm (default: sha256)
--verify HEX            Expected HMAC hex (enables verify mode)
```

---

### 2.5 `verify` — File checksum verification

Verifies a file's hash against a known checksum. Comparison is case-insensitive and constant-time.

**Success case:**
```bash
python3 crypto_util.py verify \
    --file sample_files/sample.txt \
    --checksum b5f18558e1abe53fac8f0eb58ab41ece3af61e0b8cb6a5beababe321db1ca5a3
```
```
──────────────────────────────────────────────────
  SHA256 File Verification
──────────────────────────────────────────────────
  File:              sample_files/sample.txt
  Algorithm:         SHA256
  Expected:          b5f18558e1abe53fac8f0eb58ab41ece3af61e0b8cb6a5beababe321db1ca5a3
  Computed:          b5f18558e1abe53fac8f0eb58ab41ece3af61e0b8cb6a5beababe321db1ca5a3

  ✔ OK: file integrity verified
```

**Failure case:**
```bash
python3 crypto_util.py verify \
    --file sample_files/sample.txt \
    --checksum aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```
```
──────────────────────────────────────────────────
  SHA256 File Verification
──────────────────────────────────────────────────
  File:              sample_files/sample.txt
  Algorithm:         SHA256
  Expected:          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  Computed:          b5f18558e1abe53fac8f0eb58ab41ece3af61e0b8cb6a5beababe321db1ca5a3

  ✘ FAIL: checksum mismatch, file may be corrupted or tampered
```

**Options:**
```
--file PATH             File to verify (required)
--checksum HEX          Expected hex checksum (required)
--algo {sha256,sha512}  Hash algorithm (default: sha256)
```

---

## 3. Collision Resistance

### What it means

A hash function $H$ is **collision resistant** if it is computationally infeasible to find two distinct inputs $x \neq y$ such that $H(x) = H(y)$.

### Why SHA-256 / SHA-512 are considered collision resistant

SHA-256 produces a 256-bit output. Even if you could check a trillion hashes per second, finding a collision by brute force would take longer than the age of the universe. More precisely, the **birthday bound** states that you would need approximately:

$$2^{n/2}$$

evaluations to find a collision in a function with $n$-bit output. For SHA-256 that is $2^{128}$ — a number so large it is physically unreachable with any foreseeable computing technology (classical or quantum, given NIST's current post-quantum guidance).

| Algorithm | Output | Collision bound | Status |
|-----------|--------|-----------------|--------|
| MD5       | 128-bit | $2^{64}$ | **Broken** — practical collisions since 2004 |
| SHA-1     | 160-bit | $2^{80}$ | **Broken** — SHAttered attack (Google, 2017) |
| SHA-256   | 256-bit | $2^{128}$ | ✔ Secure |
| SHA-512   | 512-bit | $2^{256}$ | ✔ Secure |

### Why MD5 and SHA-1 are broken

- **MD5**: In 2004, Wang et al. demonstrated practical collisions. By 2008, researchers created a rogue CA certificate by exploiting MD5 collisions. MD5 must **never** be used for security purposes.
- **SHA-1**: The SHAttered attack (2017) produced the first publicly known SHA-1 collision using ~$2^{63}$ operations (within range of well-funded adversaries). Chrome and other browsers now reject SHA-1 certificates.

> [!CAUTION]
> **Never use MD5 or SHA-1** for new security-sensitive applications. This tool
> intentionally only supports SHA-256 and SHA-512.

---

## 4. Salting Principles

### What is a salt?

A **salt** is a random value appended to a password before hashing: `H(salt || password)`. It is stored alongside the resulting hash.

### Why salting defeats rainbow tables

A **rainbow table** is a precomputed lookup table mapping millions of common passwords to their hashes. Without salting, an attacker who obtains the hash database can look up cracked passwords in milliseconds.

With salting:
- Each password gets a **unique, random salt**, making every entry in the database different.
- A rainbow table would need to be precomputed for every possible salt value — an impossibility at 16+ bytes of salt ($2^{128}$ possible salts).

### Why salting defeats identical-password detection

Without salts, two users with the same password produce identical hashes. An attacker can immediately identify which users share passwords. With unique salts, identical passwords hash to different values — no information is leaked.

### Salt properties

| Property | Requirement |
|----------|-------------|
| **Unique** | Each password must get its own salt |
| **Random** | Must be unpredictable (use a CSPRNG) |
| **Secret?** | No — salts are stored in plaintext alongside the hash |
| **Length** | ≥ 16 bytes (128 bits) recommended |

### Why `secrets` and not `random`

Python's `random` module uses the **Mersenne Twister**, a pseudorandom number generator that is *not* cryptographically secure. Its state can be recovered from 624 consecutive output values.

`secrets.token_bytes` is backed by `os.urandom`, which reads from the operating system's **Cryptographically Secure Pseudorandom Number Generator (CSPRNG)** — `/dev/urandom` on Linux/macOS, `BCryptGenRandom` on Windows. Its output is indistinguishable from true randomness for all practical purposes.

> [!IMPORTANT]
> Always use `secrets` (or `os.urandom`) for salts, keys, and tokens.
> **Never use `random`** for security-sensitive values.

---

## 5. Key Derivation with PBKDF2

### Why key derivation is necessary

Passwords are low-entropy strings. A direct hash (`sha256(password)`) can be attacked with billions of guesses per second on modern GPUs. A **key derivation function (KDF)** is specifically designed to be **slow** to prevent brute-force attacks.

### How PBKDF2 works

PBKDF2 (Password-Based Key Derivation Function 2, RFC 2898) applies the underlying HMAC function many thousands of times:

$$DK = \text{PBKDF2-HMAC}(\text{password},\ \text{salt},\ c,\ dkLen)$$

where $c$ is the **iteration count**. Each iteration forces the attacker to perform one more HMAC computation per guess. If $c = 600{,}000$ and an attacker can test 1 billion passwords per second without the KDF, they can now only test approximately 1,667 per second — a slowdown factor of ~600,000x.

### Recommended iteration count

| Year | NIST Recommendation (PBKDF2-HMAC-SHA256) |
|------|-------------------------------------------|
| 2017 | 10,000 |
| 2021 | 310,000 |
| 2023 | **600,000** |

This tool defaults to **600,000 iterations** per NIST SP 800-132 (2023 guidance). Increase this as hardware speeds up — a good rule of thumb is to set it so derivation takes ~100 ms on your target hardware.

> [!TIP]
> For even stronger password hashing, consider **scrypt** or **Argon2**, which are
> memory-hard (resistant to GPU/ASIC attacks). See the security notes section.

---

## 6. HMAC & Constant-Time Comparison

### What is HMAC?

**HMAC** (Hash-based Message Authentication Code, RFC 2104) provides both **integrity** and **authenticity**:

$$\text{HMAC}(K, m) = H\bigl((K' \oplus \text{opad}) \| H((K' \oplus \text{ipad}) \| m)\bigr)$$

Unlike a plain hash, HMAC requires a **secret key** $K$. Without the key, an attacker cannot forge a valid HMAC. This makes it suitable for:
- Verifying that a message was not tampered with in transit
- Authenticating API requests
- Verifying file authenticity

### Timing attacks and constant-time comparison

A **naive** comparison like `computed == expected` leaks information through **timing**:
- If the strings differ at byte 0, it returns immediately.
- If they differ at byte 60, it takes slightly longer.

By measuring how long verification takes, an attacker can progressively guess the correct HMAC byte-by-byte (a **timing side-channel attack**).

**`hmac.compare_digest`** (used throughout this tool) compares two digests in **constant time** — it always examines every byte regardless of where the first mismatch occurs. This eliminates the timing oracle.

> [!IMPORTANT]
> Always use `hmac.compare_digest` (or equivalent) whenever comparing
> security-sensitive values such as HMACs, tokens, or hashes.

---

## 7. Verification Examples

### File integrity verification (success)

```bash
# Step 1: compute the hash of the file you trust
python3 crypto_util.py hash --file sample_files/sample.txt
# → Digest: b5f18558e1abe53fac8f0eb58ab41ece3af61e0b8cb6a5beababe321db1ca5a3

# Step 2: later, verify the file hasn't changed
python3 crypto_util.py verify \
    --file sample_files/sample.txt \
    --checksum b5f18558e1abe53fac8f0eb58ab41ece3af61e0b8cb6a5beababe321db1ca5a3
# → ✔ OK: file integrity verified
```

### File integrity verification (failure / tamper detected)

```bash
python3 crypto_util.py verify \
    --file sample_files/sample.txt \
    --checksum aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
# → ✘ FAIL: checksum mismatch, file may be corrupted or tampered
```

Both the expected and computed hashes are shown on failure so you can diagnose the discrepancy.

### HMAC verification (success and failure)

```bash
# Generate HMAC
python3 crypto_util.py hmac --key "mykey" --message "important data"
# → HMAC digest: <hex>

# Verify (success)
python3 crypto_util.py hmac --key "mykey" --message "important data" --verify <hex>
# → ✔ VALID: message integrity verified  (exit code 0)

# Verify with tampered message (failure)
python3 crypto_util.py hmac --key "mykey" --message "tampered data" --verify <hex>
# → ✘ INVALID: message was altered or key is wrong  (exit code 1)
```

Exit codes are designed for scripting:
```bash
python3 crypto_util.py verify --file myfile.bin --checksum <hex>
if [ $? -eq 0 ]; then echo "Safe to proceed"; fi
```

---

## 8. Running the Tests

The test suite contains **57 tests** covering NIST/RFC test vectors and edge cases.

```bash
# Run all tests with verbose output
python3 -m unittest -v

# Or specify the test file explicitly
python3 -m unittest test_crypto_util -v
```

**What is tested:**
- SHA-256 / SHA-512 against NIST test vectors (`"abc"`, `""`)
- SHA-512 against NIST vectors (`"abc"`, `""`)
- HMAC-SHA256 against RFC 4231 Test Case 2 (`key="Jefe"`)
- PBKDF2-HMAC-SHA256 against RFC 7914 known vectors (iterations=1 and 2)
- File hashing: empty file, small file, large file (> 64 KB chunk size), UTF-8 consistency
- Salt generator: correct length, correct type, two consecutive salts differ, uses `secrets`
- HMAC verify: valid tag, uppercase hex, tampered message, wrong key, wrong digest
- Checksum verify: match, mismatch, uppercase hex, SHA-512, file not found
- Input validation: bad hex salt, odd-length hex, zero/negative iterations
- Integration: hash_text vs hash_file consistency, KDF round-trip, HMAC compute→verify

---

## 9. Security Notes & Limitations

> [!WARNING]
> **This tool is primarily educational.** It correctly demonstrates the concepts
> and uses standard library primitives properly, but it has limitations compared
> to production-grade password storage systems.

### Limitations

| Concern | This Tool | Production Recommendation |
|---------|-----------|---------------------------|
| Password hashing | PBKDF2-HMAC-SHA256 (600k iterations) | **Argon2id** (memory-hard, GPU-resistant) |
| Memory hardness | None — PBKDF2 is parallelizable on GPUs | Use **scrypt** or **Argon2id** |
| Key management | Keys passed as CLI arguments (visible in process list) | Use a proper secrets manager |
| Key storage | Not addressed | Use an HSM or secrets vault |
| Algorithm agility | SHA-256 / SHA-512 only | May need to support more algorithms |

### What this tool does correctly

- ✔ Uses `secrets` (CSPRNG) for salt generation, never `random`
- ✔ Reads files in chunks (never loads large files into memory)
- ✔ Uses `hmac.compare_digest` for all digest comparisons (constant-time)
- ✔ Proper PBKDF2 with 600,000 iterations by default
- ✔ No MD5 or SHA-1 (only SHA-256 / SHA-512)
- ✔ Graceful error handling with meaningful messages and non-zero exit codes

### References

- NIST FIPS 180-4 — SHA-256/SHA-512 specification
- NIST SP 800-132 — Recommendation for Password-Based Key Derivation
- RFC 2104 — HMAC: Keyed-Hashing for Message Authentication
- RFC 2898 / PKCS#5 — PBKDF2 specification
- RFC 4231 — HMAC-SHA256 test vectors
- RFC 7914 — The scrypt Password-Based Key Derivation Function
- Python `secrets` module documentation: https://docs.python.org/3/library/secrets.html
- SHAttered attack (SHA-1 collision): https://shattered.io
