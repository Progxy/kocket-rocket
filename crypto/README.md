# Crypto Stack

## Overview
This extension provides an authenticated, confidential envelope for messages
transmitted over your existing socket-based communication channel. The design
follows modern hybrid encryption patterns used in TLS 1.3 / HPKE: ephemeral
Diffie–Hellman (X25519) to establish shared key material, HKDF-SHA256 to derive
AEAD key and nonce, ChaCha20-Poly1305 for AEAD encryption, and Ed25519 for
message signatures.

**Key design goals**
- Confidentiality (AEAD encryption)
- Authenticity (Ed25519 signatures)
- Forward secrecy (ephemeral X25519 per message)
- Deterministic and safe key/nonce derivation (HKDF)
- Simple replay protection (sequence numbers)

## Cryptographic primitives (standards / RFCs)
- **X25519** (ECDH) — RFC 7748. Used as the KEM to derive a shared secret between sender ephemeral private key and recipient static public key.
- **Ed25519** (signatures) — RFC 8032. Used to sign plaintext before encryption (sign-then-encrypt).
- **HKDF-SHA256** — RFC 5869. Used to derive AEAD key and nonce from the raw shared secret.
- **ChaCha20-Poly1305** (AEAD) — RFC 8439. Used for authenticated encryption of the signed plaintext.
- **HPKE** (concept: KEM + KDF + AEAD) — RFC 9180. Use HPKE for a formalized API; this design follows the same pattern.

## Wire format

All integers are little-endian unless otherwise noted.

Fields of Crypto Structure:
- `version` — Protocol version (currently `0x01`)
- `flags` — reserved (for future use)
- `eph_pub` — ephemeral X25519 public key (32 bytes)
- `sender_ed25519_pub` — sender's Ed25519 public key (32 bytes) (optional if you manage pubkeys out-of-band)
- `seq` — 8-byte sequence number (unsigned integer). Use per-sender monotonic sequence for replay protection
- `aad_len` — 2-byte length of AAD
- `aad` — Associated Authenticated Data (e.g., channel identifiers, protocol version, etc.)
- `ciphertext_and_tag` — AEAD output (variable)

## Sender flow (Encrypt)
1. **Sign**: `sig = Ed25519(signing_priv, message)` (RFC 8032)  
   `signed_plaintext = sig || message`

2. **Ephemeral key**: generate ephemeral X25519 key pair `(eph_priv, eph_pub)` (RFC 7748).

3. **ECDH**: `shared = X25519(eph_priv, recipient_static_pub)` (raw 32 bytes).

4. **KDF**: Derive AEAD key and nonce via HKDF-SHA256:
    HKDF(salt=None, info = protocol_id || sender_pub || recipient_pub || seq) -> key (32 bytes) || nonce (12 bytes) (RFC 5869)

5. **AEAD encrypt**: `ciphertext = ChaCha20-Poly1305(key).encrypt(nonce, signed_plaintext, aad)` (RFC 8439).

6. **Wire**: transmit `version||flags||eph_pub||sender_ed25519_pub||seq||aad_len||aad||ciphertext`.

## Recipient flow (Decrypt)
1. Parse wire, extract `eph_pub`, `sender_ed25519_pub`, `seq`, `aad`, `ciphertext`.

2. Validate `seq` against expected sequence number(s) to mitigate replay.

3. Compute `shared = X25519(recipient_priv, eph_pub)`.

4. Derive key and nonce via the same HKDF parameters.

5. AEAD decrypt to obtain `signed_plaintext`.

6. Split signature and message (`sig || message`) and verify `Ed25519` signature using `sender_ed25519_pub`.

## Design choices and rationale
- **Sign-then-encrypt**: We sign the plaintext (not the ciphertext). This allows the recipient to verify the message origin and integrity even after decryption, and avoids some pitfalls of attempting to sign ciphertext which may leak structure.
- **Ephemeral X25519**: Ephemeral per-message key affords forward secrecy: a compromise of recipient static key does not reveal past messages.
- **HKDF for key + nonce**: Using HKDF ties the AEAD key and nonce to the shared secret in a standardized, auditable way. Including `sender_pub || recipient_pub || seq` inside `info` prevents key reuse across different contexts.
- **Sequence numbers**: Basic replay protection. Consider a window and reordering policy for higher performance networks.

## Security cautions & operational recommendations
- **Authenticate static public keys**: To prevent MITM, the recipient static public key must be verified/pinned by the sender (PKI, certificates, or pre-shared). HPKE's auth modes or TLS-style certificates address this.
- **Nonce management**: Nonce uniqueness is critical for ChaCha20-Poly1305. With ephemeral per-message keys derived from ECDH, deterministic nonce derivation via HKDF is safe because the key is unique per ephemeral. If you switch to reusing ephemeral keys for multiple messages, derive nonces using a counter or choose XChaCha20-Poly1305 with safe randomness.
- **Protect private keys**: Guard long-term private keys in secure storage (HSM, TPM, or OS-protected memory). If handling keys in kernel space, limit exposure and use kernel crypto APIs if available; prefer userland libraries.
- **RNG**: Use a CSPRNG for ephemeral keys and any random nonces. On Linux, use `getrandom()`/`os.urandom()`.

## Interoperability & alternatives
- **HPKE (RFC 9180)** is a full standard that formalizes KEM+KDF+AEAD patterns. Consider using an HPKE library instead of a custom ad-hoc packing if you want features like authenticated mode and KEM/KDF recipes.
- **TLS 1.3** offers a mature handshake and record layer; if you need sessions, renegotiation, and certificate-based authentication, TLS 1.3 is a robust alternative.
- **libsodium** and `crypto_box` / `crypto_kx` provide simpler high-level APIs for common tasks and are recommended if you want fewer low-level choices.

## References
 - [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748) — Elliptic Curves for Security (Curve25519 / X25519)
 - [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032) — Edwards-Curve Digital Signature Algorithm (Ed25519)
 - [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
 - [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) — ChaCha20 and Poly1305 for IETF Protocols
 - [RFC 9180](https://datatracker.ietf.org/doc/html/rfc9180) — Hybrid Public Key Encryption (HPKE)
 - [RFC 6234](https://datatracker.ietf.org/doc/html/rfc6234) — (SHA-512).

