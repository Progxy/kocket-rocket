# Crypto Stack

## 1. Overview
This document specifies the cryptographic subsystem used by the socket-based protocol for secure cross-machine communication.

The protocol provides:

- Confidentiality  
- Sender authentication  
- Integrity  
- Forward secrecy  
- Replay resistance  

The design is based on modern, standardized primitives:

- **X25519** for Diffie–Hellman key agreement (RFC 7748)  
- **Ed25519** for digital signatures (RFC 8032)  
- **HKDF-SHA256** for key derivation (RFC 5869)  
- **ChaCha20-Poly1305** for authenticated encryption (RFC 8439)  

The protocol follows the *KEM → KDF → AEAD* structure formalized in **HPKE** (RFC 9180).

---

## 2. Cryptographic Roles
### 2.1 Long-term recipient key
Each participant that receives encrypted messages possesses a **static X25519 keypair**:

- Private key: kept secret  
- Public key: distributed to peer systems and used for encryption  

### 2.2 Long-term sender identity key
Each participant possesses a **static Ed25519 keypair**:

- Private key: used to sign messages  
- Public key: transmitted in the wire format for sender identification  

### 2.3 Ephemeral sender key
For every encrypted message, the sender generates a **fresh ephemeral X25519 keypair** to ensure forward secrecy.

---

## 3. High-Level Protocol Flow
### 3.1 Sender Procedure

1. **Message signing**  
   `signed_message = signature || plaintext` (Ed25519, RFC 8032)

2. **Ephemeral key creation**  
   Generate ephemeral X25519 keypair (RFC 7748)

3. **Shared secret derivation**  
   shared_secret = X25519(ephemeral_priv, recipient_static_pub)

4. **Key derivation (HKDF-SHA256, RFC 5869)**  
- Input keying material (IKM): `shared_secret`  
- Salt: None  
- Info: 
  ```
  "X25519-CHACHA20POLY1305-v1" || sender_ed25519_pub || recipient_x25519_pub || sequence_number
  ```
- Output: `aead_key (32 bytes) || aead_nonce (12 bytes)`

5. **Authenticated encryption (ChaCha20-Poly1305, RFC 8439)**  
    ciphertext = ChaCha20Poly1305(aead_key).encrypt(aead_nonce, signed_message, aad)

6. **Wire message construction**  
See [§4](#4.-Wire-Format-Specification).

### 3.2 Recipient Procedure
1. Parse wire message and extract: ephemeral_pub, sequence_number, sender_pub, ciphertext, AAD.  
2. Validate sequence number for replay protection.  
3. Compute shared secret: shared_secret = X25519(recipient_priv, ephemeral_pub)
4. Derive AEAD key and nonce via HKDF-SHA256.  
5. Decrypt ciphertext with ChaCha20-Poly1305 using provided AAD.  
6. Split signature and message (`signature || plaintext`).  
7. Verify Ed25519 signature using sender public key.  
8. Deliver plaintext to upper layers.

---

## 4. Wire Format Specification
All integers are **little-endian**.

| Field                | Size       |
|----------------------|------------|
| version              | (1 byte)   |
| flags                | (1 byte)   |
| ephemeral_x25519_pub | (32 bytes) |
| sender_ed25519_pub   | (32 bytes) |
| sequence_number      | (8 bytes)  |
| aad_length           | (2 bytes)  |
| aad                  | (variable) |
| ciphertext_and_tag   | (variable) |

| Field                | Description                                                     |
|----------------------|-----------------------------------------------------------------|
| version              | Protocol version                                                |
| flags                | Reserved for future extensions                                  |
| ephemeral_x25519_pub | Ephemeral public key for forward secrecy (RFC 7748)             |
| sender_ed25519_pub   | Sender identity key (RFC 8032)                                  |
| sequence_number      | Monotonic counter for replay protection                         |
| aad_length           | Length of AAD in bytes                                          |
| aad                  | Application-controlled Associated Authenticated Data            |
| ciphertext_and_tag   | ChaCha20-Poly1305 ciphertext with authentication tag (RFC 8439) |

---

## 5. Replay Protection
- Sequence number is incremented for each message.  
- Recipient maintains the highest accepted sequence number per peer.  
- Messages with sequence numbers ≤ last accepted are rejected.

---

## 6. Security Properties
- **Confidentiality**: ChaCha20-Poly1305 AEAD  
- **Integrity & authenticity**: AEAD + Ed25519 signature  
- **Forward secrecy**: ephemeral X25519 keys  
- **Key compromise impersonation (KCI) resistance**: AEAD keys are ephemeral per message  
- **Nonce uniqueness**: Derived deterministically from unique ephemeral secrets

---

## 7. References
 - [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748) — Elliptic Curves for Security (Curve25519 / X25519)
 - [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032) — Edwards-Curve Digital Signature Algorithm (Ed25519)
 - [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
 - [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) — ChaCha20 and Poly1305 for IETF Protocols
 - [RFC 9180](https://datatracker.ietf.org/doc/html/rfc9180) — Hybrid Public Key Encryption (HPKE)
 - [RFC 6234](https://datatracker.ietf.org/doc/html/rfc6234) — (SHA-512).

