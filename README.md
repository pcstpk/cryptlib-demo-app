# P2P Encrypted Messaging Demo

A simple 2-peer demonstration of end-to-end encryption using ECDH and Kyber key exchange algorithms.

## Overview

This project illustrates:
- **Key Exchange**: ECDH (Elliptic Curve Diffie-Hellman) and Kyber (post-quantum KEM)
- **Encryption**: AES-256-GCM (authenticated encryption)
- **Direct P2P**: Alice (listener) <-> Bob (connector) on localhost

## Components

- **`p2p_demo.py`**: Main application (run as `--role alice` or `--role bob`)
- **`cryptolib_adapter.py`**: Wrapper around cryptlib (ECDH/Kyber) and cryptography (AEAD)
- **`cryptlib/`**: Post-quantum and ECC cryptography library

## Quick Start

### Prerequisites
```bash
pip install cryptography
# cryptlib is local in ./cryptlib/
```

### Run (two terminals)

**Terminal 1 (Alice, listener):**
```bash
python p2p_demo.py --role alice --algo ECDH --verbose
```

**Terminal 2 (Bob, connector):**
```bash
python p2p_demo.py --role bob --algo ECDH --verbose
```

Type messages in either terminal. First message triggers a handshake automatically.

## Algorithms

- **PLAIN**: No encryption (plaintext only)
- **ECDH**: Elliptic Curve Diffie-Hellman (P-256) + AES-256-GCM
- **KYBER**: Kyber-512 KEM (post-quantum) + AES-256-GCM

Change with `--algo PLAIN|ECDH|KYBER`.

## Handshake Flow

### ECDH
1. Initiator (Bob) sends public key
2. Responder (Alice) replies with public key
3. Both derive shared secret from peer's public key
4. Both derive AEAD key from shared secret via HKDF-SHA256
5. Exchange encrypted messages

### Kyber
1. Initiator (Bob) sends public key
2. Responder (Alice) replies with public key
3. Initiator encapsulates against responder's public key, sends ciphertext
4. Responder decapsulates to recover shared secret
5. Both derive AEAD key via HKDF-SHA256
6. Exchange encrypted messages

## Verbose Output

With `--verbose`, see:
- Base64-encoded public keys and ciphertexts
- Shared secret fingerprints
- Handshake progress

## Commands

- Type any message to send
- `/status`: Show handshake state
- `/quit`: Exit

## Notes

- Alice listens on 127.0.0.1:9001
- Bob auto-retries connection until Alice is ready
- All keys are derived from a single shared secret per peer
- AEAD uses random 12-byte nonce per message; reuse prevents forgery attacks
