"""Simple 2-peer demo (alice <-> bob) illustrating ECDH/Kyber handshakes and AEAD.

Usage examples (run in two terminals):

# Terminal 1 (alice, listener):
python p2p_demo.py --role alice --algo ECDH --verbose

# Terminal 2 (bob, connector):
python p2p_demo.py --role bob --algo ECDH --verbose

Behavior:
- alice listens on localhost:9001
- bob connects to alice:9001
- First message triggers handshake (public-key exchange / encapsulation)
- Subsequent messages are encrypted with AES-GCM using a derived key
- Verbose mode prints base64 keys and short shared fingerprints
"""

import argparse
import socket
import threading
import time
import json
import base64
import sys
from typing import Optional

from crypto_adapter import CryptoAdapter

ALICE_PORT = 9001
HOST = '127.0.0.1'


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')


def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode('ascii'))


class PeerDemo:
    def __init__(self, role: str, algo: str, verbose: bool = False):
        self.role = role
        self.algo = algo.upper()
        self.verbose = verbose
        self.sock: Optional[socket.socket] = None
        self.adapter: Optional[CryptoAdapter] = None
        if self.algo != 'PLAIN':
            self.adapter = CryptoAdapter(algorithm=self.algo)

        # handshake state
        self.sent_pub = False  # True if WE sent our public key
        self.is_initiator = False  # True if WE sent public key first
        self.have_shared = False
        self.shared = None
        self.aead_key = None
        self.my_pub = None
        self.peer_pub = None

        self.recv_thread = None
        self.running = True

    def start(self):
        """Establish network connection and start handshake + message loop.
        
        Flow:
        1. Alice listens on port 9001; Bob connects to her.
        2. Background thread continuously receives and dispatches messages.
        3. Main thread runs CLI loop: user types messages, which trigger handshake on first send.
        """
        if self.role == 'alice':
            self._start_alice()
        else:
            self._start_bob()
        # start receiver thread
        self.recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self.recv_thread.start()
        # start CLI loop
        self._cli_loop()

    def _start_alice(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, ALICE_PORT))
        s.listen(1)
        print('alice: listening on', (HOST, ALICE_PORT))
        conn, addr = s.accept()
        self.sock = conn
        print('alice: connected by', addr)

    def _start_bob(self):
        # bob connects to alice
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:
            try:
                s.connect((HOST, ALICE_PORT))
                self.sock = s
                print('bob: connected to alice')
                break
            except Exception:
                print('bob: waiting for alice...')
                time.sleep(0.5)

    def _recv_loop(self):
        """Background thread: continuously receive JSON-lines and dispatch by message type.
        
        Reads socket in blocking mode; accumulates bytes and splits on newline.
        Each line is a JSON message with a 'type' field.
        Dispatches to appropriate handler (_on_pub, _on_ct, _on_enc) based on type.
        Stops gracefully on socket close or exception.
        """
        buf = b''
        while self.running:
            try:
                data = self.sock.recv(4096)
            except Exception:
                break
            if not data:
                break
            buf += data
            while b'\n' in buf:
                line, buf = buf.split(b'\n', 1)
                if not line:
                    continue
                try:
                    msg = json.loads(line.decode())
                except Exception:
                    print('invalid message')
                    continue
                self._handle_msg(msg)
        print('recv loop exiting')
        self.running = False

    def _send(self, msg: dict):
        if not self.sock:
            print('no socket')
            return
        try:
            self.sock.send((json.dumps(msg) + '\n').encode())
        except Exception as e:
            print('send error', e)
            self.running = False

    def _handle_msg(self, msg: dict):
        """Dispatch received message by type field.
        
        Supported types:
        - 'pub': Public key exchange (ECDH or Kyber initial key material)
        - 'ct':  Kyber ciphertext (responder only)
        - 'enc': Encrypted message (symmetric payload)
        """
        t = msg.get('type')
        if t == 'pub':
            self._on_pub(msg)
        elif t == 'ct':
            self._on_ct(msg)
        elif t == 'msg_plain':
            print(f"[peer] {msg.get('text')}")
        elif t == 'msg_enc':
            self._on_enc(msg)
        else:
            print('unknown msg type', t)

    def _on_pub(self, msg: dict):
        """Handle public key exchange message.
        
        Flow:
        1. ECDH: Both sides exchange public keys and immediately derive the shared secret.
           Each side computes: shared = ECDH(their_privkey, peer_pubkey)
        
        2. KYBER (asymmetric):
           - Responder (receives pub first): sends own pub back, waits for ciphertext
           - Initiator (sends pub first): receives responder's pub, then encapsulates a shared
             secret against it, sends ciphertext
        
        Initiator flag is set when we receive a pub but haven't sent ours yet (making us responder).
        """
        peer_algo = msg.get('algo', 'ECDH').upper()
        pub = ub64(msg.get('pub'))
        self.peer_pub = pub
        if self.verbose:
            print('received peer pub:', b64(pub))
        # If we are PLAIN or algorithm mismatch, ignore
        if self.algo == 'PLAIN' or peer_algo != self.algo:
            if peer_algo != self.algo:
                print('algorithm mismatch')
            return

        # ensure we have our keypair
        if not self.my_pub:
            self.my_pub = self.adapter.generate_keypair()
        
        # If we haven't sent our pub yet, send it now (we are the responder)
        if not self.sent_pub:
            self._send({'type': 'pub', 'algo': self.algo, 'pub': b64(self.my_pub)})
            self.sent_pub = True
            self.is_initiator = False  # We didn't send first, so we're responder
            if self.verbose:
                print('sent our pub (responder)')

        if self.algo == 'ECDH':
            # ECDH is symmetric: both sides derive shared secret from each other's public key
            if not self.have_shared:
                shared = self.adapter.derive_shared_secret(pub)
                self.shared = shared
                self.aead_key = self.adapter.derive_aead(shared)
                self.have_shared = True
                print('ECDH shared established')
                if self.verbose:
                    print('shared (b64):', b64(self.shared))
        else:  # KYBER
            # KYBER is asymmetric: only the initiator (who sent pub first) encapsulates
            if self.is_initiator and not self.have_shared:
                # We sent our pub first, so we encapsulate against peer's pub
                ct, shared = self.adapter.encapsulate(pub)
                self.shared = shared
                self.aead_key = self.adapter.derive_aead(shared)
                self.have_shared = True
                self._send({'type': 'ct', 'ct': b64(ct)})
                print('Kyber: encapsulation sent (initiator). Shared established')
                if self.verbose:
                    print('shared (b64):', b64(self.shared))
            else:
                # We are responder: wait for ct
                if self.verbose:
                    print('Kyber responder: waiting for encapsulation')

    def _on_ct(self, msg: dict):
        """Handle Kyber ciphertext message (responder only).
        
        Only called in KYBER mode when responder receives the initiator's ciphertext.
        Decapsulates the ciphertext to recover the shared secret that the initiator generated.
        """
        ct = ub64(msg.get('ct'))
        if self.algo != 'KYBER':
            return
        # decapsulate
        shared = self.adapter.decapsulate(ct)
        self.shared = shared
        self.aead_key = self.adapter.derive_aead(shared)
        self.have_shared = True
        print('Kyber: decapsulated and shared established')
        if self.verbose:
            print('shared (b64):', b64(self.shared))

    def _on_enc(self, msg: dict):
        """Decrypt and display an incoming encrypted message.
        
        Requires handshake to be complete (have_shared = True).
        Decrypts using AES-256-GCM with the AEAD key derived from shared secret.
        """
        if not self.have_shared:
            print('[peer] sent encrypted message but no shared key')
            return
        nonce = ub64(msg.get('nonce'))
        payload = ub64(msg.get('payload'))
        try:
            plain = self.adapter.aead_decrypt(self.aead_key, nonce, payload)
            print(f'[peer] {plain.decode()}')
        except Exception:
            print('[peer] <decrypt failed>')

    def _cli_loop(self):
        """Interactive message loop: read user input and send encrypted messages.
        
        Handshake logic:
        1. On first encrypted message, generate our keypair and send public key.
        2. Mark ourselves as initiator (is_initiator = True).
        3. Wait up to 10 seconds for handshake to complete (peer's pub + derivation).
        4. Once have_shared = True, encrypt and send messages with AES-256-GCM AEAD.
        
        Commands:
        - /quit: exit cleanly
        - /status: show handshake state (sent_pub, have_shared)
        - Any text: send as encrypted message (or plaintext if PLAIN mode)
        """
        print('Type messages to send. First send will initiate handshake if needed.')
        try:
            while self.running:
                line = input().strip()
                if not line:
                    continue
                if line == '/quit':
                    self.running = False
                    break
                if line == '/status':
                    print('sent_pub=', self.sent_pub, 'have_shared=', self.have_shared)
                    continue

                # If PLAIN, just send
                if self.algo == 'PLAIN':
                    self._send({'type': 'msg_plain', 'text': line})
                    continue

                # For ECDH/KYBER, ensure handshake
                if not self.have_shared:
                    # Prepare our keypair and send pub if not sent
                    if not self.my_pub:
                        self.my_pub = self.adapter.generate_keypair()
                    if not self.sent_pub:
                        self._send({'type': 'pub', 'algo': self.algo, 'pub': b64(self.my_pub)})
                        self.sent_pub = True
                        self.is_initiator = True  # We sent first
                        if self.verbose:
                            print('sent our pub (initiator)')
                    # Wait for handshake to complete (simple loop)
                    wait_secs = 0
                    while not self.have_shared and wait_secs < 10:
                        time.sleep(0.2)
                        wait_secs += 0.2
                    if not self.have_shared:
                        print('handshake failed or timed out')
                        continue

                # Now we have aead_key; encrypt and send
                nonce, ct = self.adapter.aead_encrypt(self.aead_key, line.encode())
                msg = {'type': 'msg_enc', 'nonce': b64(nonce), 'payload': b64(ct)}
                self._send(msg)
        except KeyboardInterrupt:
            self.running = False
        finally:
            try:
                if self.sock:
                    self.sock.close()
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--role', choices=['alice', 'bob'], required=True)
    parser.add_argument('--algo', choices=['PLAIN', 'ECDH', 'KYBER'], default='ECDH')
    parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()

    demo = PeerDemo(args.role, args.algo, args.verbose)
    demo.start()


if __name__ == '__main__':
    main()
