#import "@preview/sleek-university-assignment:0.1.0": assignment

#show: assignment.with(
  title: "Cryptographic Timestamping Service",
  course: "Foundations of cybersecurity",
  authors: (
    (
      name: "Isaia Porcu - 635930",
      email: "Federico Volpi - 615725",
      student-no: "",
    ),
  ),

  university-logo: image("University_images/Stemma_unipi (1).png"),
)

#set heading(numbering: "1.1")

#outline(
  title: "Index", // Titolo dell'indice
  indent: auto,    // Rientro automatico per i sottotitoli (==)
  depth: 3,        // Profondità (mostra fino ai ===)
)
#pagebreak()

= Overview

The Timestamping Service (TSS) is a client-server application implementing a trusted third-party Time Stamping Authority (TSA). It allows registered users to submit cryptographic hashes of files/documents and receive back a cryptographically signed token binding the document's hash to a trusted timestamp. Users can subsequently verify these tokens to prove a document's existence at a specific time.

\

== Architectural components

1. *TSA Server* - _Server/Server.py_: A TCP-based server listening on port 1488. It handles connections, completes the secure handshake, validates credentials, tracks user token balances, issues timestamps, and verifies them.

2. *Client* - _Client/Client.py_: A command-line client enabling users to connect to the server, authenticate, check their usage balance, request timestamps, and verify existing timestamps.

3. *Database Simulator* - _Server/Database.py_: A persistent storage manager that manages registered users in a JSON file; it implements username/password authentication and handles usage counts (_available_ and _used_ timestamps quotas).

\

= Cryptographic design and primitives

The service is built around solid cryptographic principles ensuring *Perfect Forward Secrecy*, *authenticity*, *confidentiality* and *integrity*.

- *Server authentication to user*: The server possesses two distinct static RSA-4096 key pairs: ($"pubK"_"ts"$, $"privK"_"ts"$) & ($"pubK"_"c"$, $"privK"_"c"$)

  - *Connection Authentication Keys* ($"privK"_c$ / $"pubK"_c$): Used exclusively during the handshake to authenticate the server to the client. The client pre-loads the public key (implying that he gained it from a trusted _CA_).

  $->$ During the handshake, the server signs the ephemeral key transcript using $"privK"_c$. The client verifies this signature using pubKc, confirming the server's identity and preventing *Man-in-the-Middle* (*MitM*) attacks.

  The authentic $"pubK"_c$ is assumed to be provisioned to the client out-of-band, for example through a trusted installation step, a trusted configuration file, or a CA-based mechanism. The client does not learn $"pubK"_c$ from the unauthenticated network session itself.

- *Key exchange*: To implement *PFS*.

  Established using ephemeral *X25519 (ECDH)* keys. Both client and server generate a _new key pair for every session_.

- *Key Derivation Function (KDF)*:

  Once the X25519 shared secret is computed, both parties derive a 32-byte symmetric session key using *HKDF-SHA256* with an info parameter of _b"session encryption"_ and a salt value of _client_nonce_ $+$ _server_nonce_ (where both nonces are cryptographically secure random 32-byte sequences exchanged in plaintext during the handshake).

- *Symmetric Session Encryption*:

  All exchange messages post-handshake are encrypted using *ChaCha20Poly1305* (_an Authenticated Encryption with Associated Data_ - AEAD scheme). This protects the communication against eavesdropping and ensures message *non-malleability*.

- *Replay attack mitigation*:

  To prevent replay attacks (where an attacker intercepts and repeats encrypted command messages within the session - especially the most vulnerable message: _the timestamping_), a dynamic nonce-based challenge-response mechanism is implemented:

  1. Upon successful login, the server generates a cryptographically secure random 12-byte hex nonce.

  2. The server returns this nonce to the client inside the login outcome JSON.

  3. For every subsequent request (balance, timestamp, verify, quit), the client must include the current nonce in the request payload.

  4. The server decrypts the payload and verifies that the request nonce matches the expected message nonce.

    - If the nonce is valid, the server immediately generates a new 12-byte random hex nonce, invalidating the old one, and includes the new nonce in its response JSON, which the client stores for its next request.

- *Timestamp signatures*:

  When a user requests a timestamp for a hash, the server binds the binary hash to the UTC timestamp string (_%Y-%m-%dT%H:%M:%SZ_) by signing the concatenated bundle $"hash"||"timestamp"_"bytes"$ using $"privK"_"ts"$ with *RSA-PSS* padding and *SHA256*.

#pagebreak()

== Algorithm used and security objectives achieved

\

#table(
  columns: (auto, 2fr, 1.5fr, 2fr),
  align: (left, left, left, left),
  stroke: 0.5pt + luma(120),
  fill: (x, y) => if y == 0 { luma(240) } else { none },

  // Intestazioni
  [*Primitive / Algorithm*], [*System Component*], [*Primary Security Objective*], [*Mechanism & Verification*],

  // Riga 1
  [*X25519 (ECDH)*], [Ephemeral Handshake], [Perfect Forward Secrecy (PFS), Confidentiality], [Ephemeral key agreement. Key pairs are deleted after deriving the session key, protecting past traffic.],

  // Riga 2
  [*HKDF-SHA256*], [Key Derivation], [Session Key Independence], [Extracts uniform entropy from the shared secret and expands it using `client_nonce + server_nonce` as salt to ensure key uniqueness.],

  // Riga 3
  [*RSA-4096*], [Connection & Timestamp], [Authenticity, Integrity, Non-Repudiation, Malleability Defense], [Ephemeral transcript signed by `privKc` for channel auth; timestamp bundle signed by `privKts`.],

  // Riga 4
  [*ChaCha20Poly1305*], [Symmetric Session Encryption], [Confidentiality, Integrity, Ciphertext Non-malleability], [Encrypts payload with ChaCha20 stream cipher. Appends a Poly1305 MAC tag to verify authenticity and prevent bit-flipping.],

  // Riga 5
  [*Bcrypt*], [Database Credential Hashing], [Offline Dictionary & Rainbow Table Protection], [Slow key-stretching ($2^(12)$ rounds) with automatic random 16-byte salting to maximize precomputation and brute-force cost.],
)

#pagebreak()


= Exchanged Message formats

== Framing

After the initial handshake, all communication employs a structured length-prefixed protocol:

- _Header_: 4 bytes, Big-Endian Unsigned Integer (>I), indicating the length of the payload in bytes.

- Payload: The actual message bytes. For encrypted messages, the payload is structured as:

  - *Nonce*: 12 bytes (ChaCha20Poly1305 initialization vector).
  - *Ciphertext*: Variable bytes (the encrypted JSON string of the message).

\

== Plaintext handshake messages

During the handshake, keys are exchanged in raw binary format without encryption or framing:

1. *Client Ephemeral Public Key + Nonce (Client -> Server)*:

  - _Size_: $64$ bytes.
  - _Format_: _client_pub_bytes_ ($32$ bytes) concatenated with _client_nonce_ ($32$ bytes).

2. *Server Ephemeral Key + Nonce + Signature (Server -> Client)*

  - _Size_: 576 bytes.
  - _Format_: _server_pub_bytes_ ($32$ bytes) concatenated with _server_nonce_ ($32$ bytes) and a _signature_ ($512$ bytes).
  - The signature is an RSA-4096 signature over the complete handshake transcript:
    _client_pub_bytes_ $||$ _client_nonce_ $||$ _server_pub_bytes_ $||$ _server_nonce_.

3. *Handshake Confirmation (Server $->$ Client)*:

  - _Format_: Length-prefixed message ($4$-byte header + $20$-byte payload).
  - _Payload_: _b"Handshake successful"_

#pagebreak()




== Post-Handshake JSON Schemes

These JSON objects are the payloads of the encrypted messages that client and server exchange.


1. *Client Authentication (Login)*:

- Client $->$ Server:

#text(size: 14pt)[
  ```json
{
  "username": "<username_string>",
  "password": "<password_string>"
}
```
]

- Server $->$ Client: The success server reply includes the _first replay-prevention nonce_.

#text(size: 14pt)[
  ```json
{
  "status": "success",
  "nonce": "<12_byte_hex_nonce>"
}
```
]

2. *Balance Check*:

- Client $->$ Server:

#text(size: 14pt)[
  ```json
{
  "request": "balance",
  "nonce": "<current_replay_nonce>"
}
```
]

- Server $->$ Client:

#text(size: 14pt)[
  ```json
{
  "available": <integer_remaining_tokens>,
  "used": <integer_consumed_tokens>,
  "nonce": "<new_rotated_replay_nonce>"
}
```
]

3. *Hash Timestamping*:

- Client $->$ Server:

#text(size: 14pt)[
  ```json
{
  "request": "timestamp",
  "hash": "<hex_encoded_document_hash>",
  "nonce": "<current_replay_nonce>"
}
```
]

- Server $->$ Client:

  - _Success_:

	  #text(size: 14pt)[
	  ```json
	  {
	    "hash": "<hex_encoded_document_hash>",
	    "timestamp": "<UTC_time_string>",
	    "signature": "<hex_encoded_rsa_pss_signature>",
	    "nonce": "<new_rotated_replay_nonce>"
	  }
	  ```
  ]

  - _Failure_ (Quota exhausted):

  #text(size: 14pt)[
  ```json
  {
    "status": "failed",
    "message": "Uses exhausted!",
    "nonce": "<new_rotated_replay_nonce>"
  }
  ```
  ]

4. *Timestamp Verification*:

- Client $->$ Server:

#text(size: 14pt)[
  ```json
{
  "request": "verify",
  "hash": "<hex_encoded_document_hash>",
  "timestamp": "<UTC_time_string>",
  "signature": "<hex_encoded_rsa_pss_signature>",
  "nonce": "<current_replay_nonce>"
}
```
]

- Server $->$ Client:

  - _Valid timestamp_:

  #text(size: 14pt)[
  ```json
  {
    "status": "success",
    "valid": true,
    "message": "Timestamp is valid!",
    "nonce": "<new_rotated_replay_nonce>"
  }
  ```
  ]

  - _Invalid / Manipulated Timestamp_:

  #text(size: 14pt)[
  ```json
  {
    "status": "success",
    "valid": false,
    "message": "Invalid timestamp or altered data!",
    "nonce": "<new_rotated_replay_nonce>"
  }
  ```
  ]

\

5. *Quit Request*:

- Client $->$ Server:

#text(size: 14pt)[
  ```json
{
  "request": "quit",
  "nonce": "<current_replay_nonce>"
}
```
]

- Server $->$ Client: None - the socket is closed by both parties.

#pagebreak()

== Users credentials storage

To safeguard user credentials against server-side compromises, plaintext passwords are never written to disk. The simulator database stores credentials structured as:

\

#text(size: 14pt)[
  ```json
"Giacomo": {
    "password": "$2b$12$BKrwYnXiEXfTQHz2reiiN.EHlvWOpnDlCznSo3sxg.AubUYTmBGee",
    "available": 0,
    "used": 5
}
```
]

\

The following security properties are achieved:

1. *Rainbow Table Prevention*: The random 16-byte salt is _unique_ for every single database entry; precomputed tables of common password hashes cannot be used to recover passwords. If two users share the same password, their hashes will be different.

2. *Timing Side-Channel Protection*: The verification routine extracts the salt and cost parameter from the stored string, hashes the input password using those exact parameters, and performs a *constant-time byte comparison of the resulting hashes*.

\

=== Bcrypt format

The password hash string is exactly 60 characters long and adheres strictly to the modular crypt format utilized by _bcrypt_:

\

#align(center)[
  Format: \$$<"Variant">$\$$<"Rounds">$\$$<"Salt">$\$$<"Hash">$
]

\

_Example_ - "\$2b\$12\$BKrwYnXiEXfTQHz2reiiN.EHlvWOpnDlCznSo3sxg.AubUYTmBGee":

- "_\$2b\$_": Identifies the bcrypt algorithm version. The _2b_ variant is the modern standard.

- "_\$12\$_": Defines the work factor as $2^12 = 4096$ iterations of the library underlying algorithm.

- "_BKrwYnXiEXfTQHz2reiiN._": The salt of $22$ characters, randomly generated at registration time.

- "_EHlvWOpnDlCznSo3sxg.AubUYTmBGee_": Hash of $31$ characters.



#pagebreak()

= Communication protocol & Sequence diagram

1. *Connection & Cryptographic Handshake*: Establishes the secure channel using ephemeral X25519 keys, verifies server authenticity using the pre-shared RSA public key, and derives a session key with PFS.

\

#align(center)[
  #image("Diagrams/Handshake.png")
]

#pagebreak()

2. *Client Authentication (Login) & Nonce Initialization*: Validates the client's identity and issues the initial session nonce.

\

#align(center)[
  #image("Diagrams/Login.png")
]

#pagebreak()


3. *Session operations*: For every subsequent transaction, the client submits the current nonce. The server validates it, rotates it, and returns the new nonce.

- _Balance_:

\

#align(center)[
  #image("Diagrams/Balance.png")
]

\

- _Timestamping_:

\

#align(center)[
  #image("Diagrams/Timestamp.png")
]

\

#pagebreak()

- _Verification_:

\

#align(center)[
  #image("Diagrams/Veriffy.png")
]

\

- _Quit_:

\

#align(center)[
  #image("Diagrams/Quit.png")
]

\

#pagebreak()

= Demo logs

== Successful timestamp

\


#text(size: 14pt)[
  ```text
Welcome! What do you want to do?
0 - See my balance.
1 - Verify timestamp.
2 - Timestamp an hash.
3 - Quit.
Send request n. 2
Inserisci l'hash del documento da firmare (in formato HEX): 7b5cb4e5a9757657158434771605ec10e30d1d29fc2f0e0f3be8f45a278917e3
Working on timestamping, please wait...
[+] Server replied with:
{
    "hash": "7b5cb4e5a9757657158434771605ec10e30d1d29fc2f0e0f3be8f45a278917e3",
    "timestamp": "2026-06-21T19:02:54Z",
    "signature": "15d49ddf5e8d43bdecca5a9b037db49b48bad4995e75ea3dfa7528135dc4bdf90e...",
    "nonce": "77301cab77dcb540c7f01b27"
}
Welcome! What do you want to do?
0 - See my balance.
1 - Verify timestamp.
2 - Timestamp an hash.
3 - Quit.
Send request n.
```
]

\

== Timestamp verification

\

#text(size: 14pt)[
  ```text
Welcome! What do you want to do?
0 - See my balance.
1 - Verify timestamp.
2 - Timestamp an hash.
3 - Quit.
Send request n. 1
Inserisci l'hash del documento (in formato HEX): 7b5cb4e5a9757657158434771605ec10e30d1d29fc2f0e0f3be8f45a278917e3
Inserisci il timestamp (es. 2026-06-21T14:45:30Z): 2026-06-21T19:02:54Z
Inserisci la firma (in formato HEX): 15d49ddf5e8d43bdecca5a9b037db49b48bad4995e75ea3dfa7528135dc4bdf90e73939...
Working on verification, please wait...
[+] Server replied with:
{
    "status": "success",
    "valid": true,
    "message": "Timestamp is valid!",
    "nonce": "0d5b5a8bcefe6c8c3624e552"
}
```
]

== Unsuccessful timestamp


\

#text(size: 14pt)[
  ```text
[+] Connesso al server TSA su 127.0.0.1:1488
[+] Connessione stabilita con server
[>] Sending effimerate key to Server.
[+] [SERVER AUTHENTICATED]
[+] Canale sicuro stabilito (PFS abilitato).
[+] Server says: Handshake successful
Please insert your username:
Isaia
Please insert your password:
Isaia
[+] Login success!
Welcome! What do you want to do?
0 - See my balance.
1 - Verify timestamp.
2 - Timestamp an hash.
3 - Quit.
Send request n. 0
[+] Server replied with:
{
    "available": 0,
    "used": 5,
    "nonce": "5c392eb66ba74cefdf7a9949"
}
Welcome! What do you want to do?
0 - See my balance.
1 - Verify timestamp.
2 - Timestamp an hash.
3 - Quit.
Send request n. 2
Inserisci l'hash del documento da firmare (in formato HEX): 7b5cb4e5a9757657158434771605ec10e30d1d29fc2f0e0f3be8f45a278917e3
Working on timestamping, please wait...
[+] Server replied with:
{
    "status": "failed",
    "message": "Uses exhausted!",
    "nonce": "6fbec3958f5b07e394c52ba9"
}
Welcome! What do you want to do?
0 - See my balance.
1 - Verify timestamp.
2 - Timestamp an hash.
3 - Quit.
Send request n.
```
]
