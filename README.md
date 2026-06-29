# Timestamping Service Project

This project implements a simple Time Stamping Service (TSS) for the Foundations of Cybersecurity course.

The system has two programs:

- `Server/Server.py`: starts the Timestamping Authority server.
- `Client/Client.py`: starts an interactive command-line client.

The client connects to the server, establishes a secure channel, authenticates with username and password, and can then request timestamping, balance, and verification operations.

## Requirements

Use the local `.venv` through `uv` from the project root:

```bash
pip install -r requirements.txt
```

## Starting the Server

Open a terminal and run:

```bash
python Server/Server.py
```

The server listens on:

```text
127.0.0.1:1488
```

Keep this terminal open while using the client.

## Starting the Client

Open a second terminal and run:

```bash
python Client/Client.py
```

The client will connect to the server and ask for username and password.

Current users are stored in:

```text
Server/DB/status.json
```

At the moment, the database contains these accounts:

```text
Isaia
Mattia
Giacomo
```

If you do not know a user's password, create a new user or reset the database with `Server/Database.py`.

## Creating a New User

Run:

```bash
python Server/Database.py
```

The script asks for a username and password, then stores the user in `Server/DB/status.json`.

Each new user receives the default timestamp volume defined in `Database.py`.

## Using the Client

After login, the client shows this menu:

```text
0 - See my balance.
1 - Verify timestamp.
2 - Timestamp an hash.
3 - Quit.
```

### Option 0: Balance

Shows how many timestamps the user has already consumed and how many are still available.

Example response:

```json
{
    "available": 9,
    "used": 1,
    "counter": 1
}
```

### Option 2: Timestamp a Hash

Choose option `2` and paste a document hash in hexadecimal format.

Example hash:

```text
a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890
```

The server returns:

```json
{
    "hash": "...",
    "timestamp": "2026-06-21T14:45:30Z",
    "signature": "...",
    "counter": 1
}
```

Save the returned `hash`, `timestamp`, and `signature` if you want to verify the timestamp later.

If the user has no timestamps left, the server returns:

```json
{
    "status": "failed",
    "message": "Uses exhausted!",
    "counter": 1
}
```

### Option 1: Verify Timestamp

Choose option `1` and insert:

```text
hash
timestamp
signature
```

The server checks whether the signature is valid for:

```text
hash || timestamp
```

If the timestamp token is valid, the response is:

```json
{
    "status": "success",
    "valid": true,
    "message": "Timestamp is valid!",
    "counter": 1
}
```

If the hash, timestamp, or signature has been modified, the response is:

```json
{
    "status": "success",
    "valid": false,
    "message": "Invalid timestamp or altered data!",
    "counter": 1
}
```

### Option 3: Quit
Closes the client connection.

## Notes

The server uses the key pair in `Server/TSA_Keys/` for timestamp signatures.

The assignment description mentions two key pairs:

```text
pubKc / privKc   for secure-channel authentication
pubKts / privKts for timestamp signatures
```

This implementation uses both pairs:

- `privKc / certKc` authenticate the server during the secure-channel handshake. The certificate contains `pubKc`.
- `privKts / pubKts` sign and verify timestamp tokens.

To regenerate both key pairs, run:

```bash
python Server/Signing_key_generation.py
```

This overwrites the existing files in `Server/TSA_Keys/`, including the server certificate `certKc.pem`.
