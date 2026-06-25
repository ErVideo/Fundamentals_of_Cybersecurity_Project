import json
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import padding
from Database import DataBase
import socket
import struct
import os

# Database simultator
db = DataBase()

# Internal messages
ERROR = "Error"

# Server configuration
HOST = "127.0.0.1"
PORT = 1488
# Server connection-authentication keys
PATH_PRIV_KC = "TSA_Keys/privKc.pem"
PATH_PUB_KC = "TSA_Keys/pubKc.pem"
# Server timestamp-signing keys
PATH_PRIV_KTS = "TSA_Keys/privKts.pem"
PATH_PUB_KTS = "TSA_Keys/pubKts.pem"
privKc = ""
pubKc = ""
pubKts = ""
privKts = ""
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Load secure-channel authentication private key
with open(f"{BASE_DIR}/{PATH_PRIV_KC}", "rb") as key_file:
    privKc = serialization.load_pem_private_key(
        key_file.read(),
        password=None
    )

# Load secure-channel authentication public key
with open(f"{BASE_DIR}/{PATH_PUB_KC}", "rb") as key_file:
    pubKc = serialization.load_pem_public_key(
        key_file.read()
    )

# Load timestamp-signing private key
with open(f"{BASE_DIR}/{PATH_PRIV_KTS}", "rb") as key_file:
    privKts = serialization.load_pem_private_key(
        key_file.read(),
        password=None
    )

# Load timestamp-signing public key
with open(f"{BASE_DIR}/{PATH_PUB_KTS}", "rb") as key_file:
    pubKts = serialization.load_pem_public_key(
        key_file.read()
    )

print("[+] Connection and timestamp keys loaded.")


def send_structured_message(conn, payload_bytes):
    lunghezza = len(payload_bytes)
    header = struct.pack('>I', lunghezza)
    # Sends 4 bytes of header (size of message) and then the payload
    conn.sendall(header + payload_bytes)

def receive_structured_message(conn):
    header = conn.recv(4)
    if not header:
        return None
    lunghezza = struct.unpack('>I', header)[0]
    
    # Reads exactly the number of bytes needed
    return conn.recv(lunghezza)

def handshake(conn):
    # Receives client effimerate key
    client_pub_bytes = conn.recv(32)
    if len(client_pub_bytes) != 32:
        print("[-] Errore: Client pubblic key invalid.")
        return ERROR
    
    # Ephemeral key used for this session's X25519 key exchange
    server_ephemeral_private = x25519.X25519PrivateKey.generate()
    server_ephemeral_public = server_ephemeral_private.public_key()
    server_pub_bytes = server_ephemeral_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    client_public_key = x25519.X25519PublicKey.from_public_bytes(client_pub_bytes)
    print("[<] Received client effimerate key.")

    try:
        signature = privKc.sign(
            server_pub_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception as e:
        print(f"[-] Error during signing process: {e}")
        send_structured_message(conn,  b"Signing failed!")
        return

    # Effimerate key (32 byte) and RSA sign (512 byte) combining
    handshake_payload = server_pub_bytes + signature
    
    # Send the bundle to the client
    conn.sendall(handshake_payload)
    print("[>] Effimerate + signature sent to client.")
    
    # Simmetric key computation
    shared_secret = server_ephemeral_private.exchange(client_public_key)

    session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"session encryption",
        ).derive(shared_secret)
    print("[+] Secure channel established.")

    cipher = ChaCha20Poly1305(session_key)

    return cipher

def login(conn, cipher):
    data_received = receive_structured_message(conn)
    
    if not data_received or len(data_received) < 12:
        print("[-] Errore: Invalid login message (or too tiny).")
        return ERROR
    
    nonce = data_received[:12]
    ciphertext = data_received[12:]

    try:
        json_message = decrypt_json(cipher, nonce, ciphertext)
        print(f"[+] Client credentials received: {json_message}")
        
        username = json_message.get("username")
        password = json_message.get("password")
        
        if db.login(username, password):
            return json_message
        return ERROR

    except Exception as e:
        print(f"[-] Attack or integrity checks failed: {e}")
        return ERROR


def timestamp(conn, cipher, hash, username, nonce_replay):
    if db.timeStamp(username) == False:
        send_structured_message(conn, encrypt_json({"status": "failed", "message": "Uses exhausted!", "nonce": nonce_replay}, cipher))
        return
    # Time generation
    current_time_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    time_bytes = current_time_str.encode('utf-8')
    bundle = hash + time_bytes
    #Signing
    try:
        signature = privKts.sign(
            bundle,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception as e:
        print(f"[-] Error during signing process: {e}")
        send_structured_message(conn,  encrypt_json({"status": "failed", "message": "Signing error", "nonce": nonce_replay}, cipher))
        return
    
    reply = {"hash": hash.hex(), "timestamp": current_time_str, "signature": signature.hex(), "nonce": nonce_replay}
    send_structured_message(conn,  encrypt_json(reply, cipher))
    db.timeStamped(username)

def verify(conn, cipher, hash, timestamp, signature, nonce_replay):
    # 1. Reconstruct original bundle: (hash || time)
    time_bytes = timestamp.encode('utf-8')
    bundle = hash + time_bytes
    
    # 2. Trying the verification using the server public key for signatures (pubKts)
    try:
        pubKts.verify(
            signature,
            bundle,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        # If .verify() doesn't cause exceptions then it's all good!
        print("[+] Verifica riuscita: il timestamp è valido ed autentico.")
        reply = {"status": "success", "valid": True, "message": "Timestamp is valid!", "nonce": nonce_replay}
        
    except Exception as e:
        # If alterations are detected
        print(f"[-] Verifica fallita: firma non valida o dati manipolati! ({e})")
        reply = {"status": "success", "valid": False, "message": "Invalid timestamp or altered data!", "nonce": nonce_replay}
        
    # 3. Outcome reply
    send_structured_message(conn, encrypt_json(reply, cipher))

def balance(conn, cipher, username, nonce_replay):
    data = db.getData(username)
    message_json = {"available": data.get("available"), "used": data.get("used"), "nonce": nonce_replay}
    send_structured_message(conn, encrypt_json(message_json, cipher))

def encrypt_json(data_dict, cipher):
    json_string = json.dumps(data_dict)
    payload_bytes = json_string.encode("utf-8")
    
    # Generates a random nonce of 12 bytes (for ChaCha20Poly1305)
    nonce = os.urandom(12)
    
    # Encryption
    ciphertext = cipher.encrypt(nonce, payload_bytes, associated_data=None)
    
    # Returns nonce + cipher
    # [:12] for nonce and [12:] for ciphertext
    return nonce + ciphertext

def decrypt_json(cipher, nonce, ciphertext):
    decrypted_bytes = cipher.decrypt(nonce, ciphertext, associated_data=None)
    return json.loads(decrypted_bytes.decode("utf-8"))


# Server waits for Client message
while(True):
    # Open network interfacing
    #Socket creation (AF_INET = IPv4, SOCK_STREAM = TCP)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # Quick fix for server reboot (Port may result unavailable for a while)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"[*] Server in ascolto su {HOST}:{PORT}...")

        # Server stalls until connection
        conn, addr = server_socket.accept()
        with conn:
            print(f"[+] Connessione stabilita con {addr}")

            # Handshake -> Authentication & Effimeral keys generation
            cipher = handshake(conn)
            if cipher == ERROR:
                conn.close()
                continue
            else:
                send_structured_message(conn, b"Handshake successful")

            print(f"[+] Handshake with {addr} successful")

            # Login -> Client, username and password exchange
            outcome = login(conn, cipher)
            if(outcome == ERROR):
                conn.close()
                continue
            

            # Anti-replay attacks nonce (challenge) generation - 12 bytes
            nonce_replay = os.urandom(12).hex()
            send_structured_message(conn, encrypt_json({"status": "success", "nonce": nonce_replay}, cipher))

            # Rapid renaming
            credentials = outcome

            while(True):
                # Waiting for user request message
                data_received = receive_structured_message(conn)

                if not data_received or len(data_received) < 12:
                    print("[-] Connessione or data invalid from {addr}.")
                    conn.close()
                    break
    
                nonce = data_received[:12]
                ciphertext = data_received[12:]
                try:
                    json_message = decrypt_json(cipher, nonce, ciphertext)
                except Exception as e:
                    print(f"[-] Decyper error {addr}: {e}")
                    conn.close()
                    break

                # Replay attack check
                if(json_message.get("nonce") != nonce_replay):
                    print("[-] Replay attack detected!")
                    conn.close()
                    break

                # New nonce
                nonce_replay = os.urandom(12).hex()

                if(json_message["request"] == "verify"):
                    clean_hash = json_message["hash"].strip()
                    clean_sig = json_message["signature"].strip()
                    try:
                        verify(conn, cipher, bytes.fromhex(clean_hash), json_message["timestamp"], bytes.fromhex(clean_sig), nonce_replay)
                    except Exception as e:
                        print("[-] Malformed hash and/or signature")
                        send_structured_message(conn, encrypt_json({"status": "failed", "nonce": nonce_replay}, cipher))
                if(json_message["request"] == "timestamp"):
                    clean_hash = json_message["hash"].strip()
                    try:
                        timestamp(conn, cipher, bytes.fromhex(clean_hash), credentials["username"], nonce_replay)
                    except Exception as e:
                        print("[-] Malformed hash and/or signature")
                        send_structured_message(conn, encrypt_json({"status": "failed", "nonce": nonce_replay}, cipher))
                if(json_message["request"] == "balance"):
                    balance(conn, cipher, credentials["username"], nonce_replay)
                if(json_message["request"] == "quit"):
                    conn.close()
                    break

