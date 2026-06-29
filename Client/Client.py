import json
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import padding
import socket
import struct
import os

# Server configuration
HOST = "127.0.0.1"
PORT_SERVER = 1488

# Internal messages
ERROR = "Error"

pubKc = ""

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PATH_PUB_KC = "../Server/TSA_Keys/pubKc.pem"

# Load server secure-channel authentication public key
with open(f"{BASE_DIR}/{PATH_PUB_KC}", "rb") as key_file:
    pubKc = serialization.load_pem_public_key(
        key_file.read()
    )

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
    try:
        # Client effimeral key generation
        priv_kc_effimera = x25519.X25519PrivateKey.generate()
        pub_kc_effimera = priv_kc_effimera.public_key()
        
        # Serialization into 32 bytes
        client_pub_bytes = pub_kc_effimera.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        client_nonce = os.urandom(32)
        conn.sendall(client_pub_bytes + client_nonce)
        print("[>] Sending effimerate key to Server.")

        # 2. Ricezione del blocco combinato dal server
        # X25519 = 32 byte, server nonce = 32 byte and RSA-4096 signature = 512 byte -> reading 576 byte total
        server_response = conn.recv(576)
        if len(server_response) < 576:
            print("[-] Errore: Risposta dell'handshake incompleta.")
            return ERROR

        # First 32 byte are the key, next 32 byte are the nonce, remaining is the signature
        server_pub_bytes = server_response[:32]
        server_nonce = server_response[32:64]
        signature = server_response[64:]
        transcript = client_pub_bytes + client_nonce + server_pub_bytes + server_nonce

        # 3. The client uses the server connection public key to test the server authenticity
        try:
            pubKc.verify(
                signature,
                transcript,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("[+] [SERVER AUTHENTICATED]")
        except Exception:
            print("[-] [MitM ATTACK DETECTED]")
            return ERROR

        # 4. Shared secret (Diffie-Hellman)
        server_public_key = x25519.X25519PublicKey.from_public_bytes(server_pub_bytes)
        shared_secret = priv_kc_effimera.exchange(server_public_key)

        # 5. Simmetric key computation
        session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=client_nonce + server_nonce,
            info=b"session encryption",
        ).derive(shared_secret)
        print("[+] Canale sicuro stabilito (PFS abilitato).")

        # 6. Simmetric cipher initialization
        cipher = ChaCha20Poly1305(session_key)
        return cipher
    except Exception as e:
        print(f"[-] Errore critico durante l'handshake: {e}")
        return ERROR
    
def login(conn, cipher, data_dic):
    data_dic_encrypted = encrypt_json(data_dic, cipher)
    # Send data_dic
    send_structured_message(conn, data_dic_encrypted)
    # Receive outcome
    data_received = receive_structured_message(conn)

    if not data_received or len(data_received) < 12:
        print("[-] Something went wrong in login outcome receiving.")
        conn.close()
        return
    
    nonce = data_received[:12]
    ciphertext = data_received[12:]

    reply_json = decrypt_json(cipher, nonce, ciphertext)
    try:
        if reply_json.get("status") == "success":
            return {"status": True, "nonce": reply_json.get("nonce")}
        else:
            return False
    except Exception as e:
        print("[-] Fatal error in json outcome receiving")
        return {"status": False, "nonce": reply_json.get("nonce")}

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

    
# Client process start:

while(True):
    # Open network interfacing
    # 1. Socket creation (AF_INET = IPv4, SOCK_STREAM = TCP)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        try:
            conn.connect((HOST, PORT_SERVER))
            print(f"[+] Connesso al server TSA su {HOST}:{PORT_SERVER}")
        except Exception as e:
            print(f"[-] Impossibile connettersi al server: {e}")
            exit(1)
        
        with conn:
            print(f"[+] Connessione stabilita con server")

            # Handshake -> Authentication & Effimeral keys generation, exchange and simmetric key "cipher" computation
            cipher = handshake(conn)
            if cipher == ERROR:
                conn.close()
                continue

            confirm_handshake = receive_structured_message(conn)
            if confirm_handshake:
                print(f"[+] Server says: {confirm_handshake.decode('utf-8')}")

            # Login
            print("Please insert your username:")
            username = input()
            print("Please insert your password:")
            password = input()
            credentials = {"username": username, "password": password}
            login_outcome = login(conn, cipher, credentials)
            if not login_outcome.get("status"):
                print("[-] Login failed!")
                conn.close()
                exit()

            # Server nonce for anti-replay attacks
            replay_nonce = login_outcome.get("nonce")
            
            print("[+] Login success!")

            # Request loop
            while(True):
                print("Welcome! What do you want to do?")
                print("0 - See my balance.")
                print("1 - Verify timestamp.")
                print("2 - Timestamp an hash.")
                print("3 - Quit.")
                # Option is a value from 0 to 3
                option = input("Send request n. ")

                if not option.isdigit() or int(option) not in [0, 1, 2, 3]:
                    print("[-] Opzione non valida. Riprova.")
                    continue

                if(int(option) == 0):
                    message = {"request": "balance", "nonce": replay_nonce}
                if(int(option) == 1):
                    h = input("Inserisci l'hash del documento (in formato HEX): ")
                    t = input("Inserisci il timestamp (es. 2026-06-21T14:45:30Z): ")
                    s = input("Inserisci la firma (in formato HEX): ")
                    print("Working on verification, please wait...")
                    message = {"request": "verify", "hash": h, "timestamp": t, "signature": s, "nonce": replay_nonce}
                if(int(option) == 2):
                    h = input("Inserisci l'hash del documento da firmare (in formato HEX): ")
                    print("Working on timestamping, please wait...")
                    message = {"request": "timestamp", "hash": h, "nonce": replay_nonce}
                if(int(option) == 3):
                    message = {"request": "quit", "nonce": replay_nonce}

                # Request sending
                encrypted_message = encrypt_json(message, cipher)
                send_structured_message(conn, encrypted_message)

                if(int(option) == 3):
                    conn.close()
                    exit()

                # Outcome receiving
                data_received = receive_structured_message(conn)
                if not data_received or len(data_received) < 12:
                    print("[-] Something went wrong in request outcome receiving")
                    conn.close()
                    exit()
    
                nonce = data_received[:12]
                ciphertext = data_received[12:]

                decrypted_reply = decrypt_json(cipher, nonce, ciphertext)

                # New anti-replay nonce
                if "nonce" in decrypted_reply:
                    replay_nonce = decrypted_reply["nonce"]

                # Printing
                print("[+] Server replied with:")
                print(json.dumps(decrypted_reply, indent=4))
                
