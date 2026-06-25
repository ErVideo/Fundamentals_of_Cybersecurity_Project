import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Crea la cartella per le chiavi se non esiste
os.makedirs("TSA_Keys", exist_ok=True)

print("[*] Generazione della coppia di chiavi di connessione (RSA-4096)...")
# 1. Genera la chiave privata a lungo termine per autenticare il canale sicuro
privKc = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096
)

# 2. Estrai la chiave pubblica corrispondente
pubKc = privKc.public_key()

# 3. Salva la chiave privata in chiaro (NoEncryption)
with open("TSA_Keys/privKc.pem", "wb") as f:
    f.write(
        privKc.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption() # <--- Nessuna password richiesta
        )
    )

# 4. Salva la chiave pubblica
with open("TSA_Keys/pubKc.pem", "wb") as f:
    f.write(
        pubKc.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("[*] Generazione della coppia di chiavi di firma TSA (RSA-4096)...")
# 1. Genera la chiave privata a lungo termine
privKts = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096
)

# 2. Estrai la chiave pubblica corrispondente
pubKts = privKts.public_key()

# 3. Salva la chiave privata in chiaro (NoEncryption)
with open("TSA_Keys/privKts.pem", "wb") as f:
    f.write(
        privKts.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption() # <--- Nessuna password richiesta
        )
    )

# 4. Salva la chiave pubblica
with open("TSA_Keys/pubKts.pem", "wb") as f:
    f.write(
        pubKts.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("[+] Chiavi generate e salvate in chiaro nella cartella 'TSA_Keys/'.")
