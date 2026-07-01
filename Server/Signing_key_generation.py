import os
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

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

# 2b. Crea un certificato self-signed per associare identità del server e pubKc
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "Timestamping Service"),
])
certKc = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(pubKc)
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    .sign(privKc, hashes.SHA256())
)

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

# 5. Salva il certificato del server
with open("TSA_Keys/certKc.pem", "wb") as f:
    f.write(certKc.public_bytes(serialization.Encoding.PEM))

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
