from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import time

# Pesan yang akan dienkripsi
pesan = b"Keamanan Data"

# =====================
# SIMETRIS (FERNET)
# =====================
key = Fernet.generate_key()
fernet = Fernet(key)

start = time.time()
cipher_simetris = fernet.encrypt(pesan)
hasil_simetris = fernet.decrypt(cipher_simetris)
end = time.time()

waktu_simetris = end - start

# =====================
# ASIMETRIS (RSA)
# =====================
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

start = time.time()

cipher_rsa = public_key.encrypt(
    pesan,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

hasil_rsa = private_key.decrypt(
    cipher_rsa,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

end = time.time()

waktu_rsa = end - start

# Output
print("===== SIMETRIS (FERNET) =====")
print("Pesan Asli :", pesan.decode())
print("Ciphertext :", cipher_simetris)
print("Hasil Dekripsi :", hasil_simetris.decode())
print("Waktu :", waktu_simetris)
print("Ukuran Ciphertext :", len(cipher_simetris), "byte")

print("\n===== ASIMETRIS (RSA) =====")
print("Pesan Asli :", pesan.decode())
print("Ciphertext :", cipher_rsa)
print("Hasil Dekripsi :", hasil_rsa.decode())
print("Waktu :", waktu_rsa)
print("Ukuran Ciphertext :", len(cipher_rsa), "byte")