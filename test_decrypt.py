# test_decrypt.py (run in backend folder)
import json
from pathlib import Path
import encrypt_utils

# load the encrypted file (or paste the envelope JSON returned by /search)
enc_envelope = json.loads(Path("places_output_hospital.json.enc.json").read_text())

enc_data = enc_envelope["enc_data"]
nonce = bytes.fromhex(enc_data["nonce_hex"])
tag = bytes.fromhex(enc_data["tag_hex"])
ciphertext = bytes.fromhex(enc_data["ciphertext_hex"])

# derive key using same passphrase
passphrase = "mySecret123"  # same as ENCRYPT_PASSPHRASE
key = encrypt_utils.derive_key_from_passphrase(passphrase)

# decrypt (if encrypt_utils has decrypt util)
plaintext_bytes = encrypt_utils.decrypt_bytes_aes_gcm(nonce, tag, ciphertext, key)
# if decrypt_bytes_aes_gcm expects envelope, adjust accordingly

plaintext_json = plaintext_bytes.decode("utf-8")
result = json.loads(plaintext_json)
print(result)