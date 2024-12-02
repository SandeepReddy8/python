#Make sure to install Cryptographty library in your vs.code 
#pip install cryptography


import random
import string
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Function to generate an OTP
def generate_otp():
    uppercase_letters = random.choices(string.ascii_uppercase, k=2)
    special_characters = random.choices("!@#$%^&*()-_=+", k=2)
    digits = random.choices(string.digits, k=2)
    otp = uppercase_letters + special_characters + digits
    random.shuffle(otp)
    return ''.join(otp)

# Step 1: Generate the OTP
otp = generate_otp()
print("Generated OTP:", otp)

# Step 2: Generate RSA Key Pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

# Serialize the keys (optional: for storage)
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

# Step 3: Encrypt the OTP with the public key
encrypted_otp = public_key.encrypt(
    otp.encode(),  # Convert OTP to bytes
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
)

print("Encrypted OTP (binary):", encrypted_otp)

# Step 4: Decrypt the OTP using the private key
decrypted_otp = private_key.decrypt(
    encrypted_otp,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
)

print("Decrypted OTP:", decrypted_otp.decode())













