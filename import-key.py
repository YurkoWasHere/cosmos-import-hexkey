import subprocess
import sys
import nacl.secret
import nacl.utils
import os
import bcrypt
from Crypto.Hash import SHA256
import base64

secret_len = 32
nonce_len = 24

def encrypt_symmetric(cleartext_key, secret_key):         
    if len(secret_key) != secret_len:
        raise ValueError("Secret must be 32 bytes long, got len {}".format(len(secret_key)))
    
    nonce = os.urandom(nonce_len)   
    box = nacl.secret.SecretBox(secret_key)
    ciphertext=box.encrypt(cleartext_key, nonce)
    return ciphertext

#CRC24 calculator
def calculate_crc24(data):
    crc = 0xB704CE  # Initial CRC value
    poly = 0x1864CFB  # CRC-24 polynomial

    for byte in data:
        crc ^= (byte << 16)

        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= poly

    return crc.to_bytes(3, 'big')

# BCRYPT salt use a differnt hash directory
def base64_custom_encode(data):
    custom_alphabet = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    standard_alphabet =b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    
    custom_base64 = base64.urlsafe_b64encode(data).translate(bytes.maketrans(standard_alphabet, custom_alphabet))
    return custom_base64


blockTypePrivKey = "TENDERMINT PRIVATE KEY"
password=os.urandom(16).hex().upper()

if len(sys.argv)<4:
    print(f"usage: {sys.argv[0]} HEX_PRIVATE_KEY KEY_NAME COMOS_BINARY")
    exit(-1)

private_key=sys.argv[1]
if len(private_key)!=64:
    print("Required 64 hex string for the private key")
    exit(-1)
    
keyname = sys.argv[2]
cosmos_binary = sys.argv[3]

# Prefix bytes for private kyes is 0xE1B0F79B20
private_key = "E1B0F79B20" + private_key 
private_key=private_key.lower()

#Build key from password using bcrypt, salt and SHA256
salt_hex  = os.urandom(16).hex().upper()
salt_bytes = bytes.fromhex(salt_hex)
salt_base64 = base64_custom_encode(salt_bytes).decode('utf-8')
full_salt = "$2a$12$" + salt_base64

# bcrypt password with salt then sha256 hash
hashed_password = bcrypt.hashpw(password.encode("utf-8"), full_salt.encode("utf-8"))
secret_key = SHA256.new(hashed_password).digest()

encrypted_private_key = encrypt_symmetric(bytes.fromhex(private_key), secret_key)
encrypted_private_key_base64 = base64.b64encode(encrypted_private_key).decode("utf-8")

# output text time
out=""
out=out + "-----BEGIN TENDERMINT PRIVATE KEY-----\n"    
out=out + "kdf: bcrypt\n"
out=out + f"salt: {salt_hex}\n"
out=out + f"type: secp256k1\n"
out=out + "\n"

# split base64 encryption into 64 character lines
text =  encrypted_private_key_base64 + "\n"
if len(text)>64:
    text='\n'.join(text[i:i+64] for i in range(0, len(text), 64))

out = out + text
out=out + "=" + base64.b64encode(calculate_crc24(encrypted_private_key)).decode('utf-8') + "\n"  
out=out + "-----END TENDERMINT PRIVATE KEY-----\n"  
file_path = f"{os.getcwd()}\\{keyname}.pem"
file = open(file_path, "w")
file.write(out)
file.close

pass_path = f"{os.getcwd()}\\{keyname}.pwd"
file = open(pass_path, "w")
file.write(password)
file.close

print(f"Run: {cosmos_binary} keys import {keyname} {file_path} < {pass_path}")

'''
Not working automatically call the binary
print(file_path)
command  = f"{cosmos_binary} keys import {keyname} {file_path} < {pass_path}"
print(command)
result = subprocess.run(command, shell=True, capture_output=True, text=True)

print("Standard Output:")
print(result.stdout)

print("Standard Error:")
print(result.stderr)
'''
