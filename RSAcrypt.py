from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii
import sys
import json
import os

def mod_exp(a: int, b: int, m: int) -> int:
    """
    In this example, we first define the values of a, b, and m. 
    We then use a while loop to perform modular exponentiation to calculate a^b mod m.

    In the loop, the algorithm first checks the least significant bit of b. If this bit is 1, 
    then it multiplies the current result by a and takes the result modulo m. 
    Otherwise, it squares the current value of a (mod m) to represent the next most significant bit of b. 
    This process repeats until all bits of b have been processed. 
    The result variable is initially set to 1 because anything raised to the 0th power is equal to 1. 
    After the loop completes, result contains the value of a^b mod m, which is the result of the modular exponentiation calculation.
    """
    result = 1
    while b > 0:
        if b % 2 == 1:
            result = (result * a) % m
        a = (a * a) % m
        b = b // 2

    return result
    
def read_file(filename: str) -> str:
    """
    Reads a file and outputs the contents of the file as a string
    """
    with open(filename, 'r') as f:
        file_string = f.read().strip()
        return file_string
    
def write_file(filename: str, contents: str) -> None:
    """
    Writes the contents to a file named filename
    """
    with open(filename, 'w') as f:
        f.write(contents)
    
def export_hexfile(output_data: dict) -> None:
    """
    Write to a file named filename the hex string representation of the output_data
    """
    json_str = json.dumps(output_data)
    json_bytes = json_str.encode('utf-8')
    hex_str = binascii.hexlify(json_bytes).decode('utf-8')
    return hex_str


def import_hexfile(filename: str) -> dict:
    """
    Import a file named filename that contains a hex string representation of input data.
    Returns a python dictionary objects that was represented in hex string.
    """
    with open(filename, "r") as f:
        line = f.readline()
        json_bytes = binascii.unhexlify(line.encode('utf-8'))
        encrypted_data = json.loads(json_bytes.decode('utf-8'))
        return encrypted_data

def read_ciphertext(ciphertext: str) -> dict:
    """
    Reads ciphertext that contains a hex string representation of input data.
    Returns a python dictionary objects that was represented in hex string.
    """
    json_bytes = binascii.unhexlify(ciphertext)
    encrypted_data = json.loads(json_bytes.decode('utf-8'))
    return encrypted_data

def encrypt(plaintext:str, public_key_str:str):
    public_key = import_hexfile(public_key_str)
    e = public_key['e']
    n = public_key['modulus']

    # Define the key and the initialization vector (IV) for encryption
    aes_key = binascii.unhexlify(os.urandom(16).hex()) #bytes
    iv = binascii.unhexlify(os.urandom(16).hex()) #bytes

    # Convert the plaintext from string -> to hexadecimal-> to bytes
    string = plaintext
    string_hex = binascii.hexlify(string.encode()).decode() #hexadecimal
    plaintext = binascii.unhexlify(string_hex) #bytes
    
    # CBC Mode Encryption
    cbc_cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    cbc_ciphertext = cbc_cipher.encrypt(pad(plaintext, AES.block_size))    

    # Protect AES key with RSA
    rsa_ciphertext = int(aes_key.hex(), 16)
    key_prime = mod_exp(rsa_ciphertext, e, n)

    output_data = {
        'cbc_ciphertext' : cbc_ciphertext.hex(),
        'key_prime' : key_prime,
        'iv' : iv.hex(),
    }

    return export_hexfile(output_data)

def decrypt(ciphertext:str, private_key_str:str):
    private_key = import_hexfile(private_key_str)
    d = private_key['d']
    n = private_key['modulus']

    input_data = read_ciphertext(ciphertext)
    cbc_ciphertext = bytes.fromhex(input_data['cbc_ciphertext'])
    key_prime = input_data['key_prime']
    iv = bytes.fromhex(input_data['iv'])

    hex_str = hex(mod_exp(key_prime, d, n))[2:]
    if len(hex_str) % 2 != 0:
        hex_str = '0' + hex_str
    aes_key = bytes.fromhex(hex_str)

    # CBC Mode Decryption
    cbc_decipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    cbc_plaintext = unpad(cbc_decipher.decrypt(cbc_ciphertext), AES.block_size)

    return cbc_plaintext.decode('utf-8')