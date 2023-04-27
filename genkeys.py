import sys
import random
import os
import json
import binascii


def miller_rabin(n, k=10):
    """
    Performs the Miller-Rabin primality test on a given integer n.
    The parameter k specifies the number of iterations to perform.
    Returns True if n is probably prime, False if n is composite.
    """
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False

    # Write n-1 as 2^r * d, where d is odd
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    # Repeat k times
    for i in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for j in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True

def mod_inv(a, b):
    """
    Returns the modular inverse of (a modulo b) using the extended Euclidean algorithm.

    The x % b expression in the provided Python code is mathematically equivalent 
    to the modular inverse of (a modulo b) when a and b are coprime. 
    This is due to the property of modular arithmetic that if x is the inverse of (a modulo b), 
    then x + kb is also an inverse of a modulo b for any integer k.

    In the code, the extended Euclidean algorithm is used to find the greatest common divisor (gcd) of a and b, 
    and the coefficients x and y such that ax + by = gcd(a, b). 
    Since a and b are assumed to be coprime (i.e., their gcd is 1), then x and y are the Bezout coefficients of a and b.
    
    To find the modular inverse of a modulo b, the function returns x % b. 
    Since x satisfies the equation ax + by = gcd(a, b) = 1, then x is a valid modular inverse of a modulo b.
    Taking the result modulo b ensures that the result is in the range 0 <= result < b, which is equivalent to the 
    residue class of a modulo b.

    ex:
    (x+2*b)*a % b = 1
    (x+3*b)*a % b = 1
    (x+7*b)*a % b = 1
    (x+0*b)*a % b = x*a %b = 1
    """
    # compute gcd(a, b) and the coefficients x, y such that ax + by = gcd(a, b)
    gcd, x, y = extended_euclidean_algorithm(a, b)

    if gcd != 1:
        raise ValueError("The modular inverse does not exist.")

    return x % b

def extended_euclidean_algorithm(a, b):
    """
    Returns a tuple (gcd, x, y) such that a*x + b*y = gcd, using the extended
    Euclidean algorithm.
    """
    if b == 0:
        return a, 1, 0

    gcd, x1, y1 = extended_euclidean_algorithm(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return gcd, x, y

def get_pq(bytes: int):
    """
    returns p,q (about 1024 bits) of the RSA cryptosystem
    """
    p = int(os.urandom(bytes).hex(), 16)
    isPrime = miller_rabin(p)
    while not isPrime:
        p = int(os.urandom(bytes).hex(), 16)
        isPrime = miller_rabin(p)

    q = int(os.urandom(bytes).hex(), 16)
    isPrime = miller_rabin(q)
    while not isPrime or p==q:
        q = int(os.urandom(bytes).hex(), 16)
        isPrime = miller_rabin(q)

    return p, q


def export_key(key: dict, key_type: str, name:str) -> None:
    """
    Exports a key dict object as the hex string representation of the key data.
    key_type: public/private
    """
    json_bytes = json.dumps(key).encode('utf-8')
    hex_str = binascii.hexlify(json_bytes).decode('utf-8')

    if key_type=='public':
        with open("keys/{}.pub".format(name), "w") as f:
            f.write(hex_str)
    else:
        with open("keys/{}.prv".format(name), "w") as f:
            f.write(hex_str)

def get_keys(name: str):
    p, q = get_pq(64)

    n = p*q
    e = 65537
    phi_n = (p-1)*(q-1)

    # Private key (d stands for decrypt)
    # choosing d such that it satisfies
    # d*e = 1 mod (phi_n)
    d = mod_inv(e, phi_n)
    
    public_key = { 'modulus' : n,
                    'e' : e
                }
    
    private_key = { 'modulus' : n,
                    'd' : d
                    }
    
    export_key(public_key, 'public', name)
    export_key(private_key, 'private', name)
    return