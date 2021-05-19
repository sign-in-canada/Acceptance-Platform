from java.security import Key
from javax.crypto import Cipher
from javax.crypto.spec import SecretKeySpec, IvParameterSpec
from org.bouncycastle.jce.provider import BouncyCastleProvider

import base64
import string
import random

def encryptAES(key, toEncrypt):

    # make sure key length is 16 bytes (128 bits)
    if ( len(key) != 16 ):
        return None
    # generate a random IV
    randomSource = string.ascii_letters + string.digits
    iv = ''.join(random.SystemRandom().choice(randomSource) for i in range(16))
    # configure IV and key specification
    skeySpec = SecretKeySpec(key, "AES")
    ivspec = IvParameterSpec(iv)
    # setup cipher
    cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", BouncyCastleProvider())
    cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivspec)
    # encrypt the plaintext
    encryptedBytes = cipher.doFinal( toEncrypt.encode('utf-8') )
    encryptedValue = base64.b64encode( encryptedBytes )
    return iv.encode("ascii") + encryptedValue

def decryptAES(key, encryptedStr):

    # make sure key length is 16 bytes (128 bits)
    if ( len(key) != 16 ):
        return None
    # split the encrypted string into IV and ciphertext
    iv, encrypted = encryptedStr[:16], encryptedStr[16:]
    # configure IV and key specification
    skeySpec = SecretKeySpec(key, "AES")
    ivspec = IvParameterSpec(iv)
    # setup cipher
    cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", BouncyCastleProvider())
    cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivspec)
    # decrypt the plaintext
    encodedBytes = base64.b64decode( b'' + encrypted )
    decodedBytes = cipher.doFinal( encodedBytes )
    plaintext    = ''.join(chr(i) for i in decodedBytes)
    return plaintext
