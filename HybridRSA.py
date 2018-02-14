from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto import Random
import os
import math

'''This module simplifies encrypting arbitrarily large data using RSA.

RSA encrypted data size is limited by the RSA key size.
For example, a 2048 bit RSA key can only encrypt 245 bytes of data or less.

By contrast, AES can encrypt a theoretically infinite amount of data, but with
the trade-off of relying on a shared key.

We can combine RSA and AES to get the best of both worlds:
	1. Generate a random, one-time-use AES key
	2. Encrypt the data with the AES key
	3. Encrypt the AES key with the recipient's RSA public key
'''

AES_KEY_SIZE = 256

# PKCS7 padding functions.
# These are used to satisfy AES blocksize requirements.

def PKCS7pad(string):
	'''Pad string using PKCS7 scheme to pad data to AES block size.'''
	num_pad_chars = AES.block_size - len(string) % AES.block_size
	pad_char = chr(num_pad_chars)
	return string + pad_char * num_pad_chars

def PKCS7unpad(string):
	'''Unpad PKCS7 padded string'''
	pad_char = string[len(string) - 1:]
	return string[:-ord(pad_char)]


# Symmetric (AES CBC) encryption functions.
# These are used to encrypt arbitrarily sized data.

def encryptAES(string, key):
	'''Encrypts data string using AES CBC'''
	init_vector = Random.new().read(AES.block_size)
	cipher = AES.new(key, AES.MODE_CBC, init_vector)
	padded_string = PKCS7pad(string)
	encrypted = cipher.encrypt(padded_string)
	return init_vector + encrypted

def decryptAES(string, key):
	'''Decrypts AES CBC encrypted data'''
	init_vector = string[:16]
	encrypted = string[16:]
	cipher = AES.new(key, AES.MODE_CBC, init_vector)
	decrypted_string = cipher.decrypt(encrypted).decode('utf-8')
	return PKCS7unpad(decrypted_string)


# Asymmetric (RSA) encryption functions.
# These are used to encrypt the AES key.

def encryptRSA(byte_string, key):
	'''Encrypts a small string using PKCS1 OAEP'''
	rsa_key = RSA.importKey(key)
	cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256.new())
	return cipher.encrypt(byte_string)

def decryptRSA(encrypted, rsa_key):
	'''Decrypts a PKCS1 OAEP encrypted string'''
	cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256.new())
	return cipher.decrypt(encrypted)


# API
# These functions tie it all together. Call these.

def encrypt(string, rsa_key):
	'''Use RSA/AES hybrid to encrypt data'''
	global AES_KEY_SIZE

	aes_key = os.urandom(int(AES_KEY_SIZE / 8))
	enc_string = encryptAES(string, aes_key)
	enc_key = encryptRSA(aes_key, rsa_key)
	return enc_key + enc_string

def decrypt(encrypted, rsa_key):
	'''Decrypt RSA/AES hybrid encrypted data'''
	# Import key here because we need the key size to extract the AES key
	rsa_key_obj = RSA.importKey(rsa_key)
	key_size = math.ceil(math.log(rsa_key_obj.n, 2)) // 8

	aes_key = decryptRSA(encrypted[:key_size], rsa_key_obj)
	decrypted_data = decryptAES(encrypted[key_size:], aes_key)
	return decrypted_data

