from flask import request
import jwt
import re
import os
from base64 import b64encode, b64decode

import HybridRSA

def loadKey(path):
	'''Cleanly load, read, and close key files'''
	key_file = open(path, 'rb')
	key = key_file.read()
	key_file.close()
	return key

# Cache server keys because they don't change during program operation
SERVER_JWT_PRIVATE_KEY = loadKey('resources/jwt_key')
SERVER_JWT_PUBLIC_KEY  = loadKey('resources/jwt_key.pub')

# HTTP response codes
CREATED = 201
BAD_REQUEST = 400
NOT_FOUND = 404

KEY_SIZE_LIMIT = int(1e4)

def getKey(client):
	'''Retrieves the specified key for the specified client
	Returns an error if the key doesn't exist, obviously.
	'''
	global SERVER_JWT_PRIVATE_KEY
	global BAD_REQUEST

	validateClient(client)
	client_pub_key = loadClientRSAKey(client)
	token_data = decodeRequestToken(request, client_pub_key)
	key_name = validateKeyName(token_data)

	# Keys may only have alpha-numeric names
	try:
		requested_key = loadKey('keys/%s/%s.key' % (client, key_name))
	except IOError:
		raise FoxlockError(BAD_REQUEST, 'Key "%s" not found' % key_name)

	# Key is returned in a JWT encrypted with the client's public key, so only they can decrypt it
	keytoken = packJWT({'key': requested_key}, SERVER_JWT_PRIVATE_KEY, client_pub_key)

	return keytoken

def addKey(client):
	'''Adds a new key with the specified name and contents.
	Returns an error if a key with the specified name already exists.
	'''
	global BAD_REQUEST
	global CREATED

	validateClient(client)
	client_pub_key = loadClientRSAKey(client)
	token_data = decodeRequestToken(request, client_pub_key)
	key_name = validateKeyName(token_data)
	key_data = validateKeyData(token_data)

	# Use 'x' flag so we can throw an error if a key with this name already exists
	try:
		with open('keys/%s/%s.key' % (client, key_name), 'x') as f:
			f.write(key_data)
	except FileExistsError:
		raise FoxlockError(BAD_REQUEST, 'Key "%s" already exists' % key_name)

	return 'Key successfully created', CREATED

def updateKey(client):
	'''Updates the contents of a key that already exists in our system.
	Returns an error if the specified key doesn't exist for the specified user.
	'''
	global NOT_FOUND
	global CREATED

	validateClient(client)
	client_pub_key = loadClientRSAKey(client)
	token_data = decodeRequestToken(request, client_pub_key)
	key_name = validateKeyName(token_data)
	key_data = validateKeyName(token_data)

	# Use 'w' flag to replace existing key file with the new key data
	key_path = 'keys/%s/%s.key' % (client, key_name)
	if os.path.isfile(key_path):
		with open(key_path, 'w') as f:
			f.write(key_data)
	else:
		raise FoxlockError(NOT_FOUND, 'Key "%s" not found' % key_name)

	return 'Key successfully updated', CREATED

def deleteKey(client):
	'''Deletes the specified key.
	Returns an error if the key doesn't exist
	'''
	global NOT_FOUND

	validateClient(client)
	client_pub_key = loadClientRSAKey(client)
	token_data = decodeRequestToken(request, client_pub_key)
	key_name = validateKeyName(token_data)

	try:
		os.remove('keys/%s/%s.key' % (client, key_name))
	except FileNotFoundError:
		raise FoxlockError(NOT_FOUND, 'Key "%s" not found' % key_name)

	return 'Key "%s" successfully deleted' % key_name

def getJwtKey():
	'''Simply returns the RSA public key the server uses to sign JWTs'''
	global SERVER_JWT_PUBLIC_KEY
	return SERVER_JWT_PUBLIC_KEY

##################
# Helper Functions
##################

def validateClient(client):
	'''Validate client name is alpha-numeric and exists in our system'''
	global BAD_REQUEST
	global NOT_FOUND

	if re.search('[^a-zA-Z0-9]', client):
		raise FoxlockError(BAD_REQUEST, 'Client may only have alpha-numeric names')
	if not os.path.isdir('keys/' + client):
		raise FoxlockError(NOT_FOUND, 'Client "%s" not found' % client)

def loadClientRSAKey(client):
	'''Load a client's RSA public key, if they exist in our system'''
	global NOT_FOUND

	try:
		key = loadKey('keys/%s/key_rsa.pub' % client)
	except IOError:
		raise FoxlockError(NOT_FOUND, 'Client RSA public key not found')
	return key

def decodeRequestToken(req, client_pub_key):
	'''Decrypts / decodes the request's JWT with the server's JWT private key'''
	global SERVER_JWT_PRIVATE_KEY
	global BAD_REQUEST

	token = req.get_data(as_text=True)
	if not token:
		raise FoxlockError(BAD_REQUEST, 'No token found in request body')

	# Most JWT errors will come from clients signing JWTs with the wrong key
	try:
		decoded_token_data = unpackJWT(token, client_pub_key, SERVER_JWT_PRIVATE_KEY)
	except ValueError:
		raise FoxlockError(BAD_REQUEST, 'Failed to decrypt message. Are you using the right key?')
	except jwt.exceptions.InvalidTokenError:
		raise FoxlockError(BAD_REQUEST, 'Failed to decode JWT. Did you use the right key, or is the token malformed?')

	return decoded_token_data

def validateKeyName(token_data):
	'''Verify key name exists and is alpha-numeric'''
	global BAD_REQUEST

	try:
		name = token_data['name']
	except KeyError:
		raise FoxlockError(BAD_REQUEST, '"name" not provided in JWT payload')

	if re.search('[^a-zA-Z0-9]', name):
		raise FoxlockError(BAD_REQUEST, 'Invalid key name')

	return name

def validateKeyData(token_data):
	'''Verify key data exists and is valid'''
	global BAD_REQUEST
	global KEY_SIZE_LIMIT

	try:
		data = token_data['data']
	except KeyError:
		raise FoxlockError(BAD_REQUEST, '"data" not provided in JWT payload')

	if len(data) > KEY_SIZE_LIMIT:
		raise FoxlockError(BAD_REQUEST, 'Key size limited to %s bytes' % KEY_SIZE_LIMIT)

	return data

# We've switched JWT libraries 3 times in one week, so let's just wrap JWT functionality

def packJWT(data, sign_key, encrypt_key):
	'''Encrypt/encode in a compact statement'''
	token = jwt.encode(data, sign_key, algorithm='RS256')
	enc_token = HybridRSA.encrypt(token, encrypt_key)
	return b64encode(enc_token).decode('utf-8')

def unpackJWT(encoded_jwt, verify_key, decrypt_key):
	'''Decode/Decrypt in a compact statement'''
	decoded = b64decode(encoded_jwt)
	dec_token = HybridRSA.decrypt(decoded, decrypt_key)
	token = jwt.decode(dec_token, verify_key, algorithms=['RS256'])
	return token


class FoxlockError(Exception):
	'''This gives us a general purpose error Flask can catch'''
	def __init__(self, code, message):
		self.message = message
		self.code = code

