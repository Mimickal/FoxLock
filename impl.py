from flask import request
import jwt
import re
import os
from base64 import b64encode, b64decode
from subprocess import check_call, CalledProcessError
from time import time as now

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
FORBIDDEN = 403
NOT_FOUND = 404

# Clint key limits
KEY_SIZE_LIMIT = int(1e4)
KEY_NAME_LIMIT = 50

# A JWT must expire within this many seconds
MAX_JWT_EXP_DELTA = 60

seen_tokens = {}

def getKey(client):
	'''Retrieves the specified key for the specified client
	Returns an error if the key doesn't exist, obviously.
	'''
	global SERVER_JWT_PRIVATE_KEY
	global NOT_FOUND

	validateClient(client)
	client_pub_key = loadClientRSAKey(client)
	token_data = decodeRequestToken(request, client_pub_key)
	key_name = validateKeyName(token_data)

	# Keys may only have alpha-numeric names
	try:
		with open(os.path.join('keys', client, key_name + '.key')) as key_file:
			requested_key = key_file.read()
	except IOError:
		raise FoxlockError(NOT_FOUND, 'Key "%s" not found' % key_name)

	# Key is returned in a JWT encrypted with the client's public key, so only they can decrypt it
	keytoken = packJWT({'key': requested_key}, SERVER_JWT_PRIVATE_KEY, client_pub_key)

	return keytoken

def addKey(client):
	'''Adds a new key with the specified name and contents.
	Returns an error if a key with the specified name already exists.
	'''
	global BAD_REQUEST
	global CREATED
	global KEY_NAME_LIMIT

	validateClient(client)
	client_pub_key = loadClientRSAKey(client)
	token_data = decodeRequestToken(request, client_pub_key)
	key_name = validateKeyName(token_data)
	key_data = validateKeyData(token_data)

	# Limit key length
	if len(key_name) > KEY_NAME_LIMIT:
		err_text = 'Key name limited to %s characters' % KEY_NAME_LIMIT
		raise FoxlockError(BAD_REQUEST, err_text)

	# Use 'x' flag so we can throw an error if a key with this name already exists
	try:
		with open(os.path.join('keys', client, key_name + '.key'), 'x') as f:
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
	key_data = validateKeyData(token_data)

	# Use 'w' flag to replace existing key file with the new key data
	key_path = os.path.join('keys', client, key_name + '.key')
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

	# NOTE shred may not fully destroy the key file on certain filesystems.
	# See `man shred` for details.
	try:
		with open('/dev/null') as dev_null:
			check_call([
				'/usr/bin/shred',
				'--zero', '--remove',
				'keys/%s/%s.key' % (client, key_name)
			], stderr=dev_null)
	except CalledProcessError:
		raise FoxlockError(NOT_FOUND, 'Key "%s" not found' % key_name)

	return 'Key successfully deleted'

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
		key = loadKey(os.path.join('keys', client, 'key_rsa.pub'))
	except IOError:
		raise FoxlockError(NOT_FOUND, 'Client RSA public key not found')
	return key

def decodeRequestToken(req, client_pub_key):
	'''Decrypts / decodes the request's JWT with the server's JWT private key.
	Also enforces one-time-use JWTs with short exp claims to help prevent
	replay and cache flooding attacks, respectively.
	'''
	global SERVER_JWT_PRIVATE_KEY
	global BAD_REQUEST
	global FORBIDDEN
	global MAX_JWT_EXP_DELTA
	global seen_tokens

	token = req.get_data(as_text=True)
	if not token:
		raise FoxlockError(BAD_REQUEST, 'No token found in request body')

	# Most JWT errors will come from clients signing JWTs with the wrong key
	try:
		decoded_token_data = unpackJWT(token, client_pub_key, SERVER_JWT_PRIVATE_KEY)
	except ValueError:
		raise FoxlockError(BAD_REQUEST, 'Failed to decrypt message. Are you using the right key?')
	except jwt.exceptions.ExpiredSignatureError:
		raise FoxlockError(BAD_REQUEST, 'JWT already expired')
	except jwt.exceptions.InvalidTokenError:
		raise FoxlockError(BAD_REQUEST, 'Failed to decode JWT. Did you use the right key, or is the token malformed?')


	# Make sure JWTs have required registered claims
	token_exp = decoded_token_data.get('exp')
	token_id = decoded_token_data.get('jti')

	if token_exp is None:
		raise FoxlockError(BAD_REQUEST, '"exp" required in JWT payload')
	if token_id is None:
		raise FoxlockError(BAD_REQUEST, '"jti" required in JWT payload')

	# Only accept tokens that will expire soon
	if token_exp - now() > MAX_JWT_EXP_DELTA:
		raise FoxlockError(BAD_REQUEST, 'JWTs must expire within %s seconds' % MAX_JWT_EXP_DELTA)

	# Reject tokens we have seen before
	if seen_tokens.get(token_id) is not None:
		raise FoxlockError(FORBIDDEN, 'JWTs may only be used once')

	# Remember this token's ID
	seen_tokens.update({token_id: token_exp})

	# Prune expired tokens
	for jti, exp in list(seen_tokens.items()):
		if exp < now():
			del seen_tokens[jti]

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

