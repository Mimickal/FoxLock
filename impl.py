from flask import request
import jwt
import re
import os
from base64 import b64encode, b64decode

from errors import BadRequest, NotFound
import HybridRSA

# Cache server keys because they don't change during program operation
SERVER_JWT_PRIVATE_KEY = open('resources/jwt_key', 'rb').read()
SERVER_JWT_PUBLIC_KEY  = open('resources/jwt_key.pub', 'rb').read()

def getKey(client):
	"""Retrieves the specified key for the specified client
	Returns an error if the key doesn't exist, obviously.
	"""
	global SERVER_JWT_PRIVATE_KEY

	validateClient(client)

	client_pub_key = loadClientRSAKey(client)
	token_data = decodeRequestToken(request.headers['Authorization'], client_pub_key)

	# Keys may only have alpha-numeric names
	try:
		if re.search('[^a-zA-Z0-9]', token_data['key']):
			raise BadRequest('Invalid key requested')
		requested_key = open('keys/%s/%s.key' % (client, token_data['key']), 'r').read()
	except KeyError:
		raise BadRequest("JWT did not contain attribute 'key'")
	except IOError:
		raise BadRequest("Key '%s' not found" % token_data['key'])

	# Key is returned in a JWT encrypted with the client's public key, so only they can decrypt it
	keytoken = packJWT({'key': requested_key}, SERVER_JWT_PRIVATE_KEY, client_pub_key)

	return keytoken

def addKey(client):
	"""Adds a new key with the specified name and contents.
	Returns an error if a key with the specified name already exists.
	"""
	validateClient(client)

	client_pub_key = loadClientRSAKey(client)
	token_data = decodeRequestToken(request.headers['Authorization'], client_pub_key)
	validateNewKeyData(token_data)

	# Use 'x' flag so we can throw an error if a key with this name already exists
	try:
		with open('keys/%s/%s.key' % (client, token_data['name']), 'x') as f:
			f.write(token_data['key'])
	except FileExistsError:
		raise BadRequest("Key '%s' already exists" % token_data['name'])

	return 'Key successfully created'

def updateKey(client):
	"""Updates the contents of a key that already exists in our system.
	Returns an error if the specified key doesn't exist for the specified user.
	"""
	validateClient(client)

	client_pub_key = loadClientRSAKey(client)
	token_data = decodeRequestToken(request.headers['Authorization'], client_pub_key)
	validateNewKeyData(token_data)

	# Use 'w' flag to replace existing key file with the new key data
	if os.path.isfile('keys/%s/%s.key' % (client, token_data['name'])):
		with open('keys/%s/%s.key' % (client, token_data['name']), 'w') as f:
			f.write(token_data['key'])
	else:
		raise NotFound("Key '%s' not found" % token_data['name'])

	return 'Key successfully updated'

def getJwtKey():
	"""Simply returns the RSA public key the server uses to sign JWTs"""
	global SERVER_JWT_PUBLIC_KEY
	return SERVER_JWT_PUBLIC_KEY

##################
# Helper Functions
##################

def validateClient(client):
	if re.search('[^a-zA-Z0-9]', client):
		raise BadRequest('Client may only have alpha-numeric names')
	if not os.path.isdir('keys/' + client):
		raise NotFound("Client '%s' not found" % client)

def loadClientRSAKey(client):
	"""Load a client's RSA public key, if they exist in our system"""
	try:
		key = open('keys/%s/key_rsa.pub' % client, 'rb').read()
	except IOError:
		raise NotFound('Client RSA public key not found')
	return key

def decodeRequestToken(auth_header, client_pub_key):
	"""Decrypts / decodes the request's JWT with the server's JWT private key."""
	global SERVER_JWT_PRIVATE_KEY

	if auth_header is None:
		raise BadRequest('No token found in request')

	token = auth_header.lstrip('Bearer ')

	# Most JWT errors will come from clients signing JWTs with the wrong key
	try:
		decoded_token_data = unpackJWT(token, client_pub_key, SERVER_JWT_PRIVATE_KEY)
	except jwt.exceptions.DecodeError:
		raise BadRequest('Failed to decode JWT. Are you using the right key?')
	except jwt.exceptions.InvalidTokenError:
		raise BadRequest('JWT is malformed')
	return decoded_token_data

def validateNewKeyData(data):
	"""Verify that the client provided a key name and key data in their request"""
	try:
		data['name']
		data['key']
	except KeyError:
		raise BadRequest("Token data must include 'key' and 'name'")


# We've switched JWT libraries 3 times in one week, so let's just wrap JWT functionality

def packJWT(data, sign_key, encrypt_key):
	"""Encrypt/encode in a compact statement"""
	token = jwt.encode(data, sign_key, algorithm='RS256')
	enc_token = HybridRSA.encrypt(token, encrypt_key)
	return b64encode(enc_token).decode('utf-8')

def unpackJWT(encoded_jwt, verify_key, decrypt_key):
	"""Decode/Decrypt in a compact statement"""
	decoded = b64decode(encoded_jwt)
	dec_token = HybridRSA.decrypt(decoded, decrypt_key)
	token = jwt.decode(dec_token, verify_key, algorithm='RS256')
	return token

