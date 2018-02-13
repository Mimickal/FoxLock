from flask import request, abort
import jwt
import re
import os

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
	token_data = decodeRequestToken(request.args.get('token'), client_pub_key)

	# Keys may only have alpha-numeric names
	try:
		if re.search('[^a-zA-Z0-9]', token_data['key']):
			abort(400) # Invalid key requested
		requested_key = open('keys/%s/%s.key' % (client, token_data['key']), 'r').read()
	except KeyError:
		abort(400) # JWT did not contain key
	except IOError:
		abort(404) # Key not found

	# Key is returned in a JWT encrypted with the client's public key, so only they can decrypt it
	keytoken = packJWT({'key': requested_key}, SERVER_JWT_PRIVATE_KEY)

	return keytoken.decode('utf-8')

def addKey(client):
	"""Adds a new key with the specified name and contents.
	Returns an error if a key with the specified name already exists.
	"""
	validateClient(client)

	client_pub_key = loadClientRSAKey(client)
	token_data = decodeRequestToken(request.args.get('token'), client_pub_key)
	validateNewKeyData(token_data)

	# Use 'x' flag so we can throw an error if a key with this name already exists
	try:
		with open('keys/%s/%s.key' % (client, token_data['name']), 'x') as f:
			f.write(token_data['key'])
	except FileExistsError:
		abort(400) # Key with this name already exists

	return 'Key successfully created'

def updateKey(client):
	"""Updates the contents of a key that already exists in our system.
	Returns an error if the specified key doesn't exist for the specified user.
	"""
	validateClient(client)

	client_pub_key = loadClientRSAKey(client)
	token_data = decodeRequestToken(request.args.get('token'), client_pub_key)
	validateNewKeyData(token_data)

	# Use 'w' flag to replace existing key file with the new key data
	if os.path.isfile('keys/%s/%s.key' % (client, token_data['name'])):
		with open('keys/%s/%s.key' % (client, token_data['name']), 'w') as f:
			f.write(token_data['key'])
	else:
		abort(400) # Key with this name doesn't exist

	return 'Key successfully updated'

def getJwtKey():
	"""Simply returns the RSA public key the server uses to sign JWTs"""
	global SERVER_JWT_PUBLIC_KEY
	return SERVER_JWT_PUBLIC_KEY

##################
# Helper Functions
##################

def validateClient(client):
	# Client may only have alpha-numeric names
	if re.search('[^a-zA-Z0-9]', client):
		abort(400)
	if not os.path.isdir('keys/' + client):
		abort(404) # Client doesn't exist

def loadClientRSAKey(client):
	"""Load a client's RSA public key, if they exist in our system"""
	try:
		key = open('keys/%s/key_rsa.pub' % client, 'rb').read()
	except IOError:
		abort(404) # Client public key not found
	return key

def decodeRequestToken(token, client_pub_key):
	"""Decrypts / decodes the request's JWT with the server's JWT private key."""
	# Flask keeps track of the current request information in its built-in request object
	token = request.args.get('token')
	if token is None:
		abort(400)

	# Most JWT errors will come from clients signing JWTs with the wrong key
	try:
		decoded_token_data = unpackJWT(token, client_pub_key)
	except jwt.exceptions.DecodeError:
		abort(400) # Client's key might not be right, or they're not utf-8 decoding their JWT
	except jwt.exceptions.InvalidTokenError:
		abort(400) # JWT is malformed
	return decoded_token_data

def validateNewKeyData(data):
	"""Verify that the client provided a key name and key data in their request"""
	try:
		data['name']
		data['key']
	except KeyError:
		abort(400) # Token data must include 'key' and 'name'


# We've switched JWT libraries 3 times in one week, so let's just wrap JWT functionality

def packJWT(data, key):
	"""Encrypt/encode in a compact statement"""
	return jwt.encode(data, key, algorithm='RS256')

def unpackJWT(encoded_jwt, key):
	"""Decode/Decrypt in a compact statement"""
	return jwt.decode(encoded_jwt, key, algorithm='RS256')

