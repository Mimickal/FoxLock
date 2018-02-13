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

	client_request = decodeRequestToken(client)

	# Keys may only have alpha-numeric names
	try:
		if re.search('[^a-zA-Z0-9]', client_request['key']):
			abort(400) # Invalid key requested
		requested_key = open('keys/%s/%s.key' % (client, client_request['key']), 'r').read()
	except KeyError:
		abort(400) # JWT did not contain key
	except IOError:
		abort(404) # Key not found

	# Key is returned in an RSA256 signed JWT so client can be sure it actually came from us
	server_jwt_rsa_private_key = open('resources/jwt_key', 'r').read()
	keytoken = jwt.encode({'key': requested_key}, SERVER_JWT_PRIVATE_KEY, algorithm='RS256')

	return keytoken.decode('utf-8')

def addKey(client):
	"""Adds a new key with the specified name and contents.
	Returns an error if a key with the specified name already exists.
	"""
	token_data = decodeRequestToken(client)
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
	token_data = decodeRequestToken(client)
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

def decodeRequestToken(client):
	"""Decodes the request's JWT with the specified client's RSA public key (RS256).
	Returns an error if:
		- The specified client doesn't exist
		- Their RSA public key isn't in our system
		- The token isn't provided in the request
		- There's an issue decoding the JWT
	"""
	# Client may only have alpha-numeric names
	if re.search('[^a-zA-Z0-9]', client):
		abort(400)

	# Does the client even exist in our system?
	if not os.path.isdir('keys/' + client):
		abort(404) # Client doesn't exist

	# Flask keeps track of the current request information in its built-in request object
	token = request.args.get('token')
	if token is None:
		abort(400)

	# A client exists in our system if there is a matching key directory
	try:
		client_rsa_public_key = open('keys/' + client + '/key_rsa.pub', 'r').read()
	except IOError:
		abort(404) # Client public key not found

	# Most JWT errors will come from clients signing JWTs with the wrong key
	try:
		decoded_token = jwt.decode(token, client_rsa_public_key, algorithm='RS256')
	except jwt.exceptions.DecodeError:
		abort(400) # Client's key might not be right, or they're not utf-8 decoding their JWT
	except jwt.exceptions.InvalidTokenError:
		abort(400) # JWT is malformed

	return decoded_token

def validateNewKeyData(data):
	"""Verify that the client provided a key name and key data in their request"""
	try:
		data['name']
		data['key']
	except KeyError:
		abort(400) # Token data must include 'key' and 'name'

