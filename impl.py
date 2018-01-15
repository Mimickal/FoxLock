from flask import request, abort
import jwt
import re

def getKey(client):
	client_request = decodeRequestToken(client)

	# Keys may only have alpha-numeric names
	try:
		if re.search('[^a-zA-Z0-9]', client_request['key']):
			abort(400) # Invalid key requested
		requested_key = open('keys/' + client + '/' + client_request['key'] + '.key', 'r').read()
	except KeyError:
		abort(400) # JWT did not contain key
	except IOError:
		abort(404) # Key not found

	# Key is returned in an RSA256 signed JWT so client can be sure it actually came from us
	server_jwt_rsa_private_key = open('resources/jwt_key', 'r').read()
	keytoken = jwt.encode({'key': requested_key}, server_jwt_rsa_private_key, algorithm='RS256')

	return keytoken.decode('utf-8')

def addKey(client):
	token_data = decodeRequestToken(client)

	# Client needs to provide a key name and key data
	try:
		token_data['name']
		token_data['key']
	except KeyError:
		abort(400) # Token data must include 'key' and 'name'

	# Use 'x' flag so we can throw an error if a key with this name already exists
	try:
		with open('keys/' + client + '/' + token_data['name'] + '.key', 'x') as f:
			f.write(token_data['key'])
	except FileExistsError:
		abort(400) # Key with this name already exists

	return 'Key successfully created'


def getJwtKey():
	server_jwt_rsa_public_key = open('resources/jwt_key.pub', 'r').read()
	return server_jwt_rsa_public_key

##################
# Helper Functions
##################

def decodeRequestToken(client):
	"""Validates that the client exists and decodes the token using the client's RSA public key"""

	# Client may only have alpha-numeric names
	if re.search('[^a-zA-Z0-9]', client):
		abort(400)

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

