from flask import request, abort
import jwt
import re

def getKey(client):
	validateClientName(client)

	encoded_token = retrieveToken()
	client_rsa_public_key = loadClientRSAKey(client)
	client_request = decodeToken(encoded_token, client_rsa_public_key)

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

def getJwtKey():
	server_jwt_rsa_public_key = open('resources/jwt_key.pub', 'r').read()
	return server_jwt_rsa_public_key

##################
# Helper Functions
##################

def validateClientName(name):
	"""Client may only have alpha-numeric names"""
	if re.search('[^a-zA-Z0-9]', name):
		abort(400)

def retrieveToken():
	token = request.args.get('token')
	if token is None:
		abort(400)
	return token

def loadClientRSAKey(client):
	"""A client exists in our system if there is a matching key directory"""
	try:
		return open('keys/' + client + '/key_rsa.pub', 'r').read()
	except IOError:
		abort(404) # Client public key not found

def decodeToken(token, public_key):
	"""Most JWT errors will come from clients signing JWTs with the wrong key"""
	try:
		return jwt.decode(token, public_key, algorithm='RS256')
	except jwt.exceptions.DecodeError:
		abort(400) # Client's key might not be right, or they're not utf-8 decoding their JWT
	except jwt.exceptions.InvalidTokenError:
		abort(400) # JWT is malformed

