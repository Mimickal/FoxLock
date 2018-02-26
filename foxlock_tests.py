from unittest import TestCase, main
from Crypto.PublicKey import RSA
import jwt
from base64 import b64encode, b64decode
import os

import foxlock
import HybridRSA

# FIXME Refactor this so tests have their own dedicated resources.
SERVER_JWT_KEY = open('resources/jwt_key.pub', 'rb').read()
CLIENT_PRI_KEY = open('tempdevstuff/key_rsa', 'rb').read()

foxlock.app.config['TESTING'] = True
foxlock.app.config['DEBUG'] = True

'''This module tests our application's endpoints.

Since many tests will be very similar for every HTTP method, we define them
first, then bind them to each test class. Method specific values can be plugged
into the tests, and those method specific values are defined in the individual
test classes.

Yeah, it's kinda dirty. If unittest was like Mocha we wouldn't need to do this.
'''

# Tests for all methods

def test_invalidClientName(self):
	badClientName = '!!some%dir~@'

	resp = makeRequest(self, self.url + badClientName)
	resp_text = resp.get_data(as_text=True)

	with self.subTest():
		self.assertEqual(resp.status_code, 400)
	self.assertEqual(resp_text, 'Client may only have alpha-numeric names')

def test_requestedClientDoesNotExist(self):
	nonExistingClientName = 'notaclient'

	resp = makeRequest(self, self.url + nonExistingClientName)
	resp_text = resp.get_data(as_text=True)

	with self.subTest():
		self.assertEqual(resp.status_code, 404)
	self.assertEqual(resp_text, 'Client "%s" not found' % nonExistingClientName)

def test_emptyRequestBody(self):
	resp = makeRequest(self, self.url + 'testuser')
	resp_text = resp.get_data(as_text=True)

	with self.subTest():
		self.assertEqual(resp.status_code, 400)
	self.assertEqual(resp_text, 'No token found in request body')

def test_invalidKeyName(self):
	badKeyName = '!..bad&key'

	encoded_jwt = packJWT({'name': badKeyName})
	resp = makeRequest(self, self.url + 'testuser', encoded_jwt)
	resp_text = resp.get_data(as_text=True)

	with self.subTest():
		self.assertEqual(resp.status_code, 400)
	self.assertEqual(resp_text, 'Invalid key name')

def test_JWTWithoutKeyName(self):
	encoded_jwt = packJWT({})
	resp = makeRequest(self, self.url + 'testuser', encoded_jwt)
	resp_text = resp.get_data(as_text=True)

	with self.subTest():
		self.assertEqual(resp.status_code, 400)
	self.assertEqual(resp_text, '"name" not provided in JWT payload')

def test_clientMessageEncryptedWithWrongKey(self):
	global CLIENT_PRI_KEY
	wrongKey = RSA.generate(2048).publickey().exportKey()

	token = jwt.encode({}, CLIENT_PRI_KEY, algorithm='RS256')
	enc_token = HybridRSA.encrypt(token, wrongKey)
	encoded_jwt = b64encode(enc_token).decode('utf-8')

	resp = makeRequest(self, self.url + 'testuser', encoded_jwt)
	resp_text = resp.get_data(as_text=True)

	with self.subTest():
		self.assertEqual(resp.status_code, 400)
	self.assertEqual(resp_text, 'Failed to decrypt message. Are you using the right key?')

def test_malformedJWT(self):
	global SERVER_JWT_KEY

	bad_token = b'malformed_token.malformed_payload.malformed_hash'
	enc_token = HybridRSA.encrypt(bad_token, SERVER_JWT_KEY)
	encoded_bad_jwt = b64encode(enc_token).decode('utf-8')

	resp = makeRequest(self, self.url + 'testuser', encoded_bad_jwt)
	resp_text = resp.get_data(as_text=True)

	with self.subTest():
		self.assertEqual(resp.status_code, 400)
	self.assertEqual(resp_text, 'Failed to decode JWT. Did you use the right key, or is the token malformed?')

def test_JWTSignedWithWrongKey(self):
	global SERVER_JWT_KEY
	wrongKey = RSA.generate(2048).exportKey()

	bad_signed_token = jwt.encode({}, wrongKey, algorithm='RS256')
	enc_token = HybridRSA.encrypt(bad_signed_token, SERVER_JWT_KEY)
	encoded_bad_signed_jwt = b64encode(enc_token).decode('utf-8')

	resp = makeRequest(self, self.url + 'testuser', encoded_bad_signed_jwt)
	resp_text = resp.get_data(as_text=True)

	with self.subTest():
		self.assertEqual(resp.status_code, 400)
	self.assertEqual(resp_text, 'Failed to decode JWT. Did you use the right key, or is the token malformed?')

def test_JWTsAreOneTimeUse(self):
	raise NotImplementedError()



# Tests for GET, PUT, and DELETE

def test_requestNonExistingKey(self):
	non_exist_key_name = 'idontexist'

	enc_jwt = packJWT({'name': non_exist_key_name})
	resp = makeRequest(self, self.url + 'testuser', enc_jwt)
	resp_text = resp.get_data(as_text=True)

	with self.subTest():
		self.assertEqual(resp.status_code, 404)
	self.assertEqual(resp_text, 'Key "%s" not found' % non_exist_key_name)



# Tests for POST and PUT

def test_JWTWithoutKeyData(self):
	no_key_data_jwt = packJWT({'name': 'testkey'})
	resp = makeRequest(self, self.url + 'testuser', no_key_data_jwt)
	resp_text = resp.get_data(as_text=True)

	with self.subTest():
		self.assertEqual(resp.status_code, 400)
	self.assertEqual(resp_text, '"data" not provided in JWT payload')



# Tests for POST

def test_keyAlreadyExists(self):
	raise NotImplementedError()

def test_newKeyTooLarge(self):
	key_name = 'newkey'

	# Make sure our test key doesn't exist from a previous run
	try:
		os.remove('keys/testuser/' + key_name)
	except FileNotFoundError:
		pass

	keyTooLargeHelper(self, 'newkey')



# Tests for PUT

def test_updateKeyTooLarge(self):
	keyTooLargeHelper(self, 'oldkey')



# Helper functions

def makeRequest(self, url, data=None):
	return getattr(self.app, self.method)(url, data = data)

def packJWT(data):
	global CLIENT_PRI_KEY
	global SERVER_JWT_KEY
	token = jwt.encode(data, CLIENT_PRI_KEY, algorithm='RS256')
	enc_token = HybridRSA.encrypt(token, SERVER_JWT_KEY)
	return b64encode(enc_token).decode('utf-8')

def unpackJWT(encoded):
	global SERVER_JWT_KEY
	global CLIENT_PRI_KEY
	decoded = b64decode(encoded)
	dec_token = HybridRSA.decrypt(decoded, CLIENT_PRI_KEY)
	return jwt.decode(dec_token, SERVER_JWT_KEY, algorithms=['RS256'])

def keyTooLargeHelper(self, keyname):
	'''This test is the same for PUT and POST, except for the key name'''
	max_key_size = int(1e4)

	big_key_jwt = packJWT({'name': keyname, 'data': 'x' * (max_key_size + 1)})
	resp = makeRequest(self, self.url + 'testuser', big_key_jwt)
	resp_text = resp.get_data(as_text=True)

	with self.subTest():
		self.assertEqual(resp.status_code, 400)
	self.assertEqual(resp_text, 'Key size limited to %s bytes' % max_key_size)



# Set up test classes (for unittest)

def bindTest(klass, function):
	'''Easier method of binding tests to test classes'''
	setattr(klass, function.__name__, function)


class KeyTest(TestCase):
	'''Base class for key endpoint tests'''
	def setUp(self):
		self.app = foxlock.app.test_client()
		self.url = '/key/'
		self.user = 'testuser'


class GetKey(KeyTest):
	'''Test class for key endpoint GET method tests'''
	def setUp(self):
		KeyTest.setUp(self)
		self.method = 'get'

bindTest(GetKey, test_invalidClientName)
bindTest(GetKey, test_requestedClientDoesNotExist)
bindTest(GetKey, test_emptyRequestBody)
bindTest(GetKey, test_invalidKeyName)
bindTest(GetKey, test_JWTWithoutKeyName)
bindTest(GetKey, test_clientMessageEncryptedWithWrongKey)
bindTest(GetKey, test_malformedJWT)
bindTest(GetKey, test_JWTSignedWithWrongKey)
bindTest(GetKey, test_JWTsAreOneTimeUse)

bindTest(GetKey, test_requestNonExistingKey)


class PostKey(KeyTest):
	'''Test class for key endpoint POST method tests'''
	def setUp(self):
		KeyTest.setUp(self)
		self.method = 'post'

bindTest(PostKey, test_invalidClientName)
bindTest(PostKey, test_requestedClientDoesNotExist)
bindTest(PostKey, test_emptyRequestBody)
bindTest(PostKey, test_invalidKeyName)
bindTest(PostKey, test_JWTWithoutKeyName)
bindTest(PostKey, test_clientMessageEncryptedWithWrongKey)
bindTest(PostKey, test_malformedJWT)
bindTest(PostKey, test_JWTSignedWithWrongKey)
bindTest(PostKey, test_JWTsAreOneTimeUse)

bindTest(PostKey, test_newKeyTooLarge)
bindTest(PostKey, test_keyAlreadyExists)
bindTest(PostKey, test_JWTWithoutKeyData)


class PutKey(KeyTest):
	'''Test class for key endpoint PUT method tests'''
	def setUp(self):
		KeyTest.setUp(self)
		self.method = 'put'

bindTest(PutKey, test_invalidClientName)
bindTest(PutKey, test_requestedClientDoesNotExist)
bindTest(PutKey, test_emptyRequestBody)
bindTest(PutKey, test_invalidKeyName)
bindTest(PutKey, test_JWTWithoutKeyName)
bindTest(PutKey, test_clientMessageEncryptedWithWrongKey)
bindTest(PutKey, test_malformedJWT)
bindTest(PutKey, test_JWTSignedWithWrongKey)
bindTest(PutKey, test_JWTsAreOneTimeUse)

bindTest(PutKey, test_requestNonExistingKey)
bindTest(PutKey, test_JWTWithoutKeyData)
bindTest(PutKey, test_updateKeyTooLarge)


class DeleteKey(KeyTest):
	'''Test class for key endpoint DELETE method tests'''
	def setUp(self):
		KeyTest.setUp(self)
		self.method = 'delete'

bindTest(DeleteKey, test_invalidClientName)
bindTest(DeleteKey, test_requestedClientDoesNotExist)
bindTest(DeleteKey, test_emptyRequestBody)
bindTest(DeleteKey, test_invalidKeyName)
bindTest(DeleteKey, test_JWTWithoutKeyName)
bindTest(DeleteKey, test_clientMessageEncryptedWithWrongKey)
bindTest(DeleteKey, test_malformedJWT)
bindTest(DeleteKey, test_JWTSignedWithWrongKey)
bindTest(DeleteKey, test_JWTsAreOneTimeUse)

bindTest(DeleteKey, test_requestNonExistingKey)


if __name__ == '__main__':
	main() # From unittest

