from unittest import TestCase, main

import foxlock

'''This module tests our application's endpoints.

Since many tests will be very similar for every HTTP method, we define them
first, then bind them to each test class. Method specific values can be plugged
into the tests, and those method specific values are defined in the individual
test classes.

Yeah, it's kinda dirty. If unittest was like Mocha we wouldn't need to do this.
'''

# Tests for all methods

def test_invalidClientName(self):
	raise NotImplementedError()

def test_requestedClientDoesNotExist(self):
	raise NotImplementedError()

def test_invalidKeyName(self):
	raise NotImplementedError()

def test_clientMessageEncryptedWithWrongKey(self):
	raise NotImplementedError()

def test_malformedJWT(self):
	raise NotImplementedError()

def test_JWTSignedWithWrongKey(self):
	raise NotImplementedError()

def test_requestInvalidKey(self):
	raise NotImplementedError()

def test_JWTsAreOneTimeUse(self):
	raise NotImplementedError()



# Tests for GET and DELETE

def test_requestNonExistingKey(self):
	raise NotImplementedError()



# Tests for POST and PUT

def test_JWTWithoutKeyBody(self):
	raise NotImplementedError()

def test_newKeyTooLarge(self):
	raise NotImplementedError()



# Set up test classes (for unittest)

def bindTest(klass, function):
	'''Easier method of binding tests to test classes'''
	setattr(klass, function.__name__, function)


class KeyTest(TestCase):
	'''Base class for key endpoint tests'''
	def setUp(self):
		self.url = 'https://localhost:5000/key/testuser'


class GetKey(KeyTest):
	'''Test class for key endpoint GET method tests'''
	def setUp(self):
		super(KeyTest, self).setUp()
		self.method = 'get'

bindTest(GetKey, test_invalidClientName)
bindTest(GetKey, test_requestedClientDoesNotExist)
bindTest(GetKey, test_invalidKeyName)
bindTest(GetKey, test_clientMessageEncryptedWithWrongKey)
bindTest(GetKey, test_malformedJWT)
bindTest(GetKey, test_JWTSignedWithWrongKey)
bindTest(GetKey, test_requestInvalidKey)
bindTest(GetKey, test_JWTsAreOneTimeUse)

bindTest(GetKey, test_requestNonExistingKey)


class PostKey(KeyTest):
	'''Test class for key endpoint POST method tests'''
	def setUp(self):
		super(KeyTest, self).setUp()
		self.method = 'post'

bindTest(PostKey, test_invalidClientName)
bindTest(PostKey, test_requestedClientDoesNotExist)
bindTest(PostKey, test_invalidKeyName)
bindTest(PostKey, test_clientMessageEncryptedWithWrongKey)
bindTest(PostKey, test_malformedJWT)
bindTest(PostKey, test_JWTSignedWithWrongKey)
bindTest(PostKey, test_requestInvalidKey)
bindTest(PostKey, test_JWTsAreOneTimeUse)

bindTest(PostKey, test_JWTWithoutKeyBody)
bindTest(PostKey, test_newKeyTooLarge)


class PutKey(KeyTest):
	'''Test class for key endpoint PUT method tests'''
	def setUp(self):
		super(KeyTest, self).setUp()
		self.method = 'put'

bindTest(PutKey, test_invalidClientName)
bindTest(PutKey, test_requestedClientDoesNotExist)
bindTest(PutKey, test_invalidKeyName)
bindTest(PutKey, test_clientMessageEncryptedWithWrongKey)
bindTest(PutKey, test_malformedJWT)
bindTest(PutKey, test_JWTSignedWithWrongKey)
bindTest(PutKey, test_requestInvalidKey)
bindTest(PutKey, test_JWTsAreOneTimeUse)

bindTest(PutKey, test_JWTWithoutKeyBody)
bindTest(PutKey, test_newKeyTooLarge)


class DeleteKey(KeyTest):
	'''Test class for key endpoint DELETE method tests'''
	def setUp(self):
		super(KeyTest, self).setUp()
		self.method = 'delete'

bindTest(DeleteKey, test_invalidClientName)
bindTest(DeleteKey, test_requestedClientDoesNotExist)
bindTest(DeleteKey, test_invalidKeyName)
bindTest(DeleteKey, test_clientMessageEncryptedWithWrongKey)
bindTest(DeleteKey, test_malformedJWT)
bindTest(DeleteKey, test_JWTSignedWithWrongKey)
bindTest(DeleteKey, test_requestInvalidKey)
bindTest(DeleteKey, test_JWTsAreOneTimeUse)

bindTest(DeleteKey, test_requestNonExistingKey)


if __name__ == '__main__':
	main() # From unittest

