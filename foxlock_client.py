from base64 import b64encode, b64decode
from time import time as now
from uuid import uuid4
import requests
import jwt

import HybridRSA

class Client:
	def __init__(self, client_name, client_key, url='https://localhost', port='20145'):
		self.url = url + ':' + port + '/'
		self.client = client_name
		self.clientkey = client_key

		# We need to get the JWT encryption key from the server
		self.jwtkey = requests.get(self.url + 'jwtkey', verify=False).text

	def _request(self, method, name=None, data=None):
		# Build claims
		claims = {'exp': now() + 59, 'jti': uuid4().hex}
		if name is not None:
			claims.update({'name': name})
		if data is not None:
			claims.update({'data': data})

		# Pack request JWT
		token = jwt.encode(claims, self.clientkey, algorithm='RS256')
		encrypted_token = HybridRSA.encrypt(token, self.jwtkey)
		req_jwt = b64encode(encrypted_token).decode('utf-8')

		# Make request
		req_url = self.url + 'key/' + self.client
		req_func = getattr(requests, method)
		resp = req_func(req_url, data=req_jwt, verify=False)

		# Validate response
		resp_code = resp.status_code
		resp_data = resp.text
		if resp_code >= 400:
			raise FoxlockError(resp_code, resp_data)

		# Return response body
		return resp_data

	def getKey(self, name):
		resp_text = self._request('get', name=name)

		# Decrypt / unpack response JWT
		decoded_token = b64decode(resp_text)
		decrypted_token = HybridRSA.decrypt(decoded_token, self.clientkey)
		key_data = jwt.decode(decrypted_token, self.jwtkey, algorithms=['RS256'])

		return key_data['key']

	def addKey(self, name, data):
		return self._request('post', name=name, data=data)

	def updateKey(self, name, data):
		return self._request('put', name=name, data=data)

	def deleteKey(self, name):
		return self._request('delete', name=name)


class FoxlockError(Exception):
	def __init__(self, code, message):
		super(Exception, self).__init__(str(code) + ': ' + message)
		self.code = code
		self.message = message


