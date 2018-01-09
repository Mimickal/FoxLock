from flask import Flask, request, abort
import jwt
import re

app = Flask('foxlock');

@app.route('/key/<client>', methods=['GET'])
def keyRoute(client):
	# Client may only have alpha-numeric names
	if re.search('[^a-zA-Z0-9]', client):
		abort(400)

	encodedToken = request.args.get('token')
	if encodedToken is None:
		abort(400)

	# A client exists in our system if there is a matching key directory
	try:
		userPublicKey = open('keys/' + client + '/key_public.rsa', 'r').read()
	except IOError:
		abort(404) # Client public key not found

	# Most JWT errors will come from users signing tokens with the wrong key
	try:
		data = jwt.decode(encodedToken, userPublicKey, algorithm='RS256')
	except jwt.exceptions.DecodeError:
		abort(400) # Client's key might not be right, or they're not utf-8 decoding their JWT string
	except jwt.exceptions.InvalidTokenError:
		abort(400) # JWT is malformed

	# Keys may only have alpha-numeric names
	try:
		if re.search('[^a-zA-Z0-9]', data['key']):
			abort(400) # Invalid key requested
		requestedkey = open('keys/' + client + '/' + data['key'] + '.key', 'r').read()
	except KeyError:
		abort(400) # JWT did not contain key
	except IOError:
		abort(404) # Key not found

	return requestedkey


if __name__ == '__main__':
    context = ('resources/cert.pem', 'resources/key.pem')
    app.run(ssl_context=context)

