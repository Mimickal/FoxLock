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
		abort(404)

	# JWT decoding can fail for any number of reasons, but most of our failures
	# will come from users signing tokens with the wrong key.
	try:
		data = jwt.decode(encodedToken, userPublicKey, algorithm='RS256')
	except jwt.exceptions.DecodeError:
		abort(400) # TODO give additional information
	except jwt.exceptions.InvalidTokenError:
		abort(400)
	requestedkey = open('keys/' + client + '/testkey.key', 'r').read()

	return requestedkey


if __name__ == '__main__':
    context = ('resources/cert.pem', 'resources/key.pem')
    app.run(ssl_context=context)
