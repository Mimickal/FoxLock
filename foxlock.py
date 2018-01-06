from flask import Flask, request, abort
import jwt
import re

app = Flask('foxlock');

@app.route('/key/<client>', methods=['GET'])
def keyRoute(client):
	'''This is a proof of concept, so we're going to violate boundaries for a little while.'''
	# Client may only have alpha-numeric names
	if re.search('[^a-zA-Z0-9]', client):
		abort(400)

	encodedToken = request.args.get('token')
	userPublicKey = open('keys/' + client + '/key_public.rsa', 'r').read()
	data = jwt.decode(encodedToken, userPublicKey, algorithm='RS256')
	requestedkey = open('keys/' + client + '/testkey.key', 'r').read()

	return requestedkey


if __name__ == '__main__':
    context = ('resources/cert.pem', 'resources/key.pem')
    app.run(ssl_context=context)
