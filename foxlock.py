from flask import Flask, request
import jwt

app = Flask('foxlock');

@app.route('/key', methods=['GET'])
def keyRoute():
	'''This is a proof of concept, so we're going to violate boundaries for a little while.'''
	encodedToken = request.args.get('token')
	userPublicKey = open('tempdevstuff/testkey.pub', 'r').read()

	data = jwt.decode(encodedToken, userPublicKey, algorithm='RS256')

	requestedkey = open('resources/userkey.txt', 'r').read()
	return requestedkey


if __name__ == '__main__':
    context = ('resources/cert.pem', 'resources/key.pem')
    app.run(ssl_context=context)
