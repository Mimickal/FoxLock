from flask import Flask, request

app = Flask('foxlock');

@app.route('/key/', methods=['GET'])
def keyRoute():
	'''This is a proof of concept, so we're going to violate boundaries for a little while.'''
	userkey = open('resources/userkey.txt', 'r').read()
	return userkey


if __name__ == '__main__':
    context = ('resources/cert.pem', 'resources/key.pem')
    app.run(ssl_context=context)

