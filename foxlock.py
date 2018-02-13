from flask import Flask, request

from errors import FoxlockError, BadRequest
import impl

app = Flask('foxlock');

@app.route('/key/<client>', methods=['GET', 'POST', 'PUT'])
def keyRoute(client):
	"""This endpoint provides basic CRUD operations for client keys"""
	if request.method == 'GET':
		return impl.getKey(client)
	if request.method == 'POST':
		return impl.addKey(client)
	if request.method == 'PUT':
		return impl.updateKey(client)
	# Flask should automatically reject a request that doesn't match one of the above methods,
	# but defensive coding says we should catch this case anyway.
	raise BadRequest()

@app.route('/jwtkey', methods=['GET'])
def jwtKeyRoute():
	"""This endpoint returns the public key of the RSA key-pair we use to sign our JWTs."""
	return impl.getJwtKey()

@app.errorhandler(FoxlockError)
def handle_error(error):
	return error.message, error.code


if __name__ == '__main__':
    context = ('resources/ssl_cert.pem', 'resources/ssl_privatekey.pem')
    app.run(ssl_context=context)

