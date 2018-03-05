from flask import Flask, request

import impl

app = Flask('foxlock');

@app.route('/key/<client>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def keyRoute(client):
	"""This endpoint provides basic CRUD operations for client keys"""
	if request.method == 'GET':
		return impl.getKey(client)
	if request.method == 'POST':
		return impl.addKey(client)
	if request.method == 'PUT':
		return impl.updateKey(client)
	if request.method == 'DELETE':
		return impl.deleteKey(client)

	# Flask should automatically reject a request that doesn't match one of the above methods,
	# but defensive coding says we should catch this case anyway.
	raise impl.FoxlockError(405, "Unsupported method '%s'" % request.method)

@app.route('/jwtkey', methods=['GET'])
def jwtKeyRoute():
	"""This endpoint returns the public key of the RSA key-pair we use to sign our JWTs."""
	return impl.getJwtKey()

@app.errorhandler(impl.FoxlockError)
def handle_error(error):
	return error.message, error.code

@app.errorhandler(404)
def handle_404(error):
	return 'Bad endpoint', 404

@app.errorhandler(500)
def handle_500(error):
	return 'Internal server error', 500


if __name__ == '__main__':
    context = ('resources/ssl_cert.pem', 'resources/ssl_privatekey.pem')
    app.run(ssl_context=context)

