from flask import Flask, request, abort

import impl

app = Flask('foxlock');

@app.route('/key/<client>', methods=['GET', 'POST', 'PUT'])
def keyRoute(client):
	if request.method == 'GET':
		return impl.getKey(client)
	if request.method == 'POST':
		return impl.addKey(client)
	if request.method == 'PUT':
		return impl.updateKey(client)
	# Flask should automatically reject a request that doesn't match one of the above methods,
	# but defensive coding says we should catch this case anyway.
	abort(400)

@app.route('/jwtkey', methods=['GET'])
def jwtKeyRoute():
	return impl.getJwtKey()

if __name__ == '__main__':
    context = ('resources/ssl_cert.pem', 'resources/ssl_privatekey.pem')
    app.run(ssl_context=context)

