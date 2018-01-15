from flask import Flask, request

import impl

app = Flask('foxlock');

@app.route('/key/<client>', methods=['GET', 'POST'])
def keyRoute(client):
	if request.method == 'GET':
		return impl.getKey(client)
	if request.method == 'POST':
		return impl.addKey(client)

@app.route('/jwtkey', methods=['GET'])
def jwtKeyRoute():
	return impl.getJwtKey()

if __name__ == '__main__':
    context = ('resources/ssl_cert.pem', 'resources/ssl_privatekey.pem')
    app.run(ssl_context=context)

