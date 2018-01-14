from flask import Flask

import impl

app = Flask('foxlock');

@app.route('/key/<client>', methods=['GET'])
def keyRoute(client):
	return impl.getKey(client)

@app.route('/jwtkey', methods=['GET'])
def jwtKeyRoute():
	return impl.getJwtKey()

if __name__ == '__main__':
    context = ('resources/ssl_cert.pem', 'resources/ssl_privatekey.pem')
    app.run(ssl_context=context)

