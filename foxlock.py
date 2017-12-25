from flask import Flask, request

app = Flask('foxlock');

if __name__ == '__main__':
    context = ('resources/cert.pem', 'resources/key.pem')
    app.run(ssl_context=context)

