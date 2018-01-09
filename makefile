setup:
	pip install --user -r requirements.txt
	openssl req -x509 -newkey rsa:4096 -nodes -out resources/ssl_cert.pem -keyout resources/ssl_privatekey.pem -days 365
	ssh-keygen -f resources/jwt_key

run:
	python3 foxlock.py

