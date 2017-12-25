setup:
	pip install --user -r requirements.txt
	openssl req -x509 -newkey rsa:4096 -nodes -out resources/cert.pem -keyout resources/key.pem


run:
	flask run

