setup:
	pip install --user -r requirements.txt
	export FLASK_APP=foxlock.py

run:
	flask run

