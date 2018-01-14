import sys
import os
import re

try:
	name = sys.argv[1]
except IndexError:
	print("Usage: python " + sys.argv[0] + " <client name>")
	sys.exit(1)

if os.path.exists('keys/' + name):
	print('Client <' + name + '> already exists', file=sys.stderr)
	sys.exit(1)

if re.search('[^a-zA-Z0-9]', name):
	print('Client names may only be alphanumeric', file=sys.stderr)
	sys.exit(1)

os.mkdir('keys/' + name)

print("Client directory 'keys/" + name + "' created.")
print("Client's RSA public key must be manually added to this new directory as 'key_rsa.pub'")

