class FoxlockError(Exception):
	def __init__(self, message, code):
		self.message = message
		self.code = code

class BadRequest(FoxlockError):
	def __init__(self, message):
		FoxlockError.__init__(self, message, 400)

class NotFound(FoxlockError):
	def __init__(self, message):
		FoxlockError.__init__(self, message, 404)

