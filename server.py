from flask import Flask, request, jsonify

app = Flask(__name__)

# Define a list of patterns to block
blocked_patterns = [';', 'exec', 'eval', 'system', 'bash', 'rm', 'wget', 'curl']

# WAF middleware
class WAFMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        # Check request for blocked patterns
        for pattern in blocked_patterns:
            if pattern in request.path or pattern in request.query_string.decode('utf-8'):
                response = jsonify({'error': 'Blocked request. Pattern detected: {}'.format(pattern)})
                response.status_code = 403
                return response(environ, start_response)

        return self.app(environ, start_response)

# Register WAF middleware
app.wsgi_app = WAFMiddleware(app.wsgi_app)

# Example route
@app.route('/')
def index():
    return 'Hello, World!'

if __name__ == '__main__':
    app.run(debug=True)
