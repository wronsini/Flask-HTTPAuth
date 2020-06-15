import unittest

from flask import Flask

from flask_httpauth import HTTPApiKeyAuth


class HTTPAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)

        apikey_auth = HTTPApiKeyAuth('apikey')

        @apikey_auth.verify_apikey
        def verify_apikey(api_key):
            return api_key == 'this-is-the-api-key!'

        @apikey_auth.error_handler
        def error_handler():
            return 'error', 401, {'WWW-Authenticate': 'MyApiKey realm="Foo"'}

        @app.route('/')
        def index():
            return 'index'

        @app.route('/protected')
        @apikey_auth.login_required
        def apikey_auth_route():
            return 'apikey'

        self.app = app
        self.apikey_auth = apikey_auth
        self.client = app.test_client()

    def test_apikey_auth_prompt(self):
        response = self.client.get('/protected')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual('MyApiKey realm="Foo"', response.headers['WWW-Authenticate'])

    def test_apikey_auth_login_valid_query_string(self):
        response = self.client.get('/protected?apikey=this-is-the-api-key!')
        self.assertEqual('apikey', response.data.decode('utf-8'))

    def test_apikey_auth_ignore_options(self):
        response = self.client.options('/protected')
        self.assertEqual(response.status_code, 200)
        self.assertTrue('WWW-Authenticate' not in response.headers)

    def test_apikey_auth_login_valid_header(self):
        response = self.client.get('/protected',
                                   headers={'apikey': 'this-is-the-api-key!'})
        self.assertEqual('apikey', response.data.decode('utf-8'))

    def test_apikey_auth_login_no_apikey(self):
        response = self.client.get('/protected')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual('MyApiKey realm="Foo"', response.headers['WWW-Authenticate'])

    def test_apikey_auth_login_empty_apikey(self):
        response = self.client.get('/protected?apikey')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual('MyApiKey realm="Foo"', response.headers['WWW-Authenticate'])

    def test_apikey_auth_login_invalid_apikey_query_string(self):
        response = self.client.get('/protected?apikey=this-is-not-the-api-key!')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual('MyApiKey realm="Foo"', response.headers['WWW-Authenticate'])

    def test_apikey_auth_login_invalid_apikey_query_header(self):
        response = self.client.get('/protected', headers={
            'apikey': 'this-is-not-the-api-key!'})
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual('MyApiKey realm="Foo"', response.headers['WWW-Authenticate'])

    def test_apikey_invalid_schema(self):
        response = self.client.get('/protected?notkey=this-is-not-the-api-key!')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual('MyApiKey realm="Foo"', response.headers['WWW-Authenticate'])

    def test_apikey_auth_login_invalid_no_callback(self):
        apikey_auth2 = HTTPApiKeyAuth('APIKey', realm='foo')

        @self.app.route('/protected2')
        @apikey_auth2.login_required
        def token_auth_route2():
            return 'token_auth2'

        response = self.client.get('/protected2?apikey=this-is-the-api-key!')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual('APIKey realm="foo"', response.headers['WWW-Authenticate'])
