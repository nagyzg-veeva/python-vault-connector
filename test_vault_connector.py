import unittest
from unittest.mock import patch, MagicMock
import json
from vault_connector import VaultConnector


class TestVaultConnector(unittest.TestCase):
    """Test cases for the VaultConnector class."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.hostname = "test.vault.com"
        self.vc = VaultConnector(hostname=self.hostname, log_level='error', log_target='console')

    def test_init(self):
        """Test VaultConnector initialization."""
        self.assertEqual(self.vc.vault_hostname, self.hostname)
        self.assertEqual(self.vc.api_version, "v25.2")
        self.assertEqual(self.vc.timeout, 120)
        self.assertEqual(self.vc.upsert_page_size, 500)
        self.assertEqual(self.vc.query_page_size, 1000)
        self.assertIsNone(self.vc.username)
        self.assertIsNone(self.vc.password)
        self.assertEqual(self.vc.session_id, "")

    @patch('vault_connector.requests.post')
    def test_login_success(self, mock_post):
        """Test successful login with username and password."""
        # Mock the response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'responseStatus': 'SUCCESS',
            'sessionId': 'test_session_id_123'
        }
        mock_post.return_value = mock_response

        result = self.vc.login(username='testuser', password='testpass')
        
        self.assertTrue(result)
        self.assertEqual(self.vc.session_id, 'test_session_id_123')
        self.assertEqual(self.vc.username, 'testuser')
        self.assertEqual(self.vc.password, 'testpass')
        mock_post.assert_called_once_with(
            f"https://{self.hostname}/api/v25.2/auth",
            data={"username": "testuser", "password": "testpass"}
        )

    @patch('vault_connector.requests.post')
    def test_login_failure(self, mock_post):
        """Test login failure with invalid credentials."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'responseStatus': 'FAILURE',
            'responseMessage': 'Invalid credentials'
        }
        mock_post.return_value = mock_response

        result = self.vc.login(username='wronguser', password='wrongpass')
        
        self.assertFalse(result)
        self.assertEqual(self.vc.session_id, "")

    @patch('vault_connector.requests.post')
    def test_login_http_error(self, mock_post):
        """Test login with HTTP error."""
        mock_post.side_effect = Exception("Connection error")

        result = self.vc.login(username='testuser', password='testpass')
        
        self.assertFalse(result)

    def test_set_session_id(self):
        """Test setting session ID externally."""
        session_id = "external_session_id_456"
        self.vc.set_session_id(session_id)
        self.assertEqual(self.vc.session_id, session_id)

    @patch('vault_connector.requests.post')
    def test_query_success(self, mock_post):
        """Test successful query execution."""
        # First, set a session ID
        self.vc.set_session_id("test_session_id")
        
        # Mock the response for query
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'responseStatus': 'SUCCESS',
            'data': [{'id': '1', 'name': 'test'}],
            'responseDetails': {'total': 1}
        }
        mock_post.return_value = mock_response

        query = "SELECT id, name FROM document__v"
        result = self.vc.query(query)
        
        self.assertEqual(result['responseStatus'], 'SUCCESS')
        self.assertEqual(len(result['data']), 1)
        self.assertEqual(result['data'][0]['id'], '1')
        mock_post.assert_called_once()

    @patch('vault_connector.requests.post')
    def test_query_no_session(self, mock_post):
        """Test query without session ID."""
        # Ensure no session ID is set
        self.vc.session_id = ""
        
        query = "SELECT id, name FROM document__v"
        result = self.vc.query(query)
        
        self.assertEqual(result['responseStatus'], '')
        self.assertEqual(result['data'], [])
        mock_post.assert_not_called()

    @patch('vault_connector.requests.post')
    def test_query_with_pagination(self, mock_post):
        """Test query with paginated results."""
        self.vc.set_session_id("test_session_id")
        
        # Mock first page response
        first_response = MagicMock()
        first_response.json.return_value = {
            'responseStatus': 'SUCCESS',
            'data': [{'id': '1'}, {'id': '2'}],
            'responseDetails': {
                'total': 4,
                'next_page': '/api/v25.2/query?page=2'
            }
        }
        
        # Mock second page response
        second_response = MagicMock()
        second_response.json.return_value = {
            'responseStatus': 'SUCCESS',
            'data': [{'id': '3'}, {'id': '4'}],
            'responseDetails': {'total': 4}
        }
        
        mock_post.side_effect = [first_response, second_response]

        query = "SELECT id FROM document__v"
        result = self.vc.query(query)
        
        self.assertEqual(result['responseStatus'], 'SUCCESS')
        self.assertEqual(len(result['data']), 4)
        self.assertEqual(mock_post.call_count, 2)

    @patch('vault_connector.requests.post')
    def test_update_success(self, mock_post):
        """Test successful update operation."""
        self.vc.set_session_id("test_session_id")
        
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'responseStatus': 'SUCCESS',
            'data': [{'id': '1', 'status': 'updated'}]
        }
        mock_post.return_value = mock_response

        records = [{'id': '1', 'name': 'test'}]
        result = self.vc.update("document__v", records)
        
        self.assertEqual(result['responseStatus'], 'SUCCESS')
        self.assertEqual(len(result['data']), 1)
        mock_post.assert_called_once()

    @patch('vault_connector.requests.post')
    def test_insert_success(self, mock_post):
        """Test successful insert operation."""
        self.vc.set_session_id("test_session_id")
        
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'responseStatus': 'SUCCESS',
            'data': [{'id': '1', 'name': 'new'}]
        }
        mock_post.return_value = mock_response

        records = [{'name': 'new'}]
        result = self.vc.insert("document__v", records)
        
        self.assertEqual(result['responseStatus'], 'SUCCESS')
        self.assertEqual(len(result['data']), 1)
        mock_post.assert_called_once()

    @patch('vault_connector.requests.post')
    def test_oauth_login_flow(self, mock_post):
        """Test OAuth login flow with mocked responses."""
        # Mock auth profile discovery
        auth_response = MagicMock()
        auth_response.status_code = 200
        auth_response.json.return_value = {
            'responseStatus': 'SUCCESS',
            'data': {
                'auth_type': 'sso',
                'auth_profiles': [{
                    'id': 'profile_123',
                    'as_metadata': {'token_endpoint': 'https://auth.com/token'}
                }]
            }
        }
        
        # Mock token response
        token_response = MagicMock()
        token_response.status_code = 200
        token_response.json.return_value = {
            'access_token': 'test_access_token_789'
        }
        
        # Mock session ID response
        session_response = MagicMock()
        session_response.status_code = 200
        session_response.json.return_value = {
            'sessoinId': 'test_oauth_session_id'  # Note: typo in response key
        }
        
        mock_post.side_effect = [auth_response, token_response, session_response]

        result = self.vc.login_oauth(
            client_id='client_123',
            client_secret='secret_456',
            scopes=['scope1']
        )
        
        self.assertTrue(result)
        self.assertEqual(self.vc.session_id, 'test_oauth_session_id')

    def test_get_retval_instance(self):
        """Test the internal method for creating return value structure."""
        retval = self.vc._VaultConnector__get_retval_instance()
        self.assertEqual(retval, {'responseStatus': '', 'data': []})

    @patch('vault_connector.requests.post')
    def test_get_access_token_success(self, mock_post):
        """Test successful access token retrieval."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'access_token': 'test_token_abc'
        }
        mock_post.return_value = mock_response

        token = self.vc._VaultConnector__get_access_token(
            token_endpoint='https://auth.com/token',
            client_id='client_123',
            client_secret='secret_456',
            scopes=['scope1']
        )
        
        self.assertEqual(token, 'test_token_abc')

    @patch('vault_connector.requests.post')
    def test_get_access_token_failure(self, mock_post):
        """Test access token retrieval failure."""
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            'error': 'invalid_client',
            'error_description': 'Invalid client credentials'
        }
        mock_post.return_value = mock_response

        token = self.vc._VaultConnector__get_access_token(
            token_endpoint='https://auth.com/token',
            client_id='wrong_client',
            client_secret='wrong_secret',
            scopes=['scope1']
        )
        
        self.assertEqual(token, "")

    def test_split_list(self):
        """Test the list splitting utility method."""
        test_list = [1, 2, 3, 4, 5]
        chunks = list(self.vc._VaultConnector__split_list(test_list, 2))
        
        self.assertEqual(len(chunks), 3)
        self.assertEqual(chunks[0], [1, 2])
        self.assertEqual(chunks[1], [3, 4])
        self.assertEqual(chunks[2], [5])


if __name__ == '__main__':
    unittest.main()