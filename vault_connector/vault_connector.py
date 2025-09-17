import requests
import json
import logging
import inspect



class VaultConnector:
    """A connector class for interacting with Veeva Vault APIs.
    
    This class provides methods to authenticate, query, insert, and update data
    in Veeva Vault using both basic authentication and OAuth 2.0 client credentials flow.
    
    Attributes:
        api_version (str): The Vault API version to use (default: "v25.2")
        timeout (int): Request timeout in seconds (default: 120)
        upsert_page_size (int): Page size for insert/update operations (default: 500)
        query_page_size (int): Page size for query operations (default: 1000)
        statuses (dict): Dictionary mapping status strings
        user_discovery_endpoint (str): Endpoint for user authentication discovery
    """

    api_version:str = "v25.2"
    timeout:int = 120
    upsert_page_size:int = 500
    query_page_size:int = 1000
    statuses:dict = {
        "SUCCESS":"SUCCESS",
        "FAILURE":"FAILURE"
    }
    
    user_discovery_endpoint:str = "https://login.veevavault.com"


    def __init__(self, hostname:str, log_level:str='error', log_target:str='console') -> None:
        """
        Initialize the VaultConnector instance.

        Args:
            hostname (str): Vault hostname without the protocol prefix (e.g., 'myvault.veevavault.com')
            log_level (str, optional): Logging level: 'debug' for detailed logs, 'error' for errors only.
                                      Defaults to 'error'.
            log_target (str, optional): Defines where log messages are sent. 'console' for standard output,
                                       or a filename for file logging. Defaults to 'console'.

        Note:
            The constructor sets up base URLs and initializes the logger but does not establish
            a session. Call login() or login_oauth() to authenticate.
        """

        self.password:str = None
        self.username:str = None
        self.vault_hostname:str = hostname
        self.session_id:str = ""
        self.base_url:str = f"https://{self.vault_hostname}"
        self.api_endpoint_url:str = f"{self.base_url}/api/{__class__.api_version}"
        
        self.logger:logging = self.__setup_logger(log_level=log_level, log_target = log_target)


    def login_oauth(self, username:str, client_id:str, client_secret:str, scopes:list = []) -> bool:
        """
        Authenticate with Vault using OAuth 2.0 client credentials flow.

        This method performs OAuth authentication by:
        1. Discovering the authentication profile for the client ID
        2. Obtaining an access token from the token endpoint
        3. Exchanging the access token for a Vault session ID

        Args:
            client_id (str): OAuth client ID for authentication
            client_secret (str): OAuth client secret for authentication
            scopes (list, optional): List of OAuth scopes to request. Defaults to [].

        Returns:
            bool: True if authentication was successful, False otherwise

        Raises:
            Various network and authentication errors may be logged but not raised
        """
        
        method_name:str = inspect.currentframe().f_code.co_name
        self.logger.debug(f"{method_name} - called")
        
        self.username = username
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = scopes
        
        auth_params = self.__get_auth_profile(username=username)
        
        if not auth_params:
            self.logger.error(f"{method_name} - Failed to obtain Vault oauth params")
            return False
        
        profile_id = auth_params['id'],
        token_endpoint = auth_params['token_endpoint']
        
        access_token = self.__get_access_token(client_id=self.client_id, client_secret=self.client_secret, token_endpoint=token_endpoint, scopes = self.scopes)
        
        if not access_token:
            self.logger.error(f"{method_name} - Oauth access token request failed")
            return False
        
        
        session_id = self.__get_vault_session_id_access_token(vault_host=self.vault_hostname, oauth_oidc_profile_id=profile_id[0], client_id=self.client_id, access_token=access_token)    
        if not session_id:
            self.logger.error(f'{method_name} - Obtaining Vault session Id failed.')
            return False
        
        self.session_id = session_id
        self.logger.debug(f"{method_name} - Successful Login")
        
        return True
        
        


    def login(self, username:str, password:str) -> bool:
        """
        Authenticate with Vault using username and password.

        Performs basic authentication by sending credentials to the Vault auth endpoint
        and stores the session ID for subsequent API calls.

        Args:
            username (str): Vault username for authentication
            password (str): Vault password for authentication

        Returns:
            bool: True if authentication was successful, False otherwise

        Raises:
            Various network and authentication errors may be logged but not raised
        """

        method_name:str = inspect.currentframe().f_code.co_name
        self.logger.debug(f"{method_name} - called")

        self.username = username
        self.password = password

        request_body = {"username": self.username, "password": self.password}
        request_url = self.api_endpoint_url + "/auth"

        try:
            r = requests.post(request_url, data=request_body)
            r.raise_for_status()
            response = r.json()

            if r.status_code == 200 and response.get('responseStatus') == "SUCCESS":
                self.session_id = json.loads(r.text).get("sessionId")
                self.logger.debug(f"{method_name} - Successful Login")
                return True
            else:
                self.logger.error(f"{method_name} - {response.get('responseMessage')}")
                return False
            
        except Exception as e:
            self.logger.error(f"{method_name} - Login Error: {e}")
            return False



    def set_session_id(self, session_id: str) -> None:
        """
        Set the session ID for external authentication scenarios.

        Use this method when you have obtained a session ID through other means
        (e.g., from another authentication system) and want to use it with this connector.

        Args:
            session_id (str): Valid Vault session ID to use for API authentication
        """
        method_name:str = inspect.currentframe().f_code.co_name
        self.logger.debug(f"{method_name} called")
        self.session_id = session_id



    def query(self, query:str, pagesize:int=0) -> list:
        """
        Execute a VQL query with automatic pagination handling.

        This method sends a Vault Query Language (VQL) query to the Vault API and
        automatically handles pagination to retrieve all results.

        Args:
            query (str): VQL query string to execute
            pagesize (int, optional): Page size for result iteration. If 0, uses the
                                    class default (1000). Defaults to 0.

        Returns:
            list: List of records from the query result set, with standard response structure

        Note:
            The return value follows the standard response format with 'responseStatus'
            and 'data' fields. Empty results return an empty list in 'data'.
        """

        method_name:str = inspect.currentframe().f_code.co_name
        self.logger.debug(f"{method_name} called")

        if pagesize == 0:
            pagesize = __class__.query_page_size
            self.logger.debug(f"{method_name} - Page size set to default ({__class__.query_page_size})")

        retval = self.__get_retval_instance()

        if not self.session_id:
            self.logger.error(f"{method_name} - Vault operation called without valid Session ID")
            return retval

        request_url = self.api_endpoint_url + "/query"
        self.logger.debug(f"{method_name} - request URL: {request_url}")
        request_headers = {
            "Authorization": self.session_id,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }

        self.logger.debug(f"{method_name} - Sending Query: {query}")

        r = requests.post(url=request_url, headers=request_headers, data={"q": query})
        response = r.json()
        

        if response.get("responseStatus") == "FAILURE":
            retval.update({
                    "responseStatus":__class__.statuses.get("FAILURE"),
                    "data":"[]"
                    })
            self.logger.error(f"{response.get('errors')[0].get('type')} - {response.get('errors')[0].get('message')}")
            return retval
        
        self.logger.debug(f"{method_name} - Total number of records: {response.get('responseDetails').get('total')}")
        
        retval.update({'responseStatus':__class__.statuses.get('SUCCESS')})

        if (
            not "next_page" in response.get("responseDetails")
            and len(response.get("data")) > 0
        ):
            retval.get('data').extend(response.get("data"))

        else:
            while "next_page" in response.get("responseDetails"):

                retval.get('data').extend(response.get("data"))
                response.get("data").clear()

                next_page = response.get("responseDetails").get("next_page")
                r = requests.post(
                    url=self.base_url + next_page,
                    headers=request_headers,
                    data={"q": query},
                )
                response = r.json()

            if len(response.get("data")) > 0:
                retval.get('data').extend(response.get("data"))

        return retval

    


    def update(self, object: str, data: list, id_param="id") -> dict:
        """Update existing records in the specified Vault object.

        This method updates multiple records in a Vault object using the specified
        identifier parameter. Records are processed in chunks according to the
        configured page size.

        Args:
            object (str): API name of the Vault object to update (e.g., 'document__v')
            data (list): List of record dictionaries to update
            id_param (str, optional): Field name to use as identifier for the update
                                    operation. Defaults to "id".

        Returns:
            dict: Dictionary containing operation results with 'responseStatus' and 'data'

        Note:
            The method uses the private __upsert method with operation="update"
        """
        method_name:str = inspect.currentframe().f_code.co_name
        self.logger.debug(f"{method_name} called")

        return self.__upsert(operation="update", object=object, data=data, id_param=id_param)
    


    def insert(self, object: str, data: list, id_param:str=None) -> dict:
        """Insert new records into the specified Vault object.

        This method inserts multiple records into a Vault object. When used with
        an id_param, it can perform upsert operations (insert or update based on
        whether the record exists).

        Args:
            object (str): API name of the Vault object to insert into (e.g., 'document__v')
            data (list): List of record dictionaries to insert
            id_param (str, optional): Field name to use as identifier for upsert
                                    operations. If None, pure insert is performed.
                                    Defaults to None.

        Returns:
            dict: Dictionary containing operation results with 'responseStatus' and 'data'

        Note:
            The method uses the private __upsert method with operation="insert"
        """
        method_name:str = inspect.currentframe().f_code.co_name
        self.logger.debug(f"{method_name} called")

        return self.__upsert(operation="insert", object=object, data=data, id_param=id_param)



    def __upsert(self, operation:str, object:str, data:list, id_param:str) -> dict:
        """Internal method to handle insert and update operations with Vault.

        This private method processes batch operations for both insert and update
        actions, handling chunking, HTTP requests, and response parsing.

        Args:
            operation (str): Type of operation - 'insert' or 'update'
            object (str): API name of the Vault object to operate on
            data (list): List of record dictionaries to process
            id_param (str): Field name to use as identifier for the operation

        Returns:
            dict: Dictionary containing operation results with 'responseStatus' and 'data'

        Note:
            This method is called by the public insert() and update() methods
        """
        

        method_name:str = inspect.currentframe().f_code.co_name
        retval = self.__get_retval_instance()

        request_url = f"{self.api_endpoint_url}/vobjects/{object}"
        if id_param:
            request_url += f"?idParam={id_param}"

        self.logger.debug(f"{method_name} - request URL: {request_url}")
        self.logger.debug(f"{method_name} - target object: {object}")
        self.logger.debug(f"{method_name} - operation: {operation}")

        request_headers = {
            "Authorization": self.session_id,
            "Content-Type": "application/json",
        }

        chunks = self.__split_list(data, __class__.upsert_page_size)

        for chunk in chunks:

            if operation == "insert":
                r = requests.post(
                url=request_url, headers=request_headers, data=json.dumps(chunk)
            )

            if operation == "update":
                r = requests.put(
                url=request_url, headers=request_headers, data=json.dumps(chunk)
            )

            if r == None:
                return retval

            response = r.json()

            if response.get("responseStatus") == __class__.statuses.get('FAILURE'):
                retval.update({
                    "responseStatus":__class__.statuses.get("FAILURE"),
                    "data":"[]"
                    })
                self.logger.error(f"{response.get('errors')[0].get('type')} - {response.get('errors')[0].get('message')}")
                return retval

            else:
                retval.update({"responseStatus":__class__.statuses.get("SUCCESS")})
                retval.get('data').extend(response.get("data"))
                
        return retval


    def __split_list(self, list: list, chunk_size: int):
        """Split a list into chunks of specified size.

        This utility method divides a large list into smaller chunks to facilitate
        batch processing for API operations that have size limitations.

        Args:
            list (list): List to be split into chunks
            chunk_size (int): Maximum size of each chunk

        Yields:
            Iterator[list]: Generator yielding chunks of the original list
        """

        method_name:str = inspect.currentframe().f_code.co_name
        retval = []

        for i in range(0, len(list), chunk_size):
            yield list[i : i + chunk_size]



    
    def __setup_logger(self, log_level:str, log_target:str) -> logging:
        """Initialize and configure the logger instance.

        Sets up logging with specified level and output target, including
        formatting and handler configuration.

        Args:
            log_level (str): Logging level ('debug', 'error', etc.)
            log_target (str): Log output target - 'console' for stdout or filename for file logging

        Returns:
            logging.Logger: Configured logger instance
        """

        method_name:str = inspect.currentframe().f_code.co_name

        logger = logging.getLogger(self.__class__.__name__)
        log_level = getattr(logging, log_level.upper())
        logger.setLevel(log_level)

        log_handler = logging.StreamHandler()
        if log_target != "console":
            log_handler = logging.FileHandler(log_target)

        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        log_handler.setFormatter(formatter)
        logger.addHandler(log_handler)

        return logger
    

    def __get_retval_instance(self) -> dict:
        """Create a standard return value structure for API responses.

        Returns:
            dict: Dictionary with empty response structure containing:
                - responseStatus: empty string for status indication
                - data: empty list for result data
        """

        return {
            "responseStatus":"",
            "data":[]
        }
        
        
    def __get_auth_profile(self, username: str) -> dict:
        """Retrieve OAuth authentication profile for a given username.

        Queries the Vault user discovery endpoint to obtain authentication
        details required for OAuth flow, including profile ID and token endpoint.

        Args:
            username (str): Username (client ID) to discover auth profile for

        Returns:
            dict: Dictionary containing 'id' (profile ID) and 'token_endpoint' on success,
                  or empty dictionary on failure or if user doesn't use SSO authentication
        """
        
        method_name:str = inspect.currentframe().f_code.co_name
        
        data = {'username':username}
        
        try:
            response = requests.post(f"{self.user_discovery_endpoint}/auth/discovery", data=data)
            response.raise_for_status()
            r = response.json()
            
            if response.status_code == 200 and r.get('responseStatus') == self.statuses.get('SUCCESS'):
                
                self.logger.debug(f"{method_name} - response: {r}")
                
                if not 'data' in r:
                    self.logger.error(f"{method_name} - Empty response")
                    return {}
                
                if not 'auth_type' in r.get('data') or r.get('data').get('auth_type') != 'sso':
                    self.logger.error(f"{method_name} - The given user's auth type is not SSO. Try the login() method")
                    return {}
                
                if  not "auth_profiles" in r['data'] or len(r['data']['auth_profiles']) == 0:  
                    self.logger.error(f"{method_name} - The given user's has no valid auth_profile. Please contact a Vault administrator")
                    return {}
                
                id = r['data']['auth_profiles'][0]['id']
                token_endpoint = r['data']['auth_profiles'][0]['as_metadata']['token_endpoint']
                
                return {
                    'id':id,
                    "token_endpoint":token_endpoint
                }
                
            else:
                self.logger.error(f"{method_name} - {response.get('responseMessage')}")
                return {}
                    
                
        
        except Exception as e:
            self.logger.error(f"{method_name} - Oauth Login Error: {e}")
            return {}
        
    
    def __get_access_token(self, token_endpoint:str, client_id:str, client_secret:str, scopes:list) -> str:
        """Obtain OAuth access token using client credentials flow.

        Requests an access token from the OAuth token endpoint using
        client credentials grant type with optional scopes.

        Args:
            token_endpoint (str): URL of the OAuth token endpoint
            client_id (str): OAuth client identifier
            client_secret (str): OAuth client secret
            scopes (list): List of OAuth scope strings to request

        Returns:
            str: Access token string on success, empty string on failure
        """
        method_name: str = inspect.currentframe().f_code.co_name
        self.logger.debug(f"{method_name} - called")
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials",
            "scope": " ".join(scopes) if scopes else ""
        }

        try:
            response = requests.post(token_endpoint, headers=headers, data=data, timeout=self.timeout)
            response.raise_for_status()
            
            # Parse JSON response
            token_data = response.json()
            
            # Check for OAuth-specific errors in response
            if 'error' in token_data:
                error_type = token_data.get('error', 'unknown_error')
                error_description = token_data.get('error_description', 'No description provided')
                self.logger.error(f"{method_name} - OAuth error: {error_type} - {error_description}")
                return ""
            
            # Extract access token from response
            access_token = token_data.get('access_token')
            if not access_token:
                self.logger.error(f"{method_name} - No access token found in response")
                return ""
                
            return access_token
            
        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code if e.response else 'unknown'
            self.logger.error(f"{method_name} - HTTP error {status_code}: {e}")
            
            try:
                error_data = e.response.json()
                if 'error' in error_data:
                    error_type = error_data.get('error', 'unknown_error')
                    error_description = error_data.get('error_description', 'No description provided')
                    self.logger.error(f"{method_name} - OAuth error: {error_type} - {error_description}")
            except (ValueError, AttributeError):
                # If we can't parse JSON, just log the raw response text
                try:
                    response_text = e.response.text[:200] + '...' if e.response and len(e.response.text) > 200 else e.response.text if e.response else 'No response body'
                    self.logger.error(f"{method_name} - Response body: {response_text}")
                except AttributeError:
                    self.logger.error(f"{method_name} - No response body available")
                    
            return ""
        except Exception as e:
            self.logger.error(f"{method_name} - Unexpected error: {e}")
            return ""
        
    
    def __get_vault_session_id_access_token(self, vault_host:str, oauth_oidc_profile_id:str, client_id:str, access_token:str) -> str:
        """Exchange OAuth access token for Vault session ID.

        This method converts an OAuth access token into a Vault session ID
        by calling the Vault OAuth session endpoint.

        Args:
            vault_host (str): Vault hostname without protocol
            oauth_oidc_profile_id (str): OAuth OIDC profile ID obtained from auth discovery
            client_id (str): OAuth client ID
            access_token (str): Valid OAuth access token

        Returns:
            str: Vault session ID on success, empty string on failure
        """
        
        method_name: str = inspect.currentframe().f_code.co_name
        self.logger.debug(f"{method_name} - called")
        
        session_id = ""
        
        vault_url = f"{self.user_discovery_endpoint}/auth/oauth/session/{oauth_oidc_profile_id}"
        
        headers = {
            'Content-Type':'application/x-www-form-urlencoded',
            'Authorization': f'Bearer {access_token}'
        }
        
        data = {
            'vaultDNS':self.vault_hostname,
            'client_id':client_id
        }
        
        try:
            
            response = requests.post(vault_url, headers=headers, data=data)
            response.raise_for_status()
            r = response.json()
            
            if r['sessionId']:
                session_id = r['sessionId']
            
            
        except requests.exceptions.HTTPError as http_err:
            self.logger.error(f"{method_name} - Request Error: {http_err}")
        except Exception as e:
            self.logger.error(f"{method_name} - Unknown Error: {e}")
        
        return session_id
