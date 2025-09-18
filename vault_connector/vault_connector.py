import requests
import json
import logging
import inspect



class VaultConnector:
    """A connector for the Veeva Vault API.

    This class handles authentication (both basic and OAuth 2.0) and provides
    methods for interacting with the Vault API, including querying, inserting,
    and updating records.
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
        """Initializes the VaultConnector for interacting with the Veeva Vault API.

        This constructor sets up the connection parameters and configures logging.

        Args:
            hostname (str): The full hostname of the Vault instance (e.g., 'your-instance.veevavault.com').
            log_level (str, optional): The logging level to use. Can be 'debug', 'info', 'warning', 'error', or 'critical'.
                                     Defaults to 'error'.
            log_target (str, optional): Specifies where to send logs. Can be 'console' to output to the standard stream
                                      or a file path (e.g., '/path/to/log.txt'). Defaults to 'console'.
        """
       
        self.password:str = None
        self.username:str = None
        self.vault_hostname:str = hostname
        self.session_id:str = ""
        self.base_url:str = f"https://{self.vault_hostname}"
        self.api_endpoint_url:str = f"{self.base_url}/api/{__class__.api_version}"
        
        self.logger:logging = self.__setup_logger(log_level=log_level, log_target = log_target)


    def login_oauth(self, username:str, client_id:str, client_secret:str, scopes:list = []) -> bool:
        """Logs in to Vault using the OAuth 2.0 Client Credentials Flow.

        This method authenticates the user by discovering the OAuth profile, obtaining an access token,
        and then exchanging it for a Vault session ID.

        Args:
            username (str): The username for which to discover the OAuth profile.
            client_id (str): The client ID of the OAuth 2.0 application configured in Vault.
            client_secret (str): The client secret of the OAuth 2.0 application.
            scopes (list, optional): A list of OAuth scopes to request. If empty, the default scopes will be used.
                                     Defaults to [].

        Returns:
            bool: True if the login is successful and a session ID is obtained, False otherwise.
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
        """Logs in to Vault using basic authentication with a username and password.

        This method sends a POST request to the Vault authentication endpoint and stores the
        session ID upon a successful response.

        Args:
            username (str): The user's Vault username.
            password (str): The user's Vault password.

        Returns:
            bool: True if the login is successful and a session ID is obtained, False otherwise.
        """
       

        method_name:str = inspect.currentframe().f_code.co_name
        self.logger.debug(f"{method_name} - called")

        self.username = username
        self.password = password

        request_body = {"username": self.username, "password": self.password}
        request_url = self.api_endpoint_url + "/auth"
        
        request_headers = {}

        try:
            r = requests.post(request_url, data=request_body, headers=request_headers)
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
        """Manually sets the session ID for the connector.

        This method is useful when the session ID has been obtained through an external
        process and needs to be used for subsequent API calls.

        Args:
            session_id (str): The Vault session ID to set.
        """
        
        method_name:str = inspect.currentframe().f_code.co_name
        self.logger.debug(f"{method_name} called")
        self.session_id = session_id



    def query(self, query:str, pagesize:int=0) -> list:
        """Executes a VQL (Vault Query Language) query and retrieves the results.

        This method handles pagination automatically to fetch all records matching the query.

        Args:
            query (str): The VQL query string to execute.
            pagesize (int, optional): The number of records to retrieve per page. If 0, it defaults to the
                                      class-level `query_page_size` (1000).

        Returns:
            list: A list of dictionaries, where each dictionary represents a record from the query result.
                  In case of failure, it returns a dictionary with a 'responseStatus' of 'FAILURE'.
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

    


    def update(self, object: str, data: list, id_param="id", migration_mode:bool=False, no_triggers:bool=False) -> dict:
        """Updates existing records for a specified Vault object.

        This method is a convenient wrapper around the private `__upsert` method, pre-setting the
        operation to 'update'.

        Args:
            object (str): The API name of the Vault object where records will be updated (e.g., 'documents__v').
            data (list): A list of dictionaries, where each dictionary represents a record to be updated.
            id_param (str, optional): The field name to use as the external ID for matching records.
                                      Defaults to "id".
            migration_mode (bool, optional): If True, sets the 'X-VaultAPI-MigrationMode' header, which may alter
                                             system behavior for data migration scenarios. Defaults to False.

        Returns:
            dict: The response from the Vault API, which includes the status of the operation and details
                  about the updated records.
        """
       
        method_name:str = inspect.currentframe().f_code.co_name
        self.logger.debug(f"{method_name} called")

        return self.__upsert(operation="update", object=object, data=data, id_param=id_param, migration_mode=migration_mode, no_triggers=no_triggers)
    


    def insert(self, object: str, data: list, id_param:str=None, migration_mode:bool=False, no_triggers:bool=False) -> dict:
        """Inserts new records into a specified Vault object.

        This method serves as a wrapper for the `__upsert` method, with the operation fixed to 'insert'.

        Args:
            object (str): The API name of the Vault object for the insertion (e.g., 'products__v').
            data (list): A list of dictionaries, where each dictionary represents a new record.
            id_param (str, optional): The field to use as an external ID, if applicable. Defaults to None.
            migration_mode (bool, optional): If True, the 'X-VaultAPI-MigrationMode' header will be set.
                                             Defaults to False.

        Returns:
            dict: The response from the Vault API, including the operation's status and the data of the
                  newly created records.
        """
       
        method_name:str = inspect.currentframe().f_code.co_name
        self.logger.debug(f"{method_name} called")

        return self.__upsert(operation="insert", object=object, data=data, id_param=id_param, migration_mode=migration_mode, no_triggers=no_triggers)



    def __upsert(self, operation:str, object:str, data:list, id_param:str, migration_mode:bool=False, no_triggers:bool=False) -> dict:
        """A private method to handle both 'insert' and 'update' operations.

        This method chunks the data and sends it to the appropriate Vault API endpoint based on the
        specified operation.

        Args:
            operation (str): The operation to perform, either 'insert' or 'update'.
            object (str): The API name of the target Vault object.
            data (list): The list of records to process.
            id_param (str): The external ID parameter to use, if any.
            migration_mode (bool, optional): When True, the 'X-VaultAPI-MigrationMode' header is included.
                                             Defaults to False.

        Returns:
            dict: An aggregated response from the Vault API, summarizing the results of all chunks.
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
        if migration_mode:
            request_headers['X-VaultAPI-MigrationMode'] = 'true'
            
        if no_triggers:
            request_headers['X-VaultAPI-NoTriggers'] = 'true'

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
        """Splits a list into smaller chunks of a specified size.

        Args:
            list (list): The list to be chunked.
            chunk_size (int): The size of each chunk.

        Yields:
            A generator that yields each chunk of the original list as a new list.
        """
       
        method_name:str = inspect.currentframe().f_code.co_name
        retval = []

        for i in range(0, len(list), chunk_size):
            yield list[i : i + chunk_size]



    
    def __setup_logger(self, log_level:str, log_target:str) -> logging:
        """Configures and returns a logger instance.

        This private method sets up a logger with the specified level and target.

        Args:
            log_level (str): The desired logging level (e.g., 'debug', 'info').
            log_target (str): Where to send the logs, either 'console' or a file path.

        Returns:
            logging.Logger: The fully configured logger instance.
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
        """Initializes a standard dictionary for return values.

        This private method creates a dictionary with 'responseStatus' and 'data' keys
        to ensure consistent return formats across the class.

        Returns:
            dict: A dictionary with a default structure for API responses.
        """


        return {
            "responseStatus":"",
            "data":[]
        }
        
        
    def __get_auth_profile(self, username: str) -> dict:
        """Discovers the OAuth authentication profile for a given user.

        This private method queries the Vault discovery endpoint to find the user's
        authentication profile, which is required for OAuth flows.

        Args:
            username (str): The username for whom to discover the authentication profile.

        Returns:
            dict: A dictionary with the profile 'id' and 'token_endpoint'. Returns an empty dictionary if
                  the profile cannot be found or an error occurs.
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
        """Requests an OAuth access token from the specified token endpoint.

        This private method performs a POST request to the token endpoint with the
        provided credentials to obtain an access token.

        Args:
            token_endpoint (str): The URL of the OAuth token endpoint.
            client_id (str): The client ID for the OAuth application.
            client_secret (str): The client secret for the OAuth application.
            scopes (list): A list of scopes to be requested for the access token.

        Returns:
            str: The obtained access token. Returns an empty string if the request fails.
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
        """Exchanges an OAuth access token for a Vault session ID.

        This private method sends the access token to Vault's authentication endpoint
        to acquire a session ID for making authenticated API calls.

        Args:
            vault_host (str): The hostname of the target Vault instance.
            oauth_oidc_profile_id (str): The ID of the OAuth/OIDC profile being used.
            client_id (str): The client ID associated with the OAuth application.
            access_token (str): The OAuth access token to be exchanged.

        Returns:
            str: The Vault session ID. Returns an empty string if the exchange fails.
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
