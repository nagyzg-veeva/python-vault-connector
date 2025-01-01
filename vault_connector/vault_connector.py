import requests
import json
import logging
import inspect


class VaultConnector:

    api_version:str = "v24.3"
    timeout:int = 120
    upsert_page_size:int = 500
    query_page_size:int = 1000
    statuses:dict = {
        "SUCCESS":"SUCCESS",
        "FAILURE":"FAILURE"
    }


    def __init__(self, hostname:str, log_level:str='error', log_target:str='console') -> None:
        """
        Constructor

        Args:
            hostname (str): Vault hostname without the protocol (https://)
            log_level (str, optional): log level: debug  | error. Defaults to 'error'.
            log_target (str, optional): defineds where the log messages are being sent. console: standard output | <filename.extension>: file target. Defaults to 'console'.
        """

        self.password:str = None
        self.username:str = None
        self.domain:str = hostname
        self.session_id:str = ""
        self.base_url:str = f"https://{self.domain}"
        self.api_endpoint_url:str = f"{self.base_url}/api/{__class__.api_version}"
        
        self.logger:logging = self.__setup_logger(log_level=log_level, log_target = log_target)




    def login(self, username:str, password:str) -> bool:
        """
        Login to Vault, obtaining the session id
 
        Args:
            username (str): username
            password (str): password

        Returns:
            bool: login result
        """

        method_name:str = inspect.currentframe().f_code.co_name
        self.logger.debug(f'{method_name} - called')

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
                self.logger.error(f'{method_name} - {response.get("responseMessage")}')
                return False
            
        except Exception as e:
            self.logger.error(f"{method_name} - Login Error: {e}")
            return False



    def set_session_id(self, session_id: str) -> None:
        """
        Session id setter. Setting up the session id in case of external authentication

        Args:
            session_id (str): session id
        """
        method_name:str = inspect.currentframe().f_code.co_name
        self.logger.debug(f'{method_name} called')
        self.session_id = session_id



    def query(self, query:str, pagesize:int=0) -> list:
        """
        Query method with paging capabilities

        Args:
            query (str): VQL query
            pagesize (int, optional): pagesize of the iteration on the result set. Defaults to 1000.

        Returns:
            list: list of records in the result set
        """

        method_name:str = inspect.currentframe().f_code.co_name
        self.logger.debug(f'{method_name} called')

        if pagesize == 0:
            pagesize = __class__.query_page_size
            self.logger.debug(f'{method_name} - Page size set to default ({__class__.query_page_size})')

        retval = self.__get_retval_instance()

        if not self.session_id:
            self.logger.error(f"{method_name} - Vault operation called without valid Session ID")
            return retval

        request_url = self.api_endpoint_url + "/query"
        self.logger.debug(f'{method_name} - request URL: {request_url}')
        request_headers = {
            "Authorization": self.session_id,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }

        self.logger.debug(f'{method_name} - Sending Query: {query}')

        r = requests.post(url=request_url, headers=request_headers, data={"q": query})
        response = r.json()
        

        if response.get("responseStatus") == "FAILURE":
            retval.update({
                    "responseStatus":__class__.statuses.get("FAILURE"),
                    "data":"[]"
                    })
            self.logger.error(f'{response.get("errors")[0].get("type")} - {response.get("errors")[0].get("message")}')
            return retval
        
        self.logger.debug(f'{method_name} - Total number of records: {response.get("responseDetails").get('total')}')
        
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
        """ Update records of the give objects.

        Args:
            object (str): API name of the object to be updated
            data (list): list of records
            id_param (str, optional): Identifier to use for the operation. Defaults to "id".

        Returns:
            dict: a dictionary of the results
        """
        method_name:str = inspect.currentframe().f_code.co_name
        self.logger.debug(f'{method_name} called')

        return self.__upsert(operation="update", object=object, data=data, id_param=id_param)
    


    def insert(self, object: str, data: list, id_param="id") -> dict:
        """ Insert records of the give objects. using the id_param parameter with an external id, this method can be used for upsert operations.

        Args:
            object (str): API name of the object
            data (list): List of records to be inserted
            id_param (str, optional): Identifier to be used for the operation. Defaults to "id".

        Returns:
            dict: a dictionary of the results
        """
        method_name:str = inspect.currentframe().f_code.co_name
        self.logger.debug(f'{method_name} called')

        return self.__upsert(operation="insert", object=object, data=data, id_param=id_param)


    
    def __upsert(self, operation:str, object:str, data:list, id_param:str,) -> dict:
        """ Method to manage Vault interface interaction for the Insert and Update operations

        Args:
            operation (str): insert | update
            object (str): target object of the operation
            data (list): resords in scope
            id_param (str): Attribute to be used as an identifier for the operation.

        Returns:
            dict: return value
        """
        

        method_name:str = inspect.currentframe().f_code.co_name
        retval = self.__get_retval_instance()

        request_url = (
            f"{self.api_endpoint_url}/vobjects/{object}?idParam={id_param}"
        )

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
                self.logger.error(f'{response.get("errors")[0].get("type")} - {response.get("errors")[0].get("message")}')
                return retval

            else:
                retval.update({"responseStatus":__class__.statuses.get("SUCCESS")})
                retval.get('data').extend(response.get("data"))
                
        return retval
    


    def __split_list(self, list: list, chunk_size: int):
        """private util to split the list into chunks wiht the given chunk size

        Args:
            list (list): list to chunk
            chunk_size (int): size of the chunks

        Yields:
            Iterator[list]: cunks in the given size
        """

        method_name:str = inspect.currentframe().f_code.co_name
        retval = []

        for i in range(0, len(list), chunk_size):
            yield list[i : i + chunk_size]



    
    def __setup_logger(self, log_level:str, log_target:str) -> logging:
        """instantiates the logger.

        Args:
            log_level (str): log level
            log_target (str): log target: console | filename

        Returns:
            logging: logging module instance
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
        """cunstruct a standard return value structure

        Returns:
            dict: empty return value dict
        """

        return {
            "responseStatus":"",
            "data":[]
        }

