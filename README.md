# Vault Connector

General purpose Veeva Vault connector module in Python.

## Features
- Running VQL queries, with paging support
- Insert / Update / Upsert object operations with batch size handling
- Username / Password authentication or using external session ID
- OAuth 2.0 Client Credentials Flow
- Build in logging to standard output, or in a given log file.

## Usage

### Import the Module

 ```python
 from vault_connector import VaultConnector
```

### Instantiate the VaultConnector class

```python

vc = VaultConnector(
    hostname="<HOSTNAME>", 
    log_level="<LOG_LEVEL debug|error DEFAULT: error>", 
    log_target="<LOG_TARGET console|<FILENAME> DEFAULT: console>"
    )

```

**hostname**: DNS hostname of the Vault insance connect to (without https://)

**Optional parameters:**

**log_level:**
 - **debug:** Captures low-level logs, producing a higher volume of log entries.
 - **error:** Logs events that result in the termination of code execution.

**Default:** error

**log_target:**
* **console**: the log messages will be sent to the standard output
* **<{FILENAME}>**: the log messages will be written in the given files. e.g. ```vault_connector.log```


### Authenticate in Vault

```python
login_result:bool = vc.login(username="<USERNAME>", password="<PASSWORD>")
```

The method has a ```boolean``` return value. In case of any errors, the return value will be set to ```False```, and the error will be sent to the log.

Alternatively, you can authenticate using OAuth 2.0:

```python
login_result:bool = vc.login_oauth(username="<USERNAME>", client_id="<CLIENT_ID>", client_secret="<CLIENT_SECRET>", scopes=["<SCOPE1>", "<SCOPE2>"])
```

Or, the ```Session ID``` can be set explicitelly using the ```set_session_id``` method.

```python
vc.set_session_id(session_id:"<SESSION ID>")
```


## Run VQL Query

```python
vc.query(query="<VQL QUERY STRING>", pagesize=<PAGESIZE DEFAULT: 1000>)
```
The ```pagesize``` parameter is optional

### Return Vaule

The return value is a dictionary with two element:

```responseStatus```: The result of the operation. possible values:
- ```SUCCESS``` : Successful operation - does not mean that the result set contains any records
- ```FAILURE``` : Error -  the error will be sent to the log.

```data```: A Python list that contains the records in the result set as instances of Python dictionaries.


```python
{
    'responseStatus': 'SUCCESS',
    'data': [
        {
            <RECORD 1>
        },
        {
            <RECORD 2>
        }
        ...
        {
            <RECORD N>
        }
    ]
}
```

## Update Records

```python
vc.update(object="<OBJECT API NAME>", data=[<RECORDS TO UPDATE>], id_param="UNIQUE FIELD NAME | DEFAULT: id", migration_mode=False, no_triggers=False)
```

- ```object_name```: that API name of the object the update operation should run on. e.g. ```account__v```
- ```data```: list of records represented as Python dictionaries e.g.
- ```id_param```: Optional. To set a field to be used as adintifier. Any fields can be used that is set to ```unique``` in the Vault data model
- ```migration_mode```: Optional. If True, adds the X-VaultAPI-MigrationMode header. Defaults to False.
- ```no_triggers```: Optional. If True, adds the X-VaultAPI-NoTriggers header. Defaults to False.

```python
{
'id':'00P00000000K001',
'description__c':'Test'
}
```

### Return Value

The return value is a dictionary:

```responseStatus```: The result of the operation. possible values:
- ```SUCCESS``` : Successful operation - does not mean that the result set contains any records
- ```FAILURE``` : Error -  the error will be sent to the log.

On ```SUCCESS``` the method returns a responseStatus for each individual record in the same order provided in the input. The responseStatus for each record can be one of the following:
- ```SUCCESS```: Vault successfully updated at least one field value on this record.
- ```WARNING```: Vault successfully evaluated this record and reported a warning. For example, Vault returns a warning for records that process with no changes (no-op).
- ```FAILURE```: This record could not be evaluated and Vault made no field value changes. For example, an invalid or duplicate record ID.

```python
{
    'responseStatus': 'SUCCESS',
    'data': [
                {
                    'responseStatus': 'SUCCESS',
                    'data': {'id': 'V4Z000000002001',
                    'url': '/api/v24.3/vobjects/oca_org__c/V4Z000000002001'
                    }
                },
                {
                    'responseStatus': 'WARNING',
                    'warnings': [
                                    {
                                        'warning_type': 'NO_DATA_CHANGES',
                                        'message': 'No changes in values - record not updated'
                                    }
                                ],
                    'data': {
                                'id': 'V4Z000000002003',
                                'url': '/api/v24.3/vobjects/oca_org__c/V4Z000000002003'
                            }
                },
                {
                    'responseStatus': 'FAILURE',
                    'errors':   [
                                    {
                                        'type': 'INVALID_DATA',
                                        'message': 'The resource [V4Z000000002002a] does not exist'
                                    }
                                ]
                }
            ]
}
```


## Insert Record

```python
vc.insert(object="<OBJECT API NAME>", data=[<RECORDS TO UPDATE>], id_param="UNIQUE FIELD NAME | DEFAULT: None", migration_mode=False, no_triggers=False)
```

- ```object_name```: that API name of the object the insert operation should run on. e.g. ```account__v```
- ```data```: list of records represented as Python dictionaries. e.g.
- ```migration_mode```: Optional. If True, adds the X-VaultAPI-MigrationMode header. Defaults to False.
- ```no_triggers```: Optional. If True, adds the X-VaultAPI-NoTriggers header. Defaults to False.
```python
[
    {
        'name__v':'Test Record-1',
        'description__c':'Test Description-1'
    },
    {
        'name__v':'Test Record-2',
        'description__c':'Test Description-2'
    }
]
```
- ```id_param```: Optional. To set a field to be used as identifier. Any fields can be used that is set to ```unique``` in the Vault data model. In insert operations this attribute can be used for upsert operation.



### Return Value

The return value is a dictionary:

```responseStatus```: The result of the operation. possible values:
- ```SUCCESS``` : Successful operation - does not mean that the result set contains any records
- ```FAILURE``` : Error -  the error will be sent to the log.

On ```SUCCESS``` the method returns a responseStatus for each individual record in the same order provided in the input. The responseStatus for each record can be one of the following:
- ```SUCCESS```: Vault successfully updated at least one field value on this record.
- ```FAILURE```: This record could not be evaluated and Vault made no field value changes. For example, missing required parameter.

```python
{
    'responseStatus': 'SUCCESS',
    'data': [
        {
            'responseStatus': 'SUCCESS',
            'data': {
                'id': 'V4Z000000006003',
                'url': '/api/v24.3/vobjects/oca_org__c/V4Z000000006003'
            }
        },
        {
            'responseStatus': 'FAILURE',
            'errors': [
                        {
                            'type': 'PARAMETER_REQUIRED',
                            'message': 'Missing required parameter [name__v]'
                        }
                    ]
        }
    ]
}
```