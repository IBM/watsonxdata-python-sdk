# coding: utf-8

# (C) Copyright IBM Corp. 2023.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# IBM OpenAPI SDK Code Generator Version: 3.72.2-2bede9d2-20230601-202845

"""
This is the Public API for IBM watsonx.data

API Version: SaaS-GA-1.0.0
"""

from enum import Enum
from typing import Dict, List
import json

from ibm_cloud_sdk_core import BaseService, DetailedResponse
from ibm_cloud_sdk_core.authenticators.authenticator import Authenticator
from ibm_cloud_sdk_core.get_authenticator import get_authenticator_from_environment
from ibm_cloud_sdk_core.utils import convert_list, convert_model

from .common import get_sdk_headers

##############################################################################
# Service
##############################################################################


class WatsonxDataV1(BaseService):
    """The watsonx.data V1 service."""

    DEFAULT_SERVICE_URL = 'https://lakehouse/api/v1'
    DEFAULT_SERVICE_NAME = 'watsonx_data'

    @classmethod
    def new_instance(
        cls,
        service_name: str = DEFAULT_SERVICE_NAME,
    ) -> 'WatsonxDataV1':
        """
        Return a new client for the watsonx.data service using the specified
               parameters and external configuration.
        """
        authenticator = get_authenticator_from_environment(service_name)
        service = cls(authenticator)
        service.configure_service(service_name)
        return service

    def __init__(
        self,
        authenticator: Authenticator = None,
    ) -> None:
        """
        Construct a new client for the watsonx.data service.

        :param Authenticator authenticator: The authenticator specifies the authentication mechanism.
               Get up to date information from https://github.com/IBM/python-sdk-core/blob/main/README.md
               about initializing the authenticator of your choice.
        """
        BaseService.__init__(self, service_url=self.DEFAULT_SERVICE_URL, authenticator=authenticator)

    #########################
    # AccessManagement
    #########################

    def create_db_conn_users(
        self,
        database_id: str,
        *,
        groups: List['BucketDbConnGroupsMetadata'] = None,
        users: List['BucketDbConnUsersMetadata'] = None,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Grant users and groups permission to the db connection.

        You require can_administer permission to perform this action.

        :param str database_id: The db connection id.
        :param List[BucketDbConnGroupsMetadata] groups: (optional) The group list.
        :param List[BucketDbConnUsersMetadata] users: (optional) The user list.
        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessResponse` object
        """

        if database_id is None:
            raise ValueError('database_id must be provided')
        if groups is not None:
            groups = [convert_model(x) for x in groups]
        if users is not None:
            users = [convert_model(x) for x in users]
        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='create_db_conn_users',
        )
        headers.update(sdk_headers)

        data = {
            'database_id': database_id,
            'groups': groups,
            'users': users,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/access/databases'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def list_data_policies(
        self,
        *,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        catalog_name: str = None,
        status: str = None,
        include_metadata: bool = None,
        include_rules: bool = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get policies.

        Get list of all data policies.

        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param str catalog_name: (optional) catalog name to filter.
        :param str status: (optional) policy status to filter.
        :param bool include_metadata: (optional) response will include data policy
               meta data or not.
        :param bool include_rules: (optional) response will include data policy
               rules or not.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `PolicyListSchema` object
        """

        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='list_data_policies',
        )
        headers.update(sdk_headers)

        params = {
            'catalog_name': catalog_name,
            'status': status,
            'include_metadata': include_metadata,
            'include_rules': include_rules,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/access/data_policies'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def create_data_policy(
        self,
        catalog_name: str,
        data_artifact: str,
        policy_name: str,
        rules: List['Rule'],
        *,
        description: str = None,
        status: str = None,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Create new data policy.

        Create new data policy.

        :param str catalog_name: catalog name.
        :param str data_artifact: data artifact.
        :param str policy_name: the displayed name for data policy.
        :param List[Rule] rules: rules.
        :param str description: (optional) a more detailed description of the
               policy.
        :param str status: (optional) data policy status.
        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `CreateDataPolicyCreatedBody` object
        """

        if catalog_name is None:
            raise ValueError('catalog_name must be provided')
        if data_artifact is None:
            raise ValueError('data_artifact must be provided')
        if policy_name is None:
            raise ValueError('policy_name must be provided')
        if rules is None:
            raise ValueError('rules must be provided')
        rules = [convert_model(x) for x in rules]
        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='create_data_policy',
        )
        headers.update(sdk_headers)

        data = {
            'catalog_name': catalog_name,
            'data_artifact': data_artifact,
            'policy_name': policy_name,
            'rules': rules,
            'description': description,
            'status': status,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/access/data_policies'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_data_policies(
        self,
        *,
        data_policies: List[str] = None,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Revoke data policy access management policy.

        You require catalog can_administer permission to perform this action.

        :param List[str] data_policies: (optional) data policy names array to be
               deleted.
        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='delete_data_policies',
        )
        headers.update(sdk_headers)

        data = {
            'data_policies': data_policies,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        url = '/access/data_policies'
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_engine_users(
        self,
        engine_id: str,
        *,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get permission in the engine.

        Get users and groups permission in the engine.

        :param str engine_id: Engine ID for GET.
        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetEngineUsersSchema` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_engine_users',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/access/engines/{engine_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_engine_users(
        self,
        engine_id: str,
        *,
        groups: List[str] = None,
        users: List[str] = None,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Revoke permission to access engine.

        You require administrator role or can_administer permission to perform this
        action.

        :param str engine_id: Engine ID for DELETE.
        :param List[str] groups: (optional) The group ids array to be deleted.
        :param List[str] users: (optional) The user names array to be deleted.
        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='delete_engine_users',
        )
        headers.update(sdk_headers)

        data = {
            'groups': groups,
            'users': users,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/access/engines/{engine_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def update_engine_users(
        self,
        engine_id: str,
        *,
        groups: List['EngineGroupsMetadata'] = None,
        users: List['EngineUsersMetadata'] = None,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Updates user and groups permission in the engine.

        You require administrator role or can_administer permission to perform this
        action.

        :param str engine_id: Engine ID for PATCH.
        :param List[EngineGroupsMetadata] groups: (optional) The group list.
        :param List[EngineUsersMetadata] users: (optional) The user list.
        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessResponse` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if groups is not None:
            groups = [convert_model(x) for x in groups]
        if users is not None:
            users = [convert_model(x) for x in users]
        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='update_engine_users',
        )
        headers.update(sdk_headers)

        data = {
            'groups': groups,
            'users': users,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/access/engines/{engine_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='PATCH',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_db_conn_users(
        self,
        database_id: str,
        *,
        groups: List[str] = None,
        users: List[str] = None,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Revoke permission to access db connection.

        You require can_administer permission to perform this action.

        :param str database_id: Db connection id for DELETE.
        :param List[str] groups: (optional) The group ids array to be deleted.
        :param List[str] users: (optional) The user names array to be deleted.
        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not database_id:
            raise ValueError('database_id must be provided')
        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='delete_db_conn_users',
        )
        headers.update(sdk_headers)

        data = {
            'groups': groups,
            'users': users,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['database_id']
        path_param_values = self.encode_path_vars(database_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/access/databases/{database_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def update_db_conn_users(
        self,
        database_id: str,
        *,
        groups: List['BucketDbConnGroupsMetadata'] = None,
        users: List['BucketDbConnUsersMetadata'] = None,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Updates user and groups permission in the db connection.

        You require can_administer permission to perform this action.

        :param str database_id: Db connection id for PATCH.
        :param List[BucketDbConnGroupsMetadata] groups: (optional) The group list.
        :param List[BucketDbConnUsersMetadata] users: (optional) The user list.
        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessResponse` object
        """

        if not database_id:
            raise ValueError('database_id must be provided')
        if groups is not None:
            groups = [convert_model(x) for x in groups]
        if users is not None:
            users = [convert_model(x) for x in users]
        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='update_db_conn_users',
        )
        headers.update(sdk_headers)

        data = {
            'groups': groups,
            'users': users,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['database_id']
        path_param_values = self.encode_path_vars(database_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/access/databases/{database_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='PATCH',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_db_conn_users(
        self,
        database_id: str,
        *,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get permission in the db connection.

        Get users and groups permission in the db connection.

        :param str database_id: Db connection id for GET.
        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetDbConnUsersSchema` object
        """

        if not database_id:
            raise ValueError('database_id must be provided')
        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_db_conn_users',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['database_id']
        path_param_values = self.encode_path_vars(database_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/access/databases/{database_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def create_catalog_users(
        self,
        catalog_name: str,
        *,
        groups: List['CatalogGroupsMetadata'] = None,
        users: List['CatalogUsersMetadata'] = None,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Grant users and groups permission to the catalog.

        You require can_administer permission to perform this action.

        :param str catalog_name: The catalog name.
        :param List[CatalogGroupsMetadata] groups: (optional) The group list.
        :param List[CatalogUsersMetadata] users: (optional) The user list.
        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessResponse` object
        """

        if catalog_name is None:
            raise ValueError('catalog_name must be provided')
        if groups is not None:
            groups = [convert_model(x) for x in groups]
        if users is not None:
            users = [convert_model(x) for x in users]
        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='create_catalog_users',
        )
        headers.update(sdk_headers)

        data = {
            'catalog_name': catalog_name,
            'groups': groups,
            'users': users,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/access/catalogs'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_catalog_users(
        self,
        catalog_name: str,
        *,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get users and groups permission in the catalog.

        Get users and groups permission in the catalog.

        :param str catalog_name: catalog name for GET.
        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetCatalogUsersSchema` object
        """

        if not catalog_name:
            raise ValueError('catalog_name must be provided')
        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_catalog_users',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['catalog_name']
        path_param_values = self.encode_path_vars(catalog_name)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/access/catalogs/{catalog_name}'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_catalog_users(
        self,
        catalog_name: str,
        *,
        groups: List[str] = None,
        users: List[str] = None,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Revoke multiple users and groups permission to access catalog.

        You require can_administer permission to perform this action.

        :param str catalog_name: Catalog name for DELETE.
        :param List[str] groups: (optional) The group ids array to be deleted.
        :param List[str] users: (optional) The user names array to be deleted.
        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not catalog_name:
            raise ValueError('catalog_name must be provided')
        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='delete_catalog_users',
        )
        headers.update(sdk_headers)

        data = {
            'groups': groups,
            'users': users,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['catalog_name']
        path_param_values = self.encode_path_vars(catalog_name)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/access/catalogs/{catalog_name}'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def update_catalog_users(
        self,
        catalog_name: str,
        *,
        groups: List['CatalogGroupsMetadata'] = None,
        users: List['CatalogUsersMetadata'] = None,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Updates user and groups permission in the catalog.

        You require can_administer permission to perform this action.

        :param str catalog_name: Catalog name for PATCH.
        :param List[CatalogGroupsMetadata] groups: (optional) The group list.
        :param List[CatalogUsersMetadata] users: (optional) The user list.
        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessResponse` object
        """

        if not catalog_name:
            raise ValueError('catalog_name must be provided')
        if groups is not None:
            groups = [convert_model(x) for x in groups]
        if users is not None:
            users = [convert_model(x) for x in users]
        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='update_catalog_users',
        )
        headers.update(sdk_headers)

        data = {
            'groups': groups,
            'users': users,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['catalog_name']
        path_param_values = self.encode_path_vars(catalog_name)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/access/catalogs/{catalog_name}'.format(**path_param_dict)
        request = self.prepare_request(
            method='PATCH',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def evaluate(
        self,
        *,
        resources: List['ResourcesMetadata'] = None,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Evaluate permission.

        Evaluate user has permission to access resource or not.

        :param List[ResourcesMetadata] resources: (optional) resource list.
        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `EvaluationResultSchema` object
        """

        if resources is not None:
            resources = [convert_model(x) for x in resources]
        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='evaluate',
        )
        headers.update(sdk_headers)

        data = {
            'resources': resources,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/access/evaluation'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_policies_list(
        self,
        *,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        catalog_list: List[str] = None,
        engine_list: List[str] = None,
        data_policies_list: List[str] = None,
        include_data_policies: bool = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get policies for specific catalog in catalog_name list.

        Get policies list.

        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param List[str] catalog_list: (optional) policies for specific catalogs
               list.
        :param List[str] engine_list: (optional) policies for specific engines
               list.
        :param List[str] data_policies_list: (optional) policies for specific Data
               Polices list.
        :param bool include_data_policies: (optional) include policies for specific
               catalogs or not.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `PolicySchemaList` object
        """

        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_policies_list',
        )
        headers.update(sdk_headers)

        params = {
            'catalog_list': convert_list(catalog_list),
            'engine_list': convert_list(engine_list),
            'data_policies_list': convert_list(data_policies_list),
            'include_data_policies': include_data_policies,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/access/policies'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def create_metastore_users(
        self,
        metastore_name: str,
        *,
        groups: List['GroupsMetadata'] = None,
        users: List['UsersMetadata'] = None,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Grant users and groups permission to the metastore.

        You require administrator role or can_administer permission to perform this
        action.

        :param str metastore_name: The metastore name.
        :param List[GroupsMetadata] groups: (optional) The group list.
        :param List[UsersMetadata] users: (optional) The user list.
        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessResponse` object
        """

        if metastore_name is None:
            raise ValueError('metastore_name must be provided')
        if groups is not None:
            groups = [convert_model(x) for x in groups]
        if users is not None:
            users = [convert_model(x) for x in users]
        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='create_metastore_users',
        )
        headers.update(sdk_headers)

        data = {
            'metastore_name': metastore_name,
            'groups': groups,
            'users': users,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/access/metastores'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_metastore_users(
        self,
        metastore_name: str,
        *,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get permission in the metastore.

        Get users and groups permission in the metastore.

        :param str metastore_name: Metastore name for GET.
        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetMetastoreUsersSchema` object
        """

        if not metastore_name:
            raise ValueError('metastore_name must be provided')
        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_metastore_users',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['metastore_name']
        path_param_values = self.encode_path_vars(metastore_name)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/access/metastores/{metastore_name}'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_metastore_users(
        self,
        metastore_name: str,
        *,
        groups: List[str] = None,
        users: List[str] = None,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Revoke permission to access metastore.

        You require administrator role or can_administer permission to perform this
        action.

        :param str metastore_name: Metastore name for DELETE.
        :param List[str] groups: (optional) The group ids array to be deleted.
        :param List[str] users: (optional) The user names array to be deleted.
        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not metastore_name:
            raise ValueError('metastore_name must be provided')
        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='delete_metastore_users',
        )
        headers.update(sdk_headers)

        data = {
            'groups': groups,
            'users': users,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['metastore_name']
        path_param_values = self.encode_path_vars(metastore_name)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/access/metastores/{metastore_name}'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def update_metastore_users(
        self,
        metastore_name: str,
        *,
        groups: List['GroupsMetadata'] = None,
        users: List['UsersMetadata'] = None,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Updates user and groups permission in the metastore.

        You require administrator role or can_administer permission to perform this
        action.

        :param str metastore_name: Metastore name for PATCH.
        :param List[GroupsMetadata] groups: (optional) The group list.
        :param List[UsersMetadata] users: (optional) The user list.
        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessResponse` object
        """

        if not metastore_name:
            raise ValueError('metastore_name must be provided')
        if groups is not None:
            groups = [convert_model(x) for x in groups]
        if users is not None:
            users = [convert_model(x) for x in users]
        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='update_metastore_users',
        )
        headers.update(sdk_headers)

        data = {
            'groups': groups,
            'users': users,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['metastore_name']
        path_param_values = self.encode_path_vars(metastore_name)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/access/metastores/{metastore_name}'.format(**path_param_dict)
        request = self.prepare_request(
            method='PATCH',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def create_bucket_users(
        self,
        bucket_id: str,
        *,
        groups: List['BucketDbConnGroupsMetadata'] = None,
        users: List['BucketDbConnUsersMetadata'] = None,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Grant users and groups permission to the bucket.

        You require can_administer permission to perform this action.

        :param str bucket_id: The bucket id.
        :param List[BucketDbConnGroupsMetadata] groups: (optional) The group list.
        :param List[BucketDbConnUsersMetadata] users: (optional) The user list.
        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessResponse` object
        """

        if bucket_id is None:
            raise ValueError('bucket_id must be provided')
        if groups is not None:
            groups = [convert_model(x) for x in groups]
        if users is not None:
            users = [convert_model(x) for x in users]
        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='create_bucket_users',
        )
        headers.update(sdk_headers)

        data = {
            'bucket_id': bucket_id,
            'groups': groups,
            'users': users,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/access/buckets'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_default_policies(
        self,
        *,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get AMS default policies.

        Get AMS default policies.

        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `DefaultPolicySchema` object
        """

        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_default_policies',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/access/default_policies'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def get_policy_version(
        self,
        *,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get AMS policies version.

        Get AMS policies version.

        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `PolicyVersionResultSchema` object
        """

        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_policy_version',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/access/policy_versions'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def get_data_policy(
        self,
        policy_name: str,
        *,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get policy.

        Get policy detail.

        :param str policy_name: policy name to get.
        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `PolicySchema` object
        """

        if not policy_name:
            raise ValueError('policy_name must be provided')
        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_data_policy',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['policy_name']
        path_param_values = self.encode_path_vars(policy_name)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/access/data_policies/{policy_name}'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def replace_data_policy(
        self,
        policy_name: str,
        catalog_name: str,
        data_artifact: str,
        rules: List['Rule'],
        *,
        description: str = None,
        status: str = None,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Updates data policy.

        You require catalog can_administer permission to perform this action.

        :param str policy_name: Policy name for PATCH.
        :param str catalog_name: catalog name.
        :param str data_artifact: data artifact.
        :param List[Rule] rules: rules.
        :param str description: (optional) a more detailed description of the
               policy.
        :param str status: (optional) data policy status.
        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ReplaceDataPolicyCreatedBody` object
        """

        if not policy_name:
            raise ValueError('policy_name must be provided')
        if catalog_name is None:
            raise ValueError('catalog_name must be provided')
        if data_artifact is None:
            raise ValueError('data_artifact must be provided')
        if rules is None:
            raise ValueError('rules must be provided')
        rules = [convert_model(x) for x in rules]
        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='replace_data_policy',
        )
        headers.update(sdk_headers)

        data = {
            'catalog_name': catalog_name,
            'data_artifact': data_artifact,
            'rules': rules,
            'description': description,
            'status': status,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['policy_name']
        path_param_values = self.encode_path_vars(policy_name)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/access/data_policies/{policy_name}'.format(**path_param_dict)
        request = self.prepare_request(
            method='PUT',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_data_policy(
        self,
        policy_name: str,
        *,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Revoke data policy access management policy.

        You require catalog can_administer permission to perform this action.

        :param str policy_name: Policy name for DELETE.
        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not policy_name:
            raise ValueError('policy_name must be provided')
        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='delete_data_policy',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['policy_name']
        path_param_values = self.encode_path_vars(policy_name)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/access/data_policies/{policy_name}'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def create_engine_users(
        self,
        engine_id: str,
        *,
        groups: List['EngineGroupsMetadata'] = None,
        users: List['EngineUsersMetadata'] = None,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Grant permission to the engine.

        You require administrator role or can_administer permission to perform this
        action.

        :param str engine_id: The engine id.
        :param List[EngineGroupsMetadata] groups: (optional) The group list.
        :param List[EngineUsersMetadata] users: (optional) The user list.
        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessResponse` object
        """

        if engine_id is None:
            raise ValueError('engine_id must be provided')
        if groups is not None:
            groups = [convert_model(x) for x in groups]
        if users is not None:
            users = [convert_model(x) for x in users]
        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='create_engine_users',
        )
        headers.update(sdk_headers)

        data = {
            'engine_id': engine_id,
            'groups': groups,
            'users': users,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/access/engines'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_bucket_users(
        self,
        bucket_id: str,
        *,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get permission in the bucket.

        Get users and groups permission in the bucket.

        :param str bucket_id: Bucket name for GET.
        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetBucketUsersSchema` object
        """

        if not bucket_id:
            raise ValueError('bucket_id must be provided')
        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_bucket_users',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['bucket_id']
        path_param_values = self.encode_path_vars(bucket_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/access/buckets/{bucket_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_bucket_users(
        self,
        bucket_id: str,
        *,
        groups: List[str] = None,
        users: List[str] = None,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Revoke permission to access bucket.

        You require can_administer permission to perform this action.

        :param str bucket_id: Bucket ID for DELETE.
        :param List[str] groups: (optional) The group ids array to be deleted.
        :param List[str] users: (optional) The user names array to be deleted.
        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not bucket_id:
            raise ValueError('bucket_id must be provided')
        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='delete_bucket_users',
        )
        headers.update(sdk_headers)

        data = {
            'groups': groups,
            'users': users,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['bucket_id']
        path_param_values = self.encode_path_vars(bucket_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/access/buckets/{bucket_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def update_bucket_users(
        self,
        bucket_id: str,
        *,
        groups: List['BucketDbConnGroupsMetadata'] = None,
        users: List['BucketDbConnUsersMetadata'] = None,
        lh_instance_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Updates user and groups permission in the bucket.

        You require can_administer permission to perform this action.

        :param str bucket_id: Bucket ID for PATCH.
        :param List[BucketDbConnGroupsMetadata] groups: (optional) The group list.
        :param List[BucketDbConnUsersMetadata] users: (optional) The user list.
        :param str lh_instance_id: (optional) Lake House Instance ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessResponse` object
        """

        if not bucket_id:
            raise ValueError('bucket_id must be provided')
        if groups is not None:
            groups = [convert_model(x) for x in groups]
        if users is not None:
            users = [convert_model(x) for x in users]
        headers = {
            'LhInstanceId': lh_instance_id,
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='update_bucket_users',
        )
        headers.update(sdk_headers)

        data = {
            'groups': groups,
            'users': users,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['bucket_id']
        path_param_values = self.encode_path_vars(bucket_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/access/buckets/{bucket_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='PATCH',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # buckets
    #########################

    def get_buckets(
        self,
        *,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get buckets.

        Get list of all buckets registered to Lakehouse.

        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetBucketsOKBody` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_buckets',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/buckets'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def get_bucket_objects(
        self,
        bucket_id: str,
        *,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get bucket objects.

        Fetch all objects from a given bucket.

        :param str bucket_id: Bucket ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetBucketObjectsOKBody` object
        """

        if not bucket_id:
            raise ValueError('bucket_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_bucket_objects',
        )
        headers.update(sdk_headers)

        params = {
            'bucket_id': bucket_id,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/buckets/bucket/objects'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def deactivate_bucket(
        self,
        bucket_id: str,
        *,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Deactivate bucket.

        Deactivate an active bucket in Lakehouse.

        :param str bucket_id: Bucket name.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `BinaryIO` result
        """

        if bucket_id is None:
            raise ValueError('bucket_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='deactivate_bucket',
        )
        headers.update(sdk_headers)

        data = {
            'bucket_id': bucket_id,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = '*/*'

        url = '/buckets/bucket/deactivate'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def register_bucket(
        self,
        bucket_details: 'BucketDetails',
        description: str,
        table_type: str,
        bucket_type: str,
        catalog_name: str,
        managed_by: str,
        *,
        bucket_display_name: str = None,
        bucket_tags: List[str] = None,
        catalog_tags: List[str] = None,
        thrift_uri: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Register bucket.

        Register a new bucket in Lakehouse.

        :param BucketDetails bucket_details: Bucket Details.
        :param str description: Bucket description.
        :param str table_type: Table type.
        :param str bucket_type: Bucket Type.
        :param str catalog_name: Catalog name for the new catalog to be created
               with bucket.
        :param str managed_by: Managed by.
        :param str bucket_display_name: (optional) Bucket Display name.
        :param List[str] bucket_tags: (optional) tags.
        :param List[str] catalog_tags: (optional) Catalog tags.
        :param str thrift_uri: (optional) Thrift URI.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `RegisterBucketCreatedBody` object
        """

        if bucket_details is None:
            raise ValueError('bucket_details must be provided')
        if description is None:
            raise ValueError('description must be provided')
        if table_type is None:
            raise ValueError('table_type must be provided')
        if bucket_type is None:
            raise ValueError('bucket_type must be provided')
        if catalog_name is None:
            raise ValueError('catalog_name must be provided')
        if managed_by is None:
            raise ValueError('managed_by must be provided')
        bucket_details = convert_model(bucket_details)
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='register_bucket',
        )
        headers.update(sdk_headers)

        data = {
            'bucket_details': bucket_details,
            'description': description,
            'table_type': table_type,
            'bucket_type': bucket_type,
            'catalog_name': catalog_name,
            'managed_by': managed_by,
            'bucket_display_name': bucket_display_name,
            'bucket_tags': bucket_tags,
            'catalog_tags': catalog_tags,
            'thrift_uri': thrift_uri,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/buckets/bucket'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def unregister_bucket(
        self,
        bucket_id: str,
        *,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Unregister Bucket.

        Unregister a bucket from Lakehouse.

        :param str bucket_id: Bucket name.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if bucket_id is None:
            raise ValueError('bucket_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='unregister_bucket',
        )
        headers.update(sdk_headers)

        data = {
            'bucket_id': bucket_id,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        url = '/buckets/bucket'
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def update_bucket(
        self,
        bucket_id: str,
        *,
        access_key: str = None,
        bucket_display_name: str = None,
        description: str = None,
        secret_key: str = None,
        tags: List[str] = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Update bucket.

        Update bucket details/credentials.

        :param str bucket_id: Bucket ID auto generated during bucket registration.
        :param str access_key: (optional) Access key ID, encrypted during bucket
               registration.
        :param str bucket_display_name: (optional) Bucket display name.
        :param str description: (optional) Modified description.
        :param str secret_key: (optional) Secret access key, encrypted during
               bucket registration.
        :param List[str] tags: (optional) Tags.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessResponse` object
        """

        if bucket_id is None:
            raise ValueError('bucket_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='update_bucket',
        )
        headers.update(sdk_headers)

        data = {
            'bucket_id': bucket_id,
            'access_key': access_key,
            'bucket_display_name': bucket_display_name,
            'description': description,
            'secret_key': secret_key,
            'tags': tags,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/buckets/bucket'
        request = self.prepare_request(
            method='PATCH',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def activate_bucket(
        self,
        bucket_id: str,
        *,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Active bucket.

        Activate an invalid bucket in Lakehouse.

        :param str bucket_id: Bucket name.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `BinaryIO` result
        """

        if bucket_id is None:
            raise ValueError('bucket_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='activate_bucket',
        )
        headers.update(sdk_headers)

        data = {
            'bucket_id': bucket_id,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = '*/*'

        url = '/buckets/bucket/activate'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # databases
    #########################

    def get_databases(
        self,
        *,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get databases.

        Get list of all databases in Lakehouse.

        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `BinaryIO` result
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_databases',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = '*/*'

        url = '/databases'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def create_database_catalog(
        self,
        database_display_name: str,
        database_type: str,
        catalog_name: str,
        *,
        database_details: 'RegisterDatabaseCatalogBodyDatabaseDetails' = None,
        description: str = None,
        tags: List[str] = None,
        created_by: str = None,
        created_on: int = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Add/Create database.

        Add or create a new database in Lakehouse.

        :param str database_display_name: Database display name.
        :param str database_type: Connector type.
        :param str catalog_name: Catalog name of the new catalog to be created with
               database.
        :param RegisterDatabaseCatalogBodyDatabaseDetails database_details:
               (optional) database details.
        :param str description: (optional) Database description.
        :param List[str] tags: (optional) tags.
        :param str created_by: (optional) Created by.
        :param int created_on: (optional) Created on.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `BinaryIO` result
        """

        if database_display_name is None:
            raise ValueError('database_display_name must be provided')
        if database_type is None:
            raise ValueError('database_type must be provided')
        if catalog_name is None:
            raise ValueError('catalog_name must be provided')
        if database_details is not None:
            database_details = convert_model(database_details)
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='create_database_catalog',
        )
        headers.update(sdk_headers)

        data = {
            'database_display_name': database_display_name,
            'database_type': database_type,
            'catalog_name': catalog_name,
            'database_details': database_details,
            'description': description,
            'tags': tags,
            'created_by': created_by,
            'created_on': created_on,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = '*/*'

        url = '/databases/database'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_database_catalog(
        self,
        database_id: str,
        *,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Delete database.

        Delete a database from Lakehouse.

        :param str database_id: Database ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if database_id is None:
            raise ValueError('database_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='delete_database_catalog',
        )
        headers.update(sdk_headers)

        data = {
            'database_id': database_id,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        url = '/databases/database'
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def update_database(
        self,
        database_id: str,
        *,
        database_details: 'UpdateDatabaseBodyDatabaseDetails' = None,
        database_display_name: str = None,
        description: str = None,
        tags: List[str] = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Update database.

        Update database details.

        :param str database_id: Database ID.
        :param UpdateDatabaseBodyDatabaseDetails database_details: (optional)
               database details.
        :param str database_display_name: (optional) Database display name.
        :param str description: (optional) Database description.
        :param List[str] tags: (optional) tags.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `BinaryIO` result
        """

        if database_id is None:
            raise ValueError('database_id must be provided')
        if database_details is not None:
            database_details = convert_model(database_details)
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='update_database',
        )
        headers.update(sdk_headers)

        data = {
            'database_id': database_id,
            'database_details': database_details,
            'database_display_name': database_display_name,
            'description': description,
            'tags': tags,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = '*/*'

        url = '/databases/database'
        request = self.prepare_request(
            method='PATCH',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # engines
    #########################

    def pause_engine(
        self,
        engine_id: str,
        *,
        created_by: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Pause engine.

        Pause a running engine.

        :param str engine_id: Engine ID to be paused.
        :param str created_by: (optional) Created by - Logged in username.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `PauseEngineCreatedBody` object
        """

        if engine_id is None:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='pause_engine',
        )
        headers.update(sdk_headers)

        data = {
            'engine_id': engine_id,
            'created_by': created_by,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/engines/engine/pause'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_engines(
        self,
        *,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get engines.

        Get all engine details.

        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetEnginesOKBody` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_engines',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/engines'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def get_deployments(
        self,
        *,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get instance details.

        Get instance details.

        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `BinaryIO` result
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_deployments',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = '*/*'

        url = '/instance'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def update_engine(
        self,
        engine_id: str,
        *,
        coordinator: 'NodeDescription' = None,
        description: str = None,
        engine_display_name: str = None,
        tags: List[str] = None,
        worker: 'NodeDescription' = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Update engine.

        Update engine.

        :param str engine_id: Engine ID.
        :param NodeDescription coordinator: (optional) NodeDescription.
        :param str description: (optional) Modified description.
        :param str engine_display_name: (optional) Engine display name.
        :param List[str] tags: (optional) Tags.
        :param NodeDescription worker: (optional) NodeDescription.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `BinaryIO` result
        """

        if engine_id is None:
            raise ValueError('engine_id must be provided')
        if coordinator is not None:
            coordinator = convert_model(coordinator)
        if worker is not None:
            worker = convert_model(worker)
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='update_engine',
        )
        headers.update(sdk_headers)

        data = {
            'engine_id': engine_id,
            'coordinator': coordinator,
            'description': description,
            'engine_display_name': engine_display_name,
            'tags': tags,
            'worker': worker,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = '*/*'

        url = '/engines/engine'
        request = self.prepare_request(
            method='PATCH',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def create_engine(
        self,
        version: str,
        engine_details: 'EngineDetailsBody',
        origin: str,
        type: str,
        *,
        description: str = None,
        engine_display_name: str = None,
        first_time_use: bool = None,
        region: str = None,
        associated_catalogs: List[str] = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Create engine.

        Create a new engine.

        :param str version: Version like 0.278 for presto or else.
        :param EngineDetailsBody engine_details: Node details.
        :param str origin: Origin - created or registered.
        :param str type: Engine type presto, others like netezza.
        :param str description: (optional) Engine description.
        :param str engine_display_name: (optional) Engine display name.
        :param bool first_time_use: (optional) Optional parameter for UI - set as
               true when first time use.
        :param str region: (optional) Region (cloud).
        :param List[str] associated_catalogs: (optional) Associated catalogs.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `BinaryIO` result
        """

        if version is None:
            raise ValueError('version must be provided')
        if engine_details is None:
            raise ValueError('engine_details must be provided')
        if origin is None:
            raise ValueError('origin must be provided')
        if type is None:
            raise ValueError('type must be provided')
        engine_details = convert_model(engine_details)
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='create_engine',
        )
        headers.update(sdk_headers)

        data = {
            'version': version,
            'engine_details': engine_details,
            'origin': origin,
            'type': type,
            'description': description,
            'engine_display_name': engine_display_name,
            'first_time_use': first_time_use,
            'region': region,
            'associated_catalogs': associated_catalogs,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = '*/*'

        url = '/engines/engine'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_engine(
        self,
        engine_id: str,
        *,
        created_by: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Delete engine.

        Delete an engine from lakehouse.

        :param str engine_id: Engine ID.
        :param str created_by: (optional) Created by.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if engine_id is None:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='delete_engine',
        )
        headers.update(sdk_headers)

        data = {
            'engine_id': engine_id,
            'created_by': created_by,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        url = '/engines/engine'
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def resume_engine(
        self,
        engine_id: str,
        *,
        created_by: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Resume engine.

        Resume a paused engine.

        :param str engine_id: Engine ID to be resumed.
        :param str created_by: (optional) Created by - logged in username.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ResumeEngineCreatedBody` object
        """

        if engine_id is None:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='resume_engine',
        )
        headers.update(sdk_headers)

        data = {
            'engine_id': engine_id,
            'created_by': created_by,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/engines/engine/resume'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # explain
    #########################

    def explain_analyze_statement(
        self,
        catalog_name: str,
        engine_id: str,
        schema_name: str,
        statement: str,
        *,
        verbose: bool = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Explain analyze.

        Return query metrics after query is complete.

        :param str catalog_name: Catalog name.
        :param str engine_id: Engine name.
        :param str schema_name: Schema name.
        :param str statement: Statement.
        :param bool verbose: (optional) Verbose.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ExplainAnalyzeStatementCreatedBody` object
        """

        if catalog_name is None:
            raise ValueError('catalog_name must be provided')
        if engine_id is None:
            raise ValueError('engine_id must be provided')
        if schema_name is None:
            raise ValueError('schema_name must be provided')
        if statement is None:
            raise ValueError('statement must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='explain_analyze_statement',
        )
        headers.update(sdk_headers)

        data = {
            'catalog_name': catalog_name,
            'engine_id': engine_id,
            'schema_name': schema_name,
            'statement': statement,
            'verbose': verbose,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/explainanalyze'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def explain_statement(
        self,
        engine_id: str,
        statement: str,
        *,
        catalog_name: str = None,
        format: str = None,
        schema_name: str = None,
        type: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Explain.

        Explain a query statement.

        :param str engine_id: Engine name.
        :param str statement: Statement.
        :param str catalog_name: (optional) Catalog name.
        :param str format: (optional) Format.
        :param str schema_name: (optional) Schema name.
        :param str type: (optional) Type.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ExplainStatementCreatedBody` object
        """

        if engine_id is None:
            raise ValueError('engine_id must be provided')
        if statement is None:
            raise ValueError('statement must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='explain_statement',
        )
        headers.update(sdk_headers)

        data = {
            'engine_id': engine_id,
            'statement': statement,
            'catalog_name': catalog_name,
            'format': format,
            'schema_name': schema_name,
            'type': type,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/explain'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # lhconsole
    #########################

    def test_lh_console(
        self,
        **kwargs,
    ) -> DetailedResponse:
        """
        Readiness API.

        Verify lhconsole server is up and running.

        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessResponse` object
        """

        headers = {}
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='test_lh_console',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/ready'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # metastores
    #########################

    def get_metastores(
        self,
        *,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get Catalogs.

        Get list of all registered metastores.

        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetMetastoresOKBody` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_metastores',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/catalogs'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def get_hms(
        self,
        *,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get Metastore.

        Get list of all registered HMS metastores.

        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `BinaryIO` result
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_hms',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = '*/*'

        url = '/metastores'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def add_metastore_to_engine(
        self,
        catalog_name: str,
        engine_id: str,
        *,
        created_by: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Add catalog to engine.

        Associate a catalog to an engine.

        :param str catalog_name: Catalog name.
        :param str engine_id: Engine name.
        :param str created_by: (optional) Created by.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `BinaryIO` result
        """

        if catalog_name is None:
            raise ValueError('catalog_name must be provided')
        if engine_id is None:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='add_metastore_to_engine',
        )
        headers.update(sdk_headers)

        data = {
            'catalog_name': catalog_name,
            'engine_id': engine_id,
            'created_by': created_by,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = '*/*'

        url = '/catalogs/add_catalog_to_engine'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def remove_catalog_from_engine(
        self,
        catalog_name: str,
        engine_id: str,
        *,
        created_by: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Remove catalog from engine.

        Remove a catalog from an engine.

        :param str catalog_name: Catalog name.
        :param str engine_id: Engine name.
        :param str created_by: (optional) Created by.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `BinaryIO` result
        """

        if catalog_name is None:
            raise ValueError('catalog_name must be provided')
        if engine_id is None:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='remove_catalog_from_engine',
        )
        headers.update(sdk_headers)

        data = {
            'catalog_name': catalog_name,
            'engine_id': engine_id,
            'created_by': created_by,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = '*/*'

        url = '/catalogs/remove_catalog_from_engine'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # queries
    #########################

    def save_query(
        self,
        query_name: str,
        created_by: str,
        description: str,
        query_string: str,
        *,
        created_on: str = None,
        engine_id: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Save query.

        Save a new query.

        :param str query_name: Query name.
        :param str created_by: Created by.
        :param str description: Description.
        :param str query_string: Query string.
        :param str created_on: (optional) Created on.
        :param str engine_id: (optional) Engine ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessResponse` object
        """

        if not query_name:
            raise ValueError('query_name must be provided')
        if created_by is None:
            raise ValueError('created_by must be provided')
        if description is None:
            raise ValueError('description must be provided')
        if query_string is None:
            raise ValueError('query_string must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='save_query',
        )
        headers.update(sdk_headers)

        data = {
            'created_by': created_by,
            'description': description,
            'query_string': query_string,
            'created_on': created_on,
            'engine_id': engine_id,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['query_name']
        path_param_values = self.encode_path_vars(query_name)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/queries/{query_name}'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_query(
        self,
        query_name: str,
        *,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Delete query.

        Delete a saved query.

        :param str query_name: Query name.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not query_name:
            raise ValueError('query_name must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='delete_query',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['query_name']
        path_param_values = self.encode_path_vars(query_name)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/queries/{query_name}'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def update_query(
        self,
        query_name: str,
        query_string: str,
        description: str,
        new_query_name: str,
        *,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Update query.

        Update a saved query.

        :param str query_name: Query name.
        :param str query_string: Query string.
        :param str description: Description.
        :param str new_query_name: New query name.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessResponse` object
        """

        if not query_name:
            raise ValueError('query_name must be provided')
        if query_string is None:
            raise ValueError('query_string must be provided')
        if description is None:
            raise ValueError('description must be provided')
        if new_query_name is None:
            raise ValueError('new_query_name must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='update_query',
        )
        headers.update(sdk_headers)

        data = {
            'query_string': query_string,
            'description': description,
            'new_query_name': new_query_name,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['query_name']
        path_param_values = self.encode_path_vars(query_name)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/queries/{query_name}'.format(**path_param_dict)
        request = self.prepare_request(
            method='PATCH',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_queries(
        self,
        *,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get queries.

        List all saved queries.

        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetQueriesOKBody` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_queries',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/queries'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # schemas
    #########################

    def create_schema(
        self,
        catalog_name: str,
        engine_id: str,
        schema_name: str,
        *,
        bucket_name: str = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Create schema.

        Create a new schema.

        :param str catalog_name: Catalog name.
        :param str engine_id: Engine ID.
        :param str schema_name: Schema name.
        :param str bucket_name: (optional) Bucket associated to metastore where
               schema will be added.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessResponse` object
        """

        if catalog_name is None:
            raise ValueError('catalog_name must be provided')
        if engine_id is None:
            raise ValueError('engine_id must be provided')
        if schema_name is None:
            raise ValueError('schema_name must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='create_schema',
        )
        headers.update(sdk_headers)

        data = {
            'catalog_name': catalog_name,
            'engine_id': engine_id,
            'schema_name': schema_name,
            'bucket_name': bucket_name,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/schemas/schema'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_schema(
        self,
        catalog_name: str,
        engine_id: str,
        schema_name: str,
        *,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Delete schema.

        Delete a schema.

        :param str catalog_name: Catalog name.
        :param str engine_id: Engine ID.
        :param str schema_name: Schema name.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if catalog_name is None:
            raise ValueError('catalog_name must be provided')
        if engine_id is None:
            raise ValueError('engine_id must be provided')
        if schema_name is None:
            raise ValueError('schema_name must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='delete_schema',
        )
        headers.update(sdk_headers)

        data = {
            'catalog_name': catalog_name,
            'engine_id': engine_id,
            'schema_name': schema_name,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        url = '/schemas/schema'
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_schemas(
        self,
        engine_id: str,
        catalog_name: str,
        *,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get schemas.

        List schemas in catalog.

        :param str engine_id: Engine name.
        :param str catalog_name: Catalog name.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSchemasOKBody` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if not catalog_name:
            raise ValueError('catalog_name must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_schemas',
        )
        headers.update(sdk_headers)

        params = {
            'engine_id': engine_id,
            'catalog_name': catalog_name,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/schemas'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # statement
    #########################

    def post_query(
        self,
        engine: str,
        catalog: str,
        schema: str,
        sql_query: str,
        *,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Run SQL statement.

        Using this API to run a SQL statement.

        :param str engine: Presto engine name.
        :param str catalog: Catalog name.
        :param str schema: Schema name.
        :param str sql_query: SQL Query.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `BinaryIO` result
        """

        if not engine:
            raise ValueError('engine must be provided')
        if not catalog:
            raise ValueError('catalog must be provided')
        if not schema:
            raise ValueError('schema must be provided')
        if not sql_query:
            raise ValueError('sql_query must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='post_query',
        )
        headers.update(sdk_headers)

        params = {
            'engine': engine,
        }

        form_data = []
        form_data.append(('catalog', (None, catalog, 'text/plain')))
        form_data.append(('schema', (None, schema, 'text/plain')))
        form_data.append(('sqlQuery', (None, sql_query, 'text/plain')))

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = '*/*'

        url = '/v1/statement'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            params=params,
            files=form_data,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # tables
    #########################

    def delete_table(
        self,
        delete_tables: List['DeleteTableBodyDeleteTablesItems'],
        engine_id: str,
        *,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Delete table.

        Delete one or multiple tables for a given schema and catalog.

        :param List[DeleteTableBodyDeleteTablesItems] delete_tables: Delete table
               list.
        :param str engine_id: Engine ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if delete_tables is None:
            raise ValueError('delete_tables must be provided')
        if engine_id is None:
            raise ValueError('engine_id must be provided')
        delete_tables = [convert_model(x) for x in delete_tables]
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='delete_table',
        )
        headers.update(sdk_headers)

        data = {
            'delete_tables': delete_tables,
            'engine_id': engine_id,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        url = '/tables/table'
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def update_table(
        self,
        engine_id: str,
        catalog_name: str,
        schema_name: str,
        table_name: str,
        *,
        add_columns: List['UpdateTableBodyAddColumnsItems'] = None,
        drop_columns: List['UpdateTableBodyDropColumnsItems'] = None,
        new_table_name: str = None,
        rename_columns: List['UpdateTableBodyRenameColumnsItems'] = None,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Update table.

        Update the given table - rename table, add/drop/rename columns.

        :param str engine_id: Engine name.
        :param str catalog_name: Catalog name.
        :param str schema_name: Schema name.
        :param str table_name: Table name.
        :param List[UpdateTableBodyAddColumnsItems] add_columns: (optional) Add
               columns.
        :param List[UpdateTableBodyDropColumnsItems] drop_columns: (optional) Drop
               columns.
        :param str new_table_name: (optional) New table name.
        :param List[UpdateTableBodyRenameColumnsItems] rename_columns: (optional)
               Rename columns.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `BinaryIO` result
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if not catalog_name:
            raise ValueError('catalog_name must be provided')
        if not schema_name:
            raise ValueError('schema_name must be provided')
        if not table_name:
            raise ValueError('table_name must be provided')
        if add_columns is not None:
            add_columns = [convert_model(x) for x in add_columns]
        if drop_columns is not None:
            drop_columns = [convert_model(x) for x in drop_columns]
        if rename_columns is not None:
            rename_columns = [convert_model(x) for x in rename_columns]
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='update_table',
        )
        headers.update(sdk_headers)

        params = {
            'engine_id': engine_id,
            'catalog_name': catalog_name,
            'schema_name': schema_name,
            'table_name': table_name,
        }

        data = {
            'add_columns': add_columns,
            'drop_columns': drop_columns,
            'new_table_name': new_table_name,
            'rename_columns': rename_columns,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = '*/*'

        url = '/tables/table'
        request = self.prepare_request(
            method='PATCH',
            url=url,
            headers=headers,
            params=params,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_table_snapshots(
        self,
        engine_id: str,
        catalog_name: str,
        schema_name: str,
        table_name: str,
        *,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get table snapshots.

        List all table snapshots.

        :param str engine_id: Engine name.
        :param str catalog_name: Catalog name.
        :param str schema_name: Schema name.
        :param str table_name: Table name.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetTableSnapshotsOKBody` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if not catalog_name:
            raise ValueError('catalog_name must be provided')
        if not schema_name:
            raise ValueError('schema_name must be provided')
        if not table_name:
            raise ValueError('table_name must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_table_snapshots',
        )
        headers.update(sdk_headers)

        params = {
            'engine_id': engine_id,
            'catalog_name': catalog_name,
            'schema_name': schema_name,
            'table_name': table_name,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/tables/table/snapshots'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def rollback_snapshot(
        self,
        engine_id: str,
        catalog_name: str,
        schema_name: str,
        snapshot_id: str,
        table_name: str,
        *,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Rollback snapshot.

        Rollback to a table snapshot.

        :param str engine_id: Engine name.
        :param str catalog_name: Catalog name.
        :param str schema_name: Schema name.
        :param str snapshot_id: Snapshot id.
        :param str table_name: Table name.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessResponse` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if not catalog_name:
            raise ValueError('catalog_name must be provided')
        if not schema_name:
            raise ValueError('schema_name must be provided')
        if snapshot_id is None:
            raise ValueError('snapshot_id must be provided')
        if table_name is None:
            raise ValueError('table_name must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='rollback_snapshot',
        )
        headers.update(sdk_headers)

        params = {
            'engine_id': engine_id,
            'catalog_name': catalog_name,
            'schema_name': schema_name,
        }

        data = {
            'snapshot_id': snapshot_id,
            'table_name': table_name,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/tables/table/rollback'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            params=params,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_tables(
        self,
        engine_id: str,
        catalog_name: str,
        schema_name: str,
        *,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get tables.

        List all tables in a schema in a catalog for a given engine.

        :param str engine_id: Engine name.
        :param str catalog_name: Catalog name.
        :param str schema_name: Schema name.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetTablesOKBody` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if not catalog_name:
            raise ValueError('catalog_name must be provided')
        if not schema_name:
            raise ValueError('schema_name must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='get_tables',
        )
        headers.update(sdk_headers)

        params = {
            'engine_id': engine_id,
            'catalog_name': catalog_name,
            'schema_name': schema_name,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/tables'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def parse_csv(
        self,
        engine: str,
        parse_file: str,
        file_type: str,
        *,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Parse CSV for table creation.

        When creating a tabble, parse the CSV file.

        :param str engine: Presto engine name.
        :param str parse_file: parse file to data type.
        :param str file_type: File type.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `BinaryIO` result
        """

        if not engine:
            raise ValueError('engine must be provided')
        if not parse_file:
            raise ValueError('parse_file must be provided')
        if not file_type:
            raise ValueError('file_type must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='parse_csv',
        )
        headers.update(sdk_headers)

        params = {
            'engine': engine,
        }

        form_data = []
        form_data.append(('parse_file', (None, parse_file, 'text/plain')))
        form_data.append(('file_type', (None, file_type, 'text/plain')))

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = '*/*'

        url = '/parse/csv'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            params=params,
            files=form_data,
        )

        response = self.send(request, **kwargs)
        return response

    def uplaod_csv(
        self,
        engine: str,
        catalog: str,
        schema: str,
        table_name: str,
        ingestion_job_name: str,
        scheduled: str,
        created_by: str,
        target_table: str,
        headers_: str,
        csv: str,
        *,
        auth_instance_id: str = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Upload CSV for table creation.

        When creating a table, upload a CSV file.

        :param str engine: Presto engine name.
        :param str catalog: Catalog name.
        :param str schema: Schema name.
        :param str table_name: table name.
        :param str ingestion_job_name: ingestion job name.
        :param str scheduled: Scheduled.
        :param str created_by: Created by.
        :param str target_table: Target table.
        :param str headers_: Headers.
        :param str csv: csv.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `BinaryIO` result
        """

        if not engine:
            raise ValueError('engine must be provided')
        if not catalog:
            raise ValueError('catalog must be provided')
        if not schema:
            raise ValueError('schema must be provided')
        if not table_name:
            raise ValueError('table_name must be provided')
        if not ingestion_job_name:
            raise ValueError('ingestion_job_name must be provided')
        if not scheduled:
            raise ValueError('scheduled must be provided')
        if not created_by:
            raise ValueError('created_by must be provided')
        if not target_table:
            raise ValueError('target_table must be provided')
        if not headers_:
            raise ValueError('headers_ must be provided')
        if not csv:
            raise ValueError('csv must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V1',
            operation_id='uplaod_csv',
        )
        headers.update(sdk_headers)

        params = {
            'engine': engine,
        }

        form_data = []
        form_data.append(('catalog', (None, catalog, 'text/plain')))
        form_data.append(('schema', (None, schema, 'text/plain')))
        form_data.append(('tableName', (None, table_name, 'text/plain')))
        form_data.append(('ingestionJobName', (None, ingestion_job_name, 'text/plain')))
        form_data.append(('scheduled', (None, scheduled, 'text/plain')))
        form_data.append(('created_by', (None, created_by, 'text/plain')))
        form_data.append(('targetTable', (None, target_table, 'text/plain')))
        form_data.append(('headers', (None, headers_, 'text/plain')))
        form_data.append(('csv', (None, csv, 'text/plain')))

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = '*/*'

        url = '/v2/upload/csv'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            params=params,
            files=form_data,
        )

        response = self.send(request, **kwargs)
        return response


##############################################################################
# Models
##############################################################################


class Bucket:
    """
    Bucket.

    :attr str created_by: Username who created the bucket.
    :attr str created_on: Creation date.
    :attr str description: Bucket Description.
    :attr str endpoint: Bucket endpoint.
    :attr str managed_by: Managed by.
    :attr str state: Mark bucket active or inactive.
    :attr List[str] tags: Tags.
    :attr List[str] associated_catalogs: Associated catalogs.
    :attr str bucket_display_name: (optional) Bucket Display Name.
    :attr str bucket_id: (optional) Bucket ID auto generated during bucket
          registration.
    :attr str bucket_name: Actual bucket name.
    :attr str bucket_type: Bucket Type.
    :attr List[str] actions: (optional) Actions.
    """

    def __init__(
        self,
        created_by: str,
        created_on: str,
        description: str,
        endpoint: str,
        managed_by: str,
        state: str,
        tags: List[str],
        associated_catalogs: List[str],
        bucket_name: str,
        bucket_type: str,
        *,
        bucket_display_name: str = None,
        bucket_id: str = None,
        actions: List[str] = None,
    ) -> None:
        """
        Initialize a Bucket object.

        :param str created_by: Username who created the bucket.
        :param str created_on: Creation date.
        :param str description: Bucket Description.
        :param str endpoint: Bucket endpoint.
        :param str managed_by: Managed by.
        :param str state: Mark bucket active or inactive.
        :param List[str] tags: Tags.
        :param List[str] associated_catalogs: Associated catalogs.
        :param str bucket_name: Actual bucket name.
        :param str bucket_type: Bucket Type.
        :param str bucket_display_name: (optional) Bucket Display Name.
        :param str bucket_id: (optional) Bucket ID auto generated during bucket
               registration.
        :param List[str] actions: (optional) Actions.
        """
        self.created_by = created_by
        self.created_on = created_on
        self.description = description
        self.endpoint = endpoint
        self.managed_by = managed_by
        self.state = state
        self.tags = tags
        self.associated_catalogs = associated_catalogs
        self.bucket_display_name = bucket_display_name
        self.bucket_id = bucket_id
        self.bucket_name = bucket_name
        self.bucket_type = bucket_type
        self.actions = actions

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'Bucket':
        """Initialize a Bucket object from a json dictionary."""
        args = {}
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        else:
            raise ValueError('Required property \'created_by\' not present in Bucket JSON')
        if 'created_on' in _dict:
            args['created_on'] = _dict.get('created_on')
        else:
            raise ValueError('Required property \'created_on\' not present in Bucket JSON')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        else:
            raise ValueError('Required property \'description\' not present in Bucket JSON')
        if 'endpoint' in _dict:
            args['endpoint'] = _dict.get('endpoint')
        else:
            raise ValueError('Required property \'endpoint\' not present in Bucket JSON')
        if 'managed_by' in _dict:
            args['managed_by'] = _dict.get('managed_by')
        else:
            raise ValueError('Required property \'managed_by\' not present in Bucket JSON')
        if 'state' in _dict:
            args['state'] = _dict.get('state')
        else:
            raise ValueError('Required property \'state\' not present in Bucket JSON')
        if 'tags' in _dict:
            args['tags'] = _dict.get('tags')
        else:
            raise ValueError('Required property \'tags\' not present in Bucket JSON')
        if 'associated_catalogs' in _dict:
            args['associated_catalogs'] = _dict.get('associated_catalogs')
        else:
            raise ValueError('Required property \'associated_catalogs\' not present in Bucket JSON')
        if 'bucket_display_name' in _dict:
            args['bucket_display_name'] = _dict.get('bucket_display_name')
        if 'bucket_id' in _dict:
            args['bucket_id'] = _dict.get('bucket_id')
        if 'bucket_name' in _dict:
            args['bucket_name'] = _dict.get('bucket_name')
        else:
            raise ValueError('Required property \'bucket_name\' not present in Bucket JSON')
        if 'bucket_type' in _dict:
            args['bucket_type'] = _dict.get('bucket_type')
        else:
            raise ValueError('Required property \'bucket_type\' not present in Bucket JSON')
        if 'actions' in _dict:
            args['actions'] = _dict.get('actions')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a Bucket object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'created_by') and self.created_by is not None:
            _dict['created_by'] = self.created_by
        if hasattr(self, 'created_on') and self.created_on is not None:
            _dict['created_on'] = self.created_on
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'endpoint') and self.endpoint is not None:
            _dict['endpoint'] = self.endpoint
        if hasattr(self, 'managed_by') and self.managed_by is not None:
            _dict['managed_by'] = self.managed_by
        if hasattr(self, 'state') and self.state is not None:
            _dict['state'] = self.state
        if hasattr(self, 'tags') and self.tags is not None:
            _dict['tags'] = self.tags
        if hasattr(self, 'associated_catalogs') and self.associated_catalogs is not None:
            _dict['associated_catalogs'] = self.associated_catalogs
        if hasattr(self, 'bucket_display_name') and self.bucket_display_name is not None:
            _dict['bucket_display_name'] = self.bucket_display_name
        if hasattr(self, 'bucket_id') and self.bucket_id is not None:
            _dict['bucket_id'] = self.bucket_id
        if hasattr(self, 'bucket_name') and self.bucket_name is not None:
            _dict['bucket_name'] = self.bucket_name
        if hasattr(self, 'bucket_type') and self.bucket_type is not None:
            _dict['bucket_type'] = self.bucket_type
        if hasattr(self, 'actions') and self.actions is not None:
            _dict['actions'] = self.actions
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this Bucket object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'Bucket') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'Bucket') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class ManagedByEnum(str, Enum):
        """
        Managed by.
        """

        IBM = 'IBM'
        CUSTOMER = 'Customer'

    class StateEnum(str, Enum):
        """
        Mark bucket active or inactive.
        """

        ACTIVE = 'active'
        INACTIVE = 'inactive'

    class BucketTypeEnum(str, Enum):
        """
        Bucket Type.
        """

        AMAZON_S3 = 'amazon_s3'
        AWS_S3 = 'aws_s3'
        MINIO = 'minio'
        IBM_COS = 'ibm_cos'


class BucketDbConnGroupsMetadata:
    """
    BucketDbConnGroupsMetadata.

    :attr str group_id: The group id.
    :attr str permission: Eligible permission to the resource.
    """

    def __init__(
        self,
        group_id: str,
        permission: str,
    ) -> None:
        """
        Initialize a BucketDbConnGroupsMetadata object.

        :param str group_id: The group id.
        :param str permission: Eligible permission to the resource.
        """
        self.group_id = group_id
        self.permission = permission

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'BucketDbConnGroupsMetadata':
        """Initialize a BucketDbConnGroupsMetadata object from a json dictionary."""
        args = {}
        if 'group_id' in _dict:
            args['group_id'] = _dict.get('group_id')
        else:
            raise ValueError('Required property \'group_id\' not present in BucketDbConnGroupsMetadata JSON')
        if 'permission' in _dict:
            args['permission'] = _dict.get('permission')
        else:
            raise ValueError('Required property \'permission\' not present in BucketDbConnGroupsMetadata JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a BucketDbConnGroupsMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'group_id') and self.group_id is not None:
            _dict['group_id'] = self.group_id
        if hasattr(self, 'permission') and self.permission is not None:
            _dict['permission'] = self.permission
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this BucketDbConnGroupsMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'BucketDbConnGroupsMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'BucketDbConnGroupsMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class PermissionEnum(str, Enum):
        """
        Eligible permission to the resource.
        """

        CAN_ADMINISTER = 'can_administer'
        CAN_WRITE = 'can_write'
        CAN_READ = 'can_read'


class BucketDbConnUsersMetadata:
    """
    BucketDbConnUsersMetadata.

    :attr str user_name: The user name.
    :attr str permission: Eligible permission to the resource.
    """

    def __init__(
        self,
        user_name: str,
        permission: str,
    ) -> None:
        """
        Initialize a BucketDbConnUsersMetadata object.

        :param str user_name: The user name.
        :param str permission: Eligible permission to the resource.
        """
        self.user_name = user_name
        self.permission = permission

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'BucketDbConnUsersMetadata':
        """Initialize a BucketDbConnUsersMetadata object from a json dictionary."""
        args = {}
        if 'user_name' in _dict:
            args['user_name'] = _dict.get('user_name')
        else:
            raise ValueError('Required property \'user_name\' not present in BucketDbConnUsersMetadata JSON')
        if 'permission' in _dict:
            args['permission'] = _dict.get('permission')
        else:
            raise ValueError('Required property \'permission\' not present in BucketDbConnUsersMetadata JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a BucketDbConnUsersMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'user_name') and self.user_name is not None:
            _dict['user_name'] = self.user_name
        if hasattr(self, 'permission') and self.permission is not None:
            _dict['permission'] = self.permission
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this BucketDbConnUsersMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'BucketDbConnUsersMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'BucketDbConnUsersMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class PermissionEnum(str, Enum):
        """
        Eligible permission to the resource.
        """

        CAN_ADMINISTER = 'can_administer'
        CAN_WRITE = 'can_write'
        CAN_READ = 'can_read'


class BucketDetails:
    """
    Bucket Details.

    :attr str access_key: (optional) Access key ID, encrypted during bucket
          registration.
    :attr str bucket_name: Actual bucket name.
    :attr str endpoint: (optional) Cos endpoint.
    :attr str secret_key: (optional) Secret access key, encrypted during bucket
          registration.
    """

    def __init__(
        self,
        bucket_name: str,
        *,
        access_key: str = None,
        endpoint: str = None,
        secret_key: str = None,
    ) -> None:
        """
        Initialize a BucketDetails object.

        :param str bucket_name: Actual bucket name.
        :param str access_key: (optional) Access key ID, encrypted during bucket
               registration.
        :param str endpoint: (optional) Cos endpoint.
        :param str secret_key: (optional) Secret access key, encrypted during
               bucket registration.
        """
        self.access_key = access_key
        self.bucket_name = bucket_name
        self.endpoint = endpoint
        self.secret_key = secret_key

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'BucketDetails':
        """Initialize a BucketDetails object from a json dictionary."""
        args = {}
        if 'access_key' in _dict:
            args['access_key'] = _dict.get('access_key')
        if 'bucket_name' in _dict:
            args['bucket_name'] = _dict.get('bucket_name')
        else:
            raise ValueError('Required property \'bucket_name\' not present in BucketDetails JSON')
        if 'endpoint' in _dict:
            args['endpoint'] = _dict.get('endpoint')
        if 'secret_key' in _dict:
            args['secret_key'] = _dict.get('secret_key')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a BucketDetails object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'access_key') and self.access_key is not None:
            _dict['access_key'] = self.access_key
        if hasattr(self, 'bucket_name') and self.bucket_name is not None:
            _dict['bucket_name'] = self.bucket_name
        if hasattr(self, 'endpoint') and self.endpoint is not None:
            _dict['endpoint'] = self.endpoint
        if hasattr(self, 'secret_key') and self.secret_key is not None:
            _dict['secret_key'] = self.secret_key
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this BucketDetails object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'BucketDetails') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'BucketDetails') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class BucketPolicies:
    """
    BucketPolicies.

    :attr str policy_version: (optional) Policy version.
    :attr str policy_name: (optional) The policy name.
    """

    def __init__(
        self,
        *,
        policy_version: str = None,
        policy_name: str = None,
    ) -> None:
        """
        Initialize a BucketPolicies object.

        :param str policy_version: (optional) Policy version.
        :param str policy_name: (optional) The policy name.
        """
        self.policy_version = policy_version
        self.policy_name = policy_name

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'BucketPolicies':
        """Initialize a BucketPolicies object from a json dictionary."""
        args = {}
        if 'policy_version' in _dict:
            args['policy_version'] = _dict.get('policy_version')
        if 'policy_name' in _dict:
            args['policy_name'] = _dict.get('policy_name')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a BucketPolicies object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'policy_version') and self.policy_version is not None:
            _dict['policy_version'] = self.policy_version
        if hasattr(self, 'policy_name') and self.policy_name is not None:
            _dict['policy_name'] = self.policy_name
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this BucketPolicies object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'BucketPolicies') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'BucketPolicies') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CatalogGroupsMetadata:
    """
    CatalogGroupsMetadata.

    :attr str group_id: The group id.
    :attr str permission: Eligible permission to the resource.
    """

    def __init__(
        self,
        group_id: str,
        permission: str,
    ) -> None:
        """
        Initialize a CatalogGroupsMetadata object.

        :param str group_id: The group id.
        :param str permission: Eligible permission to the resource.
        """
        self.group_id = group_id
        self.permission = permission

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CatalogGroupsMetadata':
        """Initialize a CatalogGroupsMetadata object from a json dictionary."""
        args = {}
        if 'group_id' in _dict:
            args['group_id'] = _dict.get('group_id')
        else:
            raise ValueError('Required property \'group_id\' not present in CatalogGroupsMetadata JSON')
        if 'permission' in _dict:
            args['permission'] = _dict.get('permission')
        else:
            raise ValueError('Required property \'permission\' not present in CatalogGroupsMetadata JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CatalogGroupsMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'group_id') and self.group_id is not None:
            _dict['group_id'] = self.group_id
        if hasattr(self, 'permission') and self.permission is not None:
            _dict['permission'] = self.permission
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CatalogGroupsMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CatalogGroupsMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CatalogGroupsMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class PermissionEnum(str, Enum):
        """
        Eligible permission to the resource.
        """

        CAN_ADMINISTER = 'can_administer'
        CAN_USE = 'can_use'


class CatalogPolicies:
    """
    CatalogPolicies.

    :attr str policy_name: (optional) The policy name.
    :attr str policy_version: (optional) Policy version.
    """

    def __init__(
        self,
        *,
        policy_name: str = None,
        policy_version: str = None,
    ) -> None:
        """
        Initialize a CatalogPolicies object.

        :param str policy_name: (optional) The policy name.
        :param str policy_version: (optional) Policy version.
        """
        self.policy_name = policy_name
        self.policy_version = policy_version

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CatalogPolicies':
        """Initialize a CatalogPolicies object from a json dictionary."""
        args = {}
        if 'policy_name' in _dict:
            args['policy_name'] = _dict.get('policy_name')
        if 'policy_version' in _dict:
            args['policy_version'] = _dict.get('policy_version')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CatalogPolicies object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'policy_name') and self.policy_name is not None:
            _dict['policy_name'] = self.policy_name
        if hasattr(self, 'policy_version') and self.policy_version is not None:
            _dict['policy_version'] = self.policy_version
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CatalogPolicies object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CatalogPolicies') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CatalogPolicies') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CatalogUsersMetadata:
    """
    CatalogUsersMetadata.

    :attr str permission: Eligible permission to the resource.
    :attr str user_name: The user name.
    """

    def __init__(
        self,
        permission: str,
        user_name: str,
    ) -> None:
        """
        Initialize a CatalogUsersMetadata object.

        :param str permission: Eligible permission to the resource.
        :param str user_name: The user name.
        """
        self.permission = permission
        self.user_name = user_name

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CatalogUsersMetadata':
        """Initialize a CatalogUsersMetadata object from a json dictionary."""
        args = {}
        if 'permission' in _dict:
            args['permission'] = _dict.get('permission')
        else:
            raise ValueError('Required property \'permission\' not present in CatalogUsersMetadata JSON')
        if 'user_name' in _dict:
            args['user_name'] = _dict.get('user_name')
        else:
            raise ValueError('Required property \'user_name\' not present in CatalogUsersMetadata JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CatalogUsersMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'permission') and self.permission is not None:
            _dict['permission'] = self.permission
        if hasattr(self, 'user_name') and self.user_name is not None:
            _dict['user_name'] = self.user_name
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CatalogUsersMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CatalogUsersMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CatalogUsersMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class PermissionEnum(str, Enum):
        """
        Eligible permission to the resource.
        """

        CAN_ADMINISTER = 'can_administer'
        CAN_USE = 'can_use'


class CreateDataPolicyCreatedBody:
    """
    Create data policy success.

    :attr CreateDataPolicySchema data_policy: create data policy.
    :attr DataPolicyMetadata metadata:
    :attr SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        data_policy: 'CreateDataPolicySchema',
        metadata: 'DataPolicyMetadata',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a CreateDataPolicyCreatedBody object.

        :param CreateDataPolicySchema data_policy: create data policy.
        :param DataPolicyMetadata metadata:
        :param SuccessResponse response: Response of success.
        """
        self.data_policy = data_policy
        self.metadata = metadata
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CreateDataPolicyCreatedBody':
        """Initialize a CreateDataPolicyCreatedBody object from a json dictionary."""
        args = {}
        if 'data_policy' in _dict:
            args['data_policy'] = CreateDataPolicySchema.from_dict(_dict.get('data_policy'))
        else:
            raise ValueError('Required property \'data_policy\' not present in CreateDataPolicyCreatedBody JSON')
        if 'metadata' in _dict:
            args['metadata'] = DataPolicyMetadata.from_dict(_dict.get('metadata'))
        else:
            raise ValueError('Required property \'metadata\' not present in CreateDataPolicyCreatedBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in CreateDataPolicyCreatedBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateDataPolicyCreatedBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'data_policy') and self.data_policy is not None:
            if isinstance(self.data_policy, dict):
                _dict['data_policy'] = self.data_policy
            else:
                _dict['data_policy'] = self.data_policy.to_dict()
        if hasattr(self, 'metadata') and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict['metadata'] = self.metadata
            else:
                _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'response') and self.response is not None:
            if isinstance(self.response, dict):
                _dict['response'] = self.response
            else:
                _dict['response'] = self.response.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CreateDataPolicyCreatedBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CreateDataPolicyCreatedBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CreateDataPolicyCreatedBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CreateDataPolicySchema:
    """
    create data policy.

    :attr str catalog_name: catalog name.
    :attr str data_artifact: data artifact.
    :attr str description: (optional) a more detailed description of the policy.
    :attr str policy_name: the displayed name for data policy.
    :attr List[Rule] rules: rules.
    :attr str status: (optional) data policy status.
    """

    def __init__(
        self,
        catalog_name: str,
        data_artifact: str,
        policy_name: str,
        rules: List['Rule'],
        *,
        description: str = None,
        status: str = None,
    ) -> None:
        """
        Initialize a CreateDataPolicySchema object.

        :param str catalog_name: catalog name.
        :param str data_artifact: data artifact.
        :param str policy_name: the displayed name for data policy.
        :param List[Rule] rules: rules.
        :param str description: (optional) a more detailed description of the
               policy.
        :param str status: (optional) data policy status.
        """
        self.catalog_name = catalog_name
        self.data_artifact = data_artifact
        self.description = description
        self.policy_name = policy_name
        self.rules = rules
        self.status = status

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CreateDataPolicySchema':
        """Initialize a CreateDataPolicySchema object from a json dictionary."""
        args = {}
        if 'catalog_name' in _dict:
            args['catalog_name'] = _dict.get('catalog_name')
        else:
            raise ValueError('Required property \'catalog_name\' not present in CreateDataPolicySchema JSON')
        if 'data_artifact' in _dict:
            args['data_artifact'] = _dict.get('data_artifact')
        else:
            raise ValueError('Required property \'data_artifact\' not present in CreateDataPolicySchema JSON')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'policy_name' in _dict:
            args['policy_name'] = _dict.get('policy_name')
        else:
            raise ValueError('Required property \'policy_name\' not present in CreateDataPolicySchema JSON')
        if 'rules' in _dict:
            args['rules'] = [Rule.from_dict(v) for v in _dict.get('rules')]
        else:
            raise ValueError('Required property \'rules\' not present in CreateDataPolicySchema JSON')
        if 'status' in _dict:
            args['status'] = _dict.get('status')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateDataPolicySchema object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'catalog_name') and self.catalog_name is not None:
            _dict['catalog_name'] = self.catalog_name
        if hasattr(self, 'data_artifact') and self.data_artifact is not None:
            _dict['data_artifact'] = self.data_artifact
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'policy_name') and self.policy_name is not None:
            _dict['policy_name'] = self.policy_name
        if hasattr(self, 'rules') and self.rules is not None:
            rules_list = []
            for v in self.rules:
                if isinstance(v, dict):
                    rules_list.append(v)
                else:
                    rules_list.append(v.to_dict())
            _dict['rules'] = rules_list
        if hasattr(self, 'status') and self.status is not None:
            _dict['status'] = self.status
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CreateDataPolicySchema object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CreateDataPolicySchema') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CreateDataPolicySchema') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class StatusEnum(str, Enum):
        """
        data policy status.
        """

        ACTIVE = 'active'
        INACTIVE = 'inactive'


class DataPolicies:
    """
    DataPolicies.

    :attr str associate_catalog: (optional) Associate catalog.
    :attr str policy_name: (optional) For resource policy, it's resource name like
          engin1. And for data policy it's policy name.
    :attr str policy_version: (optional) Policy version.
    """

    def __init__(
        self,
        *,
        associate_catalog: str = None,
        policy_name: str = None,
        policy_version: str = None,
    ) -> None:
        """
        Initialize a DataPolicies object.

        :param str associate_catalog: (optional) Associate catalog.
        :param str policy_name: (optional) For resource policy, it's resource name
               like engin1. And for data policy it's policy name.
        :param str policy_version: (optional) Policy version.
        """
        self.associate_catalog = associate_catalog
        self.policy_name = policy_name
        self.policy_version = policy_version

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'DataPolicies':
        """Initialize a DataPolicies object from a json dictionary."""
        args = {}
        if 'associate_catalog' in _dict:
            args['associate_catalog'] = _dict.get('associate_catalog')
        if 'policy_name' in _dict:
            args['policy_name'] = _dict.get('policy_name')
        if 'policy_version' in _dict:
            args['policy_version'] = _dict.get('policy_version')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a DataPolicies object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'associate_catalog') and self.associate_catalog is not None:
            _dict['associate_catalog'] = self.associate_catalog
        if hasattr(self, 'policy_name') and self.policy_name is not None:
            _dict['policy_name'] = self.policy_name
        if hasattr(self, 'policy_version') and self.policy_version is not None:
            _dict['policy_version'] = self.policy_version
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this DataPolicies object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'DataPolicies') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'DataPolicies') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class DataPolicyMetadata:
    """
    DataPolicyMetadata.

    :attr str creator: (optional) an identifier for the creator of the policy.
    :attr str description: (optional) a more detailed description of the rule.
    :attr str modifier: (optional) an identifier for the last modifier of the
          policy.
    :attr str pid: (optional) an unique identifier for the policy.
    :attr str policy_name: (optional) policy name.
    :attr str updated_at: (optional) time when the policy was last updated.
    :attr str version: (optional) data policy version.
    :attr str created_at: (optional) time when the policy was created.
    """

    def __init__(
        self,
        *,
        creator: str = None,
        description: str = None,
        modifier: str = None,
        pid: str = None,
        policy_name: str = None,
        updated_at: str = None,
        version: str = None,
        created_at: str = None,
    ) -> None:
        """
        Initialize a DataPolicyMetadata object.

        :param str creator: (optional) an identifier for the creator of the policy.
        :param str description: (optional) a more detailed description of the rule.
        :param str modifier: (optional) an identifier for the last modifier of the
               policy.
        :param str pid: (optional) an unique identifier for the policy.
        :param str policy_name: (optional) policy name.
        :param str updated_at: (optional) time when the policy was last updated.
        :param str version: (optional) data policy version.
        :param str created_at: (optional) time when the policy was created.
        """
        self.creator = creator
        self.description = description
        self.modifier = modifier
        self.pid = pid
        self.policy_name = policy_name
        self.updated_at = updated_at
        self.version = version
        self.created_at = created_at

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'DataPolicyMetadata':
        """Initialize a DataPolicyMetadata object from a json dictionary."""
        args = {}
        if 'creator' in _dict:
            args['creator'] = _dict.get('creator')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'modifier' in _dict:
            args['modifier'] = _dict.get('modifier')
        if 'pid' in _dict:
            args['pid'] = _dict.get('pid')
        if 'policy_name' in _dict:
            args['policy_name'] = _dict.get('policy_name')
        if 'updated_at' in _dict:
            args['updated_at'] = _dict.get('updated_at')
        if 'version' in _dict:
            args['version'] = _dict.get('version')
        if 'created_at' in _dict:
            args['created_at'] = _dict.get('created_at')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a DataPolicyMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'creator') and self.creator is not None:
            _dict['creator'] = self.creator
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'modifier') and self.modifier is not None:
            _dict['modifier'] = self.modifier
        if hasattr(self, 'pid') and self.pid is not None:
            _dict['pid'] = self.pid
        if hasattr(self, 'policy_name') and self.policy_name is not None:
            _dict['policy_name'] = self.policy_name
        if hasattr(self, 'updated_at') and self.updated_at is not None:
            _dict['updated_at'] = self.updated_at
        if hasattr(self, 'version') and self.version is not None:
            _dict['version'] = self.version
        if hasattr(self, 'created_at') and self.created_at is not None:
            _dict['created_at'] = self.created_at
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this DataPolicyMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'DataPolicyMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'DataPolicyMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class DbConnPolicies:
    """
    DbConnPolicies.

    :attr str policy_name: (optional) The policy name.
    :attr str policy_version: (optional) Policy version.
    """

    def __init__(
        self,
        *,
        policy_name: str = None,
        policy_version: str = None,
    ) -> None:
        """
        Initialize a DbConnPolicies object.

        :param str policy_name: (optional) The policy name.
        :param str policy_version: (optional) Policy version.
        """
        self.policy_name = policy_name
        self.policy_version = policy_version

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'DbConnPolicies':
        """Initialize a DbConnPolicies object from a json dictionary."""
        args = {}
        if 'policy_name' in _dict:
            args['policy_name'] = _dict.get('policy_name')
        if 'policy_version' in _dict:
            args['policy_version'] = _dict.get('policy_version')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a DbConnPolicies object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'policy_name') and self.policy_name is not None:
            _dict['policy_name'] = self.policy_name
        if hasattr(self, 'policy_version') and self.policy_version is not None:
            _dict['policy_version'] = self.policy_version
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this DbConnPolicies object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'DbConnPolicies') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'DbConnPolicies') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class DefaultPolicySchema:
    """
    AMS default schema.

    :attr List[GroupingPolicyMetadata] grouping_policies: (optional) default
          grouping policies.
    :attr str model: (optional) casbin model.
    :attr List[PolicyMetadata] policies: (optional) default policies.
    """

    def __init__(
        self,
        *,
        grouping_policies: List['GroupingPolicyMetadata'] = None,
        model: str = None,
        policies: List['PolicyMetadata'] = None,
    ) -> None:
        """
        Initialize a DefaultPolicySchema object.

        :param List[GroupingPolicyMetadata] grouping_policies: (optional) default
               grouping policies.
        :param str model: (optional) casbin model.
        :param List[PolicyMetadata] policies: (optional) default policies.
        """
        self.grouping_policies = grouping_policies
        self.model = model
        self.policies = policies

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'DefaultPolicySchema':
        """Initialize a DefaultPolicySchema object from a json dictionary."""
        args = {}
        if 'grouping_policies' in _dict:
            args['grouping_policies'] = [GroupingPolicyMetadata.from_dict(v) for v in _dict.get('grouping_policies')]
        if 'model' in _dict:
            args['model'] = _dict.get('model')
        if 'policies' in _dict:
            args['policies'] = [PolicyMetadata.from_dict(v) for v in _dict.get('policies')]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a DefaultPolicySchema object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'grouping_policies') and self.grouping_policies is not None:
            grouping_policies_list = []
            for v in self.grouping_policies:
                if isinstance(v, dict):
                    grouping_policies_list.append(v)
                else:
                    grouping_policies_list.append(v.to_dict())
            _dict['grouping_policies'] = grouping_policies_list
        if hasattr(self, 'model') and self.model is not None:
            _dict['model'] = self.model
        if hasattr(self, 'policies') and self.policies is not None:
            policies_list = []
            for v in self.policies:
                if isinstance(v, dict):
                    policies_list.append(v)
                else:
                    policies_list.append(v.to_dict())
            _dict['policies'] = policies_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this DefaultPolicySchema object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'DefaultPolicySchema') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'DefaultPolicySchema') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class DeleteTableBodyDeleteTablesItems:
    """
    Delete tables items.

    :attr str catalog_name: (optional) Catalog name.
    :attr str schema_name: (optional) Schema name.
    :attr str table_name: (optional) Table name.
    """

    def __init__(
        self,
        *,
        catalog_name: str = None,
        schema_name: str = None,
        table_name: str = None,
    ) -> None:
        """
        Initialize a DeleteTableBodyDeleteTablesItems object.

        :param str catalog_name: (optional) Catalog name.
        :param str schema_name: (optional) Schema name.
        :param str table_name: (optional) Table name.
        """
        self.catalog_name = catalog_name
        self.schema_name = schema_name
        self.table_name = table_name

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'DeleteTableBodyDeleteTablesItems':
        """Initialize a DeleteTableBodyDeleteTablesItems object from a json dictionary."""
        args = {}
        if 'catalog_name' in _dict:
            args['catalog_name'] = _dict.get('catalog_name')
        if 'schema_name' in _dict:
            args['schema_name'] = _dict.get('schema_name')
        if 'table_name' in _dict:
            args['table_name'] = _dict.get('table_name')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a DeleteTableBodyDeleteTablesItems object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'catalog_name') and self.catalog_name is not None:
            _dict['catalog_name'] = self.catalog_name
        if hasattr(self, 'schema_name') and self.schema_name is not None:
            _dict['schema_name'] = self.schema_name
        if hasattr(self, 'table_name') and self.table_name is not None:
            _dict['table_name'] = self.table_name
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this DeleteTableBodyDeleteTablesItems object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'DeleteTableBodyDeleteTablesItems') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'DeleteTableBodyDeleteTablesItems') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class EngineDetail:
    """
    EngineDetail.

    :attr str group_id: (optional) Group ID.
    :attr str region: (optional) Region - place holder.
    :attr str size_config: (optional) Size config.
    :attr int created_on: (optional) Created time in epoch format.
    :attr str engine_display_name: (optional) Engine display name.
    :attr str origin: (optional) Origin - place holder.
    :attr int port: (optional) Engine port.
    :attr str type: (optional) Type like presto, netezza,..
    :attr str version: (optional) Version of the engine.
    :attr NodeDescription worker: (optional) NodeDescription.
    :attr List[str] actions: (optional) Actions.
    :attr List[str] associated_catalogs: (optional) Associated catalogs.
    :attr str status: (optional) Engine status.
    :attr List[str] tags: (optional) Tags.
    :attr NodeDescription coordinator: (optional) NodeDescription.
    :attr str created_by: (optional) Created user name.
    :attr str host_name: (optional) Engine host name.
    :attr int status_code: Engine status code.
    :attr str description: (optional) Engine description.
    :attr str engine_id: (optional) Engine programmatic name.
    """

    def __init__(
        self,
        status_code: int,
        *,
        group_id: str = None,
        region: str = None,
        size_config: str = None,
        created_on: int = None,
        engine_display_name: str = None,
        origin: str = None,
        port: int = None,
        type: str = None,
        version: str = None,
        worker: 'NodeDescription' = None,
        actions: List[str] = None,
        associated_catalogs: List[str] = None,
        status: str = None,
        tags: List[str] = None,
        coordinator: 'NodeDescription' = None,
        created_by: str = None,
        host_name: str = None,
        description: str = None,
        engine_id: str = None,
    ) -> None:
        """
        Initialize a EngineDetail object.

        :param int status_code: Engine status code.
        :param str group_id: (optional) Group ID.
        :param str region: (optional) Region - place holder.
        :param str size_config: (optional) Size config.
        :param int created_on: (optional) Created time in epoch format.
        :param str engine_display_name: (optional) Engine display name.
        :param str origin: (optional) Origin - place holder.
        :param int port: (optional) Engine port.
        :param str type: (optional) Type like presto, netezza,..
        :param str version: (optional) Version of the engine.
        :param NodeDescription worker: (optional) NodeDescription.
        :param List[str] actions: (optional) Actions.
        :param List[str] associated_catalogs: (optional) Associated catalogs.
        :param str status: (optional) Engine status.
        :param List[str] tags: (optional) Tags.
        :param NodeDescription coordinator: (optional) NodeDescription.
        :param str created_by: (optional) Created user name.
        :param str host_name: (optional) Engine host name.
        :param str description: (optional) Engine description.
        :param str engine_id: (optional) Engine programmatic name.
        """
        self.group_id = group_id
        self.region = region
        self.size_config = size_config
        self.created_on = created_on
        self.engine_display_name = engine_display_name
        self.origin = origin
        self.port = port
        self.type = type
        self.version = version
        self.worker = worker
        self.actions = actions
        self.associated_catalogs = associated_catalogs
        self.status = status
        self.tags = tags
        self.coordinator = coordinator
        self.created_by = created_by
        self.host_name = host_name
        self.status_code = status_code
        self.description = description
        self.engine_id = engine_id

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'EngineDetail':
        """Initialize a EngineDetail object from a json dictionary."""
        args = {}
        if 'group_id' in _dict:
            args['group_id'] = _dict.get('group_id')
        if 'region' in _dict:
            args['region'] = _dict.get('region')
        if 'size_config' in _dict:
            args['size_config'] = _dict.get('size_config')
        if 'created_on' in _dict:
            args['created_on'] = _dict.get('created_on')
        if 'engine_display_name' in _dict:
            args['engine_display_name'] = _dict.get('engine_display_name')
        if 'origin' in _dict:
            args['origin'] = _dict.get('origin')
        if 'port' in _dict:
            args['port'] = _dict.get('port')
        if 'type' in _dict:
            args['type'] = _dict.get('type')
        if 'version' in _dict:
            args['version'] = _dict.get('version')
        if 'worker' in _dict:
            args['worker'] = NodeDescription.from_dict(_dict.get('worker'))
        if 'actions' in _dict:
            args['actions'] = _dict.get('actions')
        if 'associated_catalogs' in _dict:
            args['associated_catalogs'] = _dict.get('associated_catalogs')
        if 'status' in _dict:
            args['status'] = _dict.get('status')
        if 'tags' in _dict:
            args['tags'] = _dict.get('tags')
        if 'coordinator' in _dict:
            args['coordinator'] = NodeDescription.from_dict(_dict.get('coordinator'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'host_name' in _dict:
            args['host_name'] = _dict.get('host_name')
        if 'status_code' in _dict:
            args['status_code'] = _dict.get('status_code')
        else:
            raise ValueError('Required property \'status_code\' not present in EngineDetail JSON')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'engine_id' in _dict:
            args['engine_id'] = _dict.get('engine_id')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a EngineDetail object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'group_id') and self.group_id is not None:
            _dict['group_id'] = self.group_id
        if hasattr(self, 'region') and self.region is not None:
            _dict['region'] = self.region
        if hasattr(self, 'size_config') and self.size_config is not None:
            _dict['size_config'] = self.size_config
        if hasattr(self, 'created_on') and self.created_on is not None:
            _dict['created_on'] = self.created_on
        if hasattr(self, 'engine_display_name') and self.engine_display_name is not None:
            _dict['engine_display_name'] = self.engine_display_name
        if hasattr(self, 'origin') and self.origin is not None:
            _dict['origin'] = self.origin
        if hasattr(self, 'port') and self.port is not None:
            _dict['port'] = self.port
        if hasattr(self, 'type') and self.type is not None:
            _dict['type'] = self.type
        if hasattr(self, 'version') and self.version is not None:
            _dict['version'] = self.version
        if hasattr(self, 'worker') and self.worker is not None:
            if isinstance(self.worker, dict):
                _dict['worker'] = self.worker
            else:
                _dict['worker'] = self.worker.to_dict()
        if hasattr(self, 'actions') and self.actions is not None:
            _dict['actions'] = self.actions
        if hasattr(self, 'associated_catalogs') and self.associated_catalogs is not None:
            _dict['associated_catalogs'] = self.associated_catalogs
        if hasattr(self, 'status') and self.status is not None:
            _dict['status'] = self.status
        if hasattr(self, 'tags') and self.tags is not None:
            _dict['tags'] = self.tags
        if hasattr(self, 'coordinator') and self.coordinator is not None:
            if isinstance(self.coordinator, dict):
                _dict['coordinator'] = self.coordinator
            else:
                _dict['coordinator'] = self.coordinator.to_dict()
        if hasattr(self, 'created_by') and self.created_by is not None:
            _dict['created_by'] = self.created_by
        if hasattr(self, 'host_name') and self.host_name is not None:
            _dict['host_name'] = self.host_name
        if hasattr(self, 'status_code') and self.status_code is not None:
            _dict['status_code'] = self.status_code
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'engine_id') and self.engine_id is not None:
            _dict['engine_id'] = self.engine_id
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this EngineDetail object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'EngineDetail') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'EngineDetail') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class EngineDetailsBody:
    """
    Node details.

    :attr NodeDescriptionBody worker: (optional) Node details.
    :attr NodeDescriptionBody coordinator: (optional) Node details.
    :attr str size_config: (optional) Size config.
    """

    def __init__(
        self,
        *,
        worker: 'NodeDescriptionBody' = None,
        coordinator: 'NodeDescriptionBody' = None,
        size_config: str = None,
    ) -> None:
        """
        Initialize a EngineDetailsBody object.

        :param NodeDescriptionBody worker: (optional) Node details.
        :param NodeDescriptionBody coordinator: (optional) Node details.
        :param str size_config: (optional) Size config.
        """
        self.worker = worker
        self.coordinator = coordinator
        self.size_config = size_config

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'EngineDetailsBody':
        """Initialize a EngineDetailsBody object from a json dictionary."""
        args = {}
        if 'worker' in _dict:
            args['worker'] = NodeDescriptionBody.from_dict(_dict.get('worker'))
        if 'coordinator' in _dict:
            args['coordinator'] = NodeDescriptionBody.from_dict(_dict.get('coordinator'))
        if 'size_config' in _dict:
            args['size_config'] = _dict.get('size_config')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a EngineDetailsBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'worker') and self.worker is not None:
            if isinstance(self.worker, dict):
                _dict['worker'] = self.worker
            else:
                _dict['worker'] = self.worker.to_dict()
        if hasattr(self, 'coordinator') and self.coordinator is not None:
            if isinstance(self.coordinator, dict):
                _dict['coordinator'] = self.coordinator
            else:
                _dict['coordinator'] = self.coordinator.to_dict()
        if hasattr(self, 'size_config') and self.size_config is not None:
            _dict['size_config'] = self.size_config
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this EngineDetailsBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'EngineDetailsBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'EngineDetailsBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class SizeConfigEnum(str, Enum):
        """
        Size config.
        """

        STARTER = 'starter'
        STORAGE_OPTIMIZED = 'storage_optimized'
        COMPUTE_OPTIMIZED = 'compute_optimized'
        SMALL = 'small'
        MEDIUM = 'medium'
        LARGE = 'large'
        CUSTOM = 'custom'


class EngineGroupsMetadata:
    """
    EngineGroupsMetadata.

    :attr str group_id: The group id.
    :attr str permission: Eligible permission to the resource.
    """

    def __init__(
        self,
        group_id: str,
        permission: str,
    ) -> None:
        """
        Initialize a EngineGroupsMetadata object.

        :param str group_id: The group id.
        :param str permission: Eligible permission to the resource.
        """
        self.group_id = group_id
        self.permission = permission

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'EngineGroupsMetadata':
        """Initialize a EngineGroupsMetadata object from a json dictionary."""
        args = {}
        if 'group_id' in _dict:
            args['group_id'] = _dict.get('group_id')
        else:
            raise ValueError('Required property \'group_id\' not present in EngineGroupsMetadata JSON')
        if 'permission' in _dict:
            args['permission'] = _dict.get('permission')
        else:
            raise ValueError('Required property \'permission\' not present in EngineGroupsMetadata JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a EngineGroupsMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'group_id') and self.group_id is not None:
            _dict['group_id'] = self.group_id
        if hasattr(self, 'permission') and self.permission is not None:
            _dict['permission'] = self.permission
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this EngineGroupsMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'EngineGroupsMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'EngineGroupsMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class PermissionEnum(str, Enum):
        """
        Eligible permission to the resource.
        """

        CAN_ADMINISTER = 'can_administer'
        CAN_MANAGE = 'can_manage'
        CAN_USE = 'can_use'


class EnginePolicies:
    """
    EnginePolicies.

    :attr str policy_name: (optional) The policy name.
    :attr str policy_version: (optional) Policy version.
    """

    def __init__(
        self,
        *,
        policy_name: str = None,
        policy_version: str = None,
    ) -> None:
        """
        Initialize a EnginePolicies object.

        :param str policy_name: (optional) The policy name.
        :param str policy_version: (optional) Policy version.
        """
        self.policy_name = policy_name
        self.policy_version = policy_version

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'EnginePolicies':
        """Initialize a EnginePolicies object from a json dictionary."""
        args = {}
        if 'policy_name' in _dict:
            args['policy_name'] = _dict.get('policy_name')
        if 'policy_version' in _dict:
            args['policy_version'] = _dict.get('policy_version')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a EnginePolicies object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'policy_name') and self.policy_name is not None:
            _dict['policy_name'] = self.policy_name
        if hasattr(self, 'policy_version') and self.policy_version is not None:
            _dict['policy_version'] = self.policy_version
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this EnginePolicies object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'EnginePolicies') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'EnginePolicies') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class EngineUsersMetadata:
    """
    EngineUsersMetadata.

    :attr str permission: Eligible permission to the resource.
    :attr str user_name: The user name.
    """

    def __init__(
        self,
        permission: str,
        user_name: str,
    ) -> None:
        """
        Initialize a EngineUsersMetadata object.

        :param str permission: Eligible permission to the resource.
        :param str user_name: The user name.
        """
        self.permission = permission
        self.user_name = user_name

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'EngineUsersMetadata':
        """Initialize a EngineUsersMetadata object from a json dictionary."""
        args = {}
        if 'permission' in _dict:
            args['permission'] = _dict.get('permission')
        else:
            raise ValueError('Required property \'permission\' not present in EngineUsersMetadata JSON')
        if 'user_name' in _dict:
            args['user_name'] = _dict.get('user_name')
        else:
            raise ValueError('Required property \'user_name\' not present in EngineUsersMetadata JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a EngineUsersMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'permission') and self.permission is not None:
            _dict['permission'] = self.permission
        if hasattr(self, 'user_name') and self.user_name is not None:
            _dict['user_name'] = self.user_name
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this EngineUsersMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'EngineUsersMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'EngineUsersMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class PermissionEnum(str, Enum):
        """
        Eligible permission to the resource.
        """

        CAN_ADMINISTER = 'can_administer'
        CAN_MANAGE = 'can_manage'
        CAN_USE = 'can_use'


class EvaluationResultSchema:
    """
    Evaluation result schema.

    :attr List[ResourceWithResult] resources: (optional) resource list.
    """

    def __init__(
        self,
        *,
        resources: List['ResourceWithResult'] = None,
    ) -> None:
        """
        Initialize a EvaluationResultSchema object.

        :param List[ResourceWithResult] resources: (optional) resource list.
        """
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'EvaluationResultSchema':
        """Initialize a EvaluationResultSchema object from a json dictionary."""
        args = {}
        if 'resources' in _dict:
            args['resources'] = [ResourceWithResult.from_dict(v) for v in _dict.get('resources')]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a EvaluationResultSchema object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'resources') and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict['resources'] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this EvaluationResultSchema object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'EvaluationResultSchema') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'EvaluationResultSchema') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ExplainAnalyzeStatementCreatedBody:
    """
    explainAnalyzeStatement OK.

    :attr SuccessResponse response: Response of success.
    :attr str result: explainAnalyzeStatement result.
    """

    def __init__(
        self,
        response: 'SuccessResponse',
        result: str,
    ) -> None:
        """
        Initialize a ExplainAnalyzeStatementCreatedBody object.

        :param SuccessResponse response: Response of success.
        :param str result: explainAnalyzeStatement result.
        """
        self.response = response
        self.result = result

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ExplainAnalyzeStatementCreatedBody':
        """Initialize a ExplainAnalyzeStatementCreatedBody object from a json dictionary."""
        args = {}
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in ExplainAnalyzeStatementCreatedBody JSON')
        if 'result' in _dict:
            args['result'] = _dict.get('result')
        else:
            raise ValueError('Required property \'result\' not present in ExplainAnalyzeStatementCreatedBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ExplainAnalyzeStatementCreatedBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'response') and self.response is not None:
            if isinstance(self.response, dict):
                _dict['response'] = self.response
            else:
                _dict['response'] = self.response.to_dict()
        if hasattr(self, 'result') and self.result is not None:
            _dict['result'] = self.result
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ExplainAnalyzeStatementCreatedBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ExplainAnalyzeStatementCreatedBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ExplainAnalyzeStatementCreatedBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ExplainStatementCreatedBody:
    """
    ExplainStatement OK.

    :attr SuccessResponse response: Response of success.
    :attr str result: Result.
    """

    def __init__(
        self,
        response: 'SuccessResponse',
        result: str,
    ) -> None:
        """
        Initialize a ExplainStatementCreatedBody object.

        :param SuccessResponse response: Response of success.
        :param str result: Result.
        """
        self.response = response
        self.result = result

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ExplainStatementCreatedBody':
        """Initialize a ExplainStatementCreatedBody object from a json dictionary."""
        args = {}
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in ExplainStatementCreatedBody JSON')
        if 'result' in _dict:
            args['result'] = _dict.get('result')
        else:
            raise ValueError('Required property \'result\' not present in ExplainStatementCreatedBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ExplainStatementCreatedBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'response') and self.response is not None:
            if isinstance(self.response, dict):
                _dict['response'] = self.response
            else:
                _dict['response'] = self.response.to_dict()
        if hasattr(self, 'result') and self.result is not None:
            _dict['result'] = self.result
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ExplainStatementCreatedBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ExplainStatementCreatedBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ExplainStatementCreatedBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetBucketObjectsOKBody:
    """
    GetBucketObjects OK.

    :attr List[str] objects: Bucket objects.
    :attr SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        objects: List[str],
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a GetBucketObjectsOKBody object.

        :param List[str] objects: Bucket objects.
        :param SuccessResponse response: Response of success.
        """
        self.objects = objects
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetBucketObjectsOKBody':
        """Initialize a GetBucketObjectsOKBody object from a json dictionary."""
        args = {}
        if 'objects' in _dict:
            args['objects'] = _dict.get('objects')
        else:
            raise ValueError('Required property \'objects\' not present in GetBucketObjectsOKBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in GetBucketObjectsOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetBucketObjectsOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'objects') and self.objects is not None:
            _dict['objects'] = self.objects
        if hasattr(self, 'response') and self.response is not None:
            if isinstance(self.response, dict):
                _dict['response'] = self.response
            else:
                _dict['response'] = self.response.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetBucketObjectsOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetBucketObjectsOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetBucketObjectsOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetBucketUsersSchema:
    """
    Get bucket users schema.

    :attr str bucket_id: The bucket id.
    :attr List[BucketDbConnGroupsMetadata] groups: (optional) The group list.
    :attr int total_count: Total number of users and groups.
    :attr List[BucketDbConnUsersMetadata] users: (optional) The user list.
    """

    def __init__(
        self,
        bucket_id: str,
        total_count: int,
        *,
        groups: List['BucketDbConnGroupsMetadata'] = None,
        users: List['BucketDbConnUsersMetadata'] = None,
    ) -> None:
        """
        Initialize a GetBucketUsersSchema object.

        :param str bucket_id: The bucket id.
        :param int total_count: Total number of users and groups.
        :param List[BucketDbConnGroupsMetadata] groups: (optional) The group list.
        :param List[BucketDbConnUsersMetadata] users: (optional) The user list.
        """
        self.bucket_id = bucket_id
        self.groups = groups
        self.total_count = total_count
        self.users = users

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetBucketUsersSchema':
        """Initialize a GetBucketUsersSchema object from a json dictionary."""
        args = {}
        if 'bucket_id' in _dict:
            args['bucket_id'] = _dict.get('bucket_id')
        else:
            raise ValueError('Required property \'bucket_id\' not present in GetBucketUsersSchema JSON')
        if 'groups' in _dict:
            args['groups'] = [BucketDbConnGroupsMetadata.from_dict(v) for v in _dict.get('groups')]
        if 'total_count' in _dict:
            args['total_count'] = _dict.get('total_count')
        else:
            raise ValueError('Required property \'total_count\' not present in GetBucketUsersSchema JSON')
        if 'users' in _dict:
            args['users'] = [BucketDbConnUsersMetadata.from_dict(v) for v in _dict.get('users')]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetBucketUsersSchema object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'bucket_id') and self.bucket_id is not None:
            _dict['bucket_id'] = self.bucket_id
        if hasattr(self, 'groups') and self.groups is not None:
            groups_list = []
            for v in self.groups:
                if isinstance(v, dict):
                    groups_list.append(v)
                else:
                    groups_list.append(v.to_dict())
            _dict['groups'] = groups_list
        if hasattr(self, 'total_count') and self.total_count is not None:
            _dict['total_count'] = self.total_count
        if hasattr(self, 'users') and self.users is not None:
            users_list = []
            for v in self.users:
                if isinstance(v, dict):
                    users_list.append(v)
                else:
                    users_list.append(v.to_dict())
            _dict['users'] = users_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetBucketUsersSchema object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetBucketUsersSchema') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetBucketUsersSchema') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetBucketsOKBody:
    """
    GetBuckets OK.

    :attr List[Bucket] buckets: Buckets.
    :attr SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        buckets: List['Bucket'],
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a GetBucketsOKBody object.

        :param List[Bucket] buckets: Buckets.
        :param SuccessResponse response: Response of success.
        """
        self.buckets = buckets
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetBucketsOKBody':
        """Initialize a GetBucketsOKBody object from a json dictionary."""
        args = {}
        if 'buckets' in _dict:
            args['buckets'] = [Bucket.from_dict(v) for v in _dict.get('buckets')]
        else:
            raise ValueError('Required property \'buckets\' not present in GetBucketsOKBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in GetBucketsOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetBucketsOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'buckets') and self.buckets is not None:
            buckets_list = []
            for v in self.buckets:
                if isinstance(v, dict):
                    buckets_list.append(v)
                else:
                    buckets_list.append(v.to_dict())
            _dict['buckets'] = buckets_list
        if hasattr(self, 'response') and self.response is not None:
            if isinstance(self.response, dict):
                _dict['response'] = self.response
            else:
                _dict['response'] = self.response.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetBucketsOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetBucketsOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetBucketsOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetCatalogUsersSchema:
    """
    Get catalog users schema.

    :attr int total_count: Total number of users and groups.
    :attr List[CatalogUsersMetadata] users: (optional) The user list.
    :attr str catalog_name: The catalog name.
    :attr List[CatalogGroupsMetadata] groups: (optional) The group list.
    """

    def __init__(
        self,
        total_count: int,
        catalog_name: str,
        *,
        users: List['CatalogUsersMetadata'] = None,
        groups: List['CatalogGroupsMetadata'] = None,
    ) -> None:
        """
        Initialize a GetCatalogUsersSchema object.

        :param int total_count: Total number of users and groups.
        :param str catalog_name: The catalog name.
        :param List[CatalogUsersMetadata] users: (optional) The user list.
        :param List[CatalogGroupsMetadata] groups: (optional) The group list.
        """
        self.total_count = total_count
        self.users = users
        self.catalog_name = catalog_name
        self.groups = groups

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetCatalogUsersSchema':
        """Initialize a GetCatalogUsersSchema object from a json dictionary."""
        args = {}
        if 'total_count' in _dict:
            args['total_count'] = _dict.get('total_count')
        else:
            raise ValueError('Required property \'total_count\' not present in GetCatalogUsersSchema JSON')
        if 'users' in _dict:
            args['users'] = [CatalogUsersMetadata.from_dict(v) for v in _dict.get('users')]
        if 'catalog_name' in _dict:
            args['catalog_name'] = _dict.get('catalog_name')
        else:
            raise ValueError('Required property \'catalog_name\' not present in GetCatalogUsersSchema JSON')
        if 'groups' in _dict:
            args['groups'] = [CatalogGroupsMetadata.from_dict(v) for v in _dict.get('groups')]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetCatalogUsersSchema object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'total_count') and self.total_count is not None:
            _dict['total_count'] = self.total_count
        if hasattr(self, 'users') and self.users is not None:
            users_list = []
            for v in self.users:
                if isinstance(v, dict):
                    users_list.append(v)
                else:
                    users_list.append(v.to_dict())
            _dict['users'] = users_list
        if hasattr(self, 'catalog_name') and self.catalog_name is not None:
            _dict['catalog_name'] = self.catalog_name
        if hasattr(self, 'groups') and self.groups is not None:
            groups_list = []
            for v in self.groups:
                if isinstance(v, dict):
                    groups_list.append(v)
                else:
                    groups_list.append(v.to_dict())
            _dict['groups'] = groups_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetCatalogUsersSchema object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetCatalogUsersSchema') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetCatalogUsersSchema') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetDbConnUsersSchema:
    """
    Get Db connection users schema.

    :attr List[BucketDbConnGroupsMetadata] groups: (optional) The group list.
    :attr int total_count: Total number of users and groups.
    :attr List[BucketDbConnUsersMetadata] users: (optional) The user list.
    :attr str database_id: The db connection id.
    """

    def __init__(
        self,
        total_count: int,
        database_id: str,
        *,
        groups: List['BucketDbConnGroupsMetadata'] = None,
        users: List['BucketDbConnUsersMetadata'] = None,
    ) -> None:
        """
        Initialize a GetDbConnUsersSchema object.

        :param int total_count: Total number of users and groups.
        :param str database_id: The db connection id.
        :param List[BucketDbConnGroupsMetadata] groups: (optional) The group list.
        :param List[BucketDbConnUsersMetadata] users: (optional) The user list.
        """
        self.groups = groups
        self.total_count = total_count
        self.users = users
        self.database_id = database_id

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetDbConnUsersSchema':
        """Initialize a GetDbConnUsersSchema object from a json dictionary."""
        args = {}
        if 'groups' in _dict:
            args['groups'] = [BucketDbConnGroupsMetadata.from_dict(v) for v in _dict.get('groups')]
        if 'total_count' in _dict:
            args['total_count'] = _dict.get('total_count')
        else:
            raise ValueError('Required property \'total_count\' not present in GetDbConnUsersSchema JSON')
        if 'users' in _dict:
            args['users'] = [BucketDbConnUsersMetadata.from_dict(v) for v in _dict.get('users')]
        if 'database_id' in _dict:
            args['database_id'] = _dict.get('database_id')
        else:
            raise ValueError('Required property \'database_id\' not present in GetDbConnUsersSchema JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetDbConnUsersSchema object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'groups') and self.groups is not None:
            groups_list = []
            for v in self.groups:
                if isinstance(v, dict):
                    groups_list.append(v)
                else:
                    groups_list.append(v.to_dict())
            _dict['groups'] = groups_list
        if hasattr(self, 'total_count') and self.total_count is not None:
            _dict['total_count'] = self.total_count
        if hasattr(self, 'users') and self.users is not None:
            users_list = []
            for v in self.users:
                if isinstance(v, dict):
                    users_list.append(v)
                else:
                    users_list.append(v.to_dict())
            _dict['users'] = users_list
        if hasattr(self, 'database_id') and self.database_id is not None:
            _dict['database_id'] = self.database_id
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetDbConnUsersSchema object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetDbConnUsersSchema') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetDbConnUsersSchema') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetEngineUsersSchema:
    """
    Get engine users schema.

    :attr str engine_id: The engine id.
    :attr List[EngineGroupsMetadata] groups: (optional) The group list.
    :attr int total_count: Total number of users and groups.
    :attr List[EngineUsersMetadata] users: (optional) The user list.
    """

    def __init__(
        self,
        engine_id: str,
        total_count: int,
        *,
        groups: List['EngineGroupsMetadata'] = None,
        users: List['EngineUsersMetadata'] = None,
    ) -> None:
        """
        Initialize a GetEngineUsersSchema object.

        :param str engine_id: The engine id.
        :param int total_count: Total number of users and groups.
        :param List[EngineGroupsMetadata] groups: (optional) The group list.
        :param List[EngineUsersMetadata] users: (optional) The user list.
        """
        self.engine_id = engine_id
        self.groups = groups
        self.total_count = total_count
        self.users = users

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetEngineUsersSchema':
        """Initialize a GetEngineUsersSchema object from a json dictionary."""
        args = {}
        if 'engine_id' in _dict:
            args['engine_id'] = _dict.get('engine_id')
        else:
            raise ValueError('Required property \'engine_id\' not present in GetEngineUsersSchema JSON')
        if 'groups' in _dict:
            args['groups'] = [EngineGroupsMetadata.from_dict(v) for v in _dict.get('groups')]
        if 'total_count' in _dict:
            args['total_count'] = _dict.get('total_count')
        else:
            raise ValueError('Required property \'total_count\' not present in GetEngineUsersSchema JSON')
        if 'users' in _dict:
            args['users'] = [EngineUsersMetadata.from_dict(v) for v in _dict.get('users')]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetEngineUsersSchema object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'engine_id') and self.engine_id is not None:
            _dict['engine_id'] = self.engine_id
        if hasattr(self, 'groups') and self.groups is not None:
            groups_list = []
            for v in self.groups:
                if isinstance(v, dict):
                    groups_list.append(v)
                else:
                    groups_list.append(v.to_dict())
            _dict['groups'] = groups_list
        if hasattr(self, 'total_count') and self.total_count is not None:
            _dict['total_count'] = self.total_count
        if hasattr(self, 'users') and self.users is not None:
            users_list = []
            for v in self.users:
                if isinstance(v, dict):
                    users_list.append(v)
                else:
                    users_list.append(v.to_dict())
            _dict['users'] = users_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetEngineUsersSchema object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetEngineUsersSchema') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetEngineUsersSchema') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetEnginesOKBody:
    """
    getEngines.

    :attr List[EngineDetail] engines:
    :attr SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        engines: List['EngineDetail'],
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a GetEnginesOKBody object.

        :param List[EngineDetail] engines:
        :param SuccessResponse response: Response of success.
        """
        self.engines = engines
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetEnginesOKBody':
        """Initialize a GetEnginesOKBody object from a json dictionary."""
        args = {}
        if 'engines' in _dict:
            args['engines'] = [EngineDetail.from_dict(v) for v in _dict.get('engines')]
        else:
            raise ValueError('Required property \'engines\' not present in GetEnginesOKBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in GetEnginesOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetEnginesOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'engines') and self.engines is not None:
            engines_list = []
            for v in self.engines:
                if isinstance(v, dict):
                    engines_list.append(v)
                else:
                    engines_list.append(v.to_dict())
            _dict['engines'] = engines_list
        if hasattr(self, 'response') and self.response is not None:
            if isinstance(self.response, dict):
                _dict['response'] = self.response
            else:
                _dict['response'] = self.response.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetEnginesOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetEnginesOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetEnginesOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetMetastoreUsersSchema:
    """
    Get metastore users schema.

    :attr List[GroupsMetadata] groups: (optional) The group list.
    :attr str metastore_name: The metastore name.
    :attr int total_count: Total number of users and groups.
    :attr List[UsersMetadata] users: (optional) The user list.
    """

    def __init__(
        self,
        metastore_name: str,
        total_count: int,
        *,
        groups: List['GroupsMetadata'] = None,
        users: List['UsersMetadata'] = None,
    ) -> None:
        """
        Initialize a GetMetastoreUsersSchema object.

        :param str metastore_name: The metastore name.
        :param int total_count: Total number of users and groups.
        :param List[GroupsMetadata] groups: (optional) The group list.
        :param List[UsersMetadata] users: (optional) The user list.
        """
        self.groups = groups
        self.metastore_name = metastore_name
        self.total_count = total_count
        self.users = users

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetMetastoreUsersSchema':
        """Initialize a GetMetastoreUsersSchema object from a json dictionary."""
        args = {}
        if 'groups' in _dict:
            args['groups'] = [GroupsMetadata.from_dict(v) for v in _dict.get('groups')]
        if 'metastore_name' in _dict:
            args['metastore_name'] = _dict.get('metastore_name')
        else:
            raise ValueError('Required property \'metastore_name\' not present in GetMetastoreUsersSchema JSON')
        if 'total_count' in _dict:
            args['total_count'] = _dict.get('total_count')
        else:
            raise ValueError('Required property \'total_count\' not present in GetMetastoreUsersSchema JSON')
        if 'users' in _dict:
            args['users'] = [UsersMetadata.from_dict(v) for v in _dict.get('users')]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetMetastoreUsersSchema object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'groups') and self.groups is not None:
            groups_list = []
            for v in self.groups:
                if isinstance(v, dict):
                    groups_list.append(v)
                else:
                    groups_list.append(v.to_dict())
            _dict['groups'] = groups_list
        if hasattr(self, 'metastore_name') and self.metastore_name is not None:
            _dict['metastore_name'] = self.metastore_name
        if hasattr(self, 'total_count') and self.total_count is not None:
            _dict['total_count'] = self.total_count
        if hasattr(self, 'users') and self.users is not None:
            users_list = []
            for v in self.users:
                if isinstance(v, dict):
                    users_list.append(v)
                else:
                    users_list.append(v.to_dict())
            _dict['users'] = users_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetMetastoreUsersSchema object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetMetastoreUsersSchema') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetMetastoreUsersSchema') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetMetastoresOKBody:
    """
    GetMetastores OK.

    :attr List[Metastore] catalogs: Metastores.
    :attr SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        catalogs: List['Metastore'],
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a GetMetastoresOKBody object.

        :param List[Metastore] catalogs: Metastores.
        :param SuccessResponse response: Response of success.
        """
        self.catalogs = catalogs
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetMetastoresOKBody':
        """Initialize a GetMetastoresOKBody object from a json dictionary."""
        args = {}
        if 'catalogs' in _dict:
            args['catalogs'] = [Metastore.from_dict(v) for v in _dict.get('catalogs')]
        else:
            raise ValueError('Required property \'catalogs\' not present in GetMetastoresOKBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in GetMetastoresOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetMetastoresOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'catalogs') and self.catalogs is not None:
            catalogs_list = []
            for v in self.catalogs:
                if isinstance(v, dict):
                    catalogs_list.append(v)
                else:
                    catalogs_list.append(v.to_dict())
            _dict['catalogs'] = catalogs_list
        if hasattr(self, 'response') and self.response is not None:
            if isinstance(self.response, dict):
                _dict['response'] = self.response
            else:
                _dict['response'] = self.response.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetMetastoresOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetMetastoresOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetMetastoresOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetQueriesOKBody:
    """
    GetQueries OK.

    :attr List[Query] queries: Queries.
    :attr SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        queries: List['Query'],
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a GetQueriesOKBody object.

        :param List[Query] queries: Queries.
        :param SuccessResponse response: Response of success.
        """
        self.queries = queries
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetQueriesOKBody':
        """Initialize a GetQueriesOKBody object from a json dictionary."""
        args = {}
        if 'queries' in _dict:
            args['queries'] = [Query.from_dict(v) for v in _dict.get('queries')]
        else:
            raise ValueError('Required property \'queries\' not present in GetQueriesOKBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in GetQueriesOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetQueriesOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'queries') and self.queries is not None:
            queries_list = []
            for v in self.queries:
                if isinstance(v, dict):
                    queries_list.append(v)
                else:
                    queries_list.append(v.to_dict())
            _dict['queries'] = queries_list
        if hasattr(self, 'response') and self.response is not None:
            if isinstance(self.response, dict):
                _dict['response'] = self.response
            else:
                _dict['response'] = self.response.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetQueriesOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetQueriesOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetQueriesOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetSchemasOKBody:
    """
    GetSchemas OK.

    :attr SuccessResponse response: Response of success.
    :attr List[str] schemas: Schemas.
    """

    def __init__(
        self,
        response: 'SuccessResponse',
        schemas: List[str],
    ) -> None:
        """
        Initialize a GetSchemasOKBody object.

        :param SuccessResponse response: Response of success.
        :param List[str] schemas: Schemas.
        """
        self.response = response
        self.schemas = schemas

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetSchemasOKBody':
        """Initialize a GetSchemasOKBody object from a json dictionary."""
        args = {}
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in GetSchemasOKBody JSON')
        if 'schemas' in _dict:
            args['schemas'] = _dict.get('schemas')
        else:
            raise ValueError('Required property \'schemas\' not present in GetSchemasOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetSchemasOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'response') and self.response is not None:
            if isinstance(self.response, dict):
                _dict['response'] = self.response
            else:
                _dict['response'] = self.response.to_dict()
        if hasattr(self, 'schemas') and self.schemas is not None:
            _dict['schemas'] = self.schemas
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetSchemasOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetSchemasOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetSchemasOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetTableSnapshotsOKBody:
    """
    TableSnapshot OK.

    :attr SuccessResponse response: Response of success.
    :attr List[TableSnapshot] snapshots: Snapshots.
    """

    def __init__(
        self,
        response: 'SuccessResponse',
        snapshots: List['TableSnapshot'],
    ) -> None:
        """
        Initialize a GetTableSnapshotsOKBody object.

        :param SuccessResponse response: Response of success.
        :param List[TableSnapshot] snapshots: Snapshots.
        """
        self.response = response
        self.snapshots = snapshots

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetTableSnapshotsOKBody':
        """Initialize a GetTableSnapshotsOKBody object from a json dictionary."""
        args = {}
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in GetTableSnapshotsOKBody JSON')
        if 'snapshots' in _dict:
            args['snapshots'] = [TableSnapshot.from_dict(v) for v in _dict.get('snapshots')]
        else:
            raise ValueError('Required property \'snapshots\' not present in GetTableSnapshotsOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetTableSnapshotsOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'response') and self.response is not None:
            if isinstance(self.response, dict):
                _dict['response'] = self.response
            else:
                _dict['response'] = self.response.to_dict()
        if hasattr(self, 'snapshots') and self.snapshots is not None:
            snapshots_list = []
            for v in self.snapshots:
                if isinstance(v, dict):
                    snapshots_list.append(v)
                else:
                    snapshots_list.append(v.to_dict())
            _dict['snapshots'] = snapshots_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetTableSnapshotsOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetTableSnapshotsOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetTableSnapshotsOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetTablesOKBody:
    """
    GetTables OK.

    :attr SuccessResponse response: Response of success.
    :attr List[str] tables: Tables.
    """

    def __init__(
        self,
        response: 'SuccessResponse',
        tables: List[str],
    ) -> None:
        """
        Initialize a GetTablesOKBody object.

        :param SuccessResponse response: Response of success.
        :param List[str] tables: Tables.
        """
        self.response = response
        self.tables = tables

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetTablesOKBody':
        """Initialize a GetTablesOKBody object from a json dictionary."""
        args = {}
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in GetTablesOKBody JSON')
        if 'tables' in _dict:
            args['tables'] = _dict.get('tables')
        else:
            raise ValueError('Required property \'tables\' not present in GetTablesOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetTablesOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'response') and self.response is not None:
            if isinstance(self.response, dict):
                _dict['response'] = self.response
            else:
                _dict['response'] = self.response.to_dict()
        if hasattr(self, 'tables') and self.tables is not None:
            _dict['tables'] = self.tables
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetTablesOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetTablesOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetTablesOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GroupingPolicyMetadata:
    """
    GroupingPolicyMetadata.

    :attr str domain: (optional) domain.
    :attr str inheritor: (optional) inheritor.
    :attr str role: (optional) role.
    """

    def __init__(
        self,
        *,
        domain: str = None,
        inheritor: str = None,
        role: str = None,
    ) -> None:
        """
        Initialize a GroupingPolicyMetadata object.

        :param str domain: (optional) domain.
        :param str inheritor: (optional) inheritor.
        :param str role: (optional) role.
        """
        self.domain = domain
        self.inheritor = inheritor
        self.role = role

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GroupingPolicyMetadata':
        """Initialize a GroupingPolicyMetadata object from a json dictionary."""
        args = {}
        if 'domain' in _dict:
            args['domain'] = _dict.get('domain')
        if 'inheritor' in _dict:
            args['inheritor'] = _dict.get('inheritor')
        if 'role' in _dict:
            args['role'] = _dict.get('role')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GroupingPolicyMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'domain') and self.domain is not None:
            _dict['domain'] = self.domain
        if hasattr(self, 'inheritor') and self.inheritor is not None:
            _dict['inheritor'] = self.inheritor
        if hasattr(self, 'role') and self.role is not None:
            _dict['role'] = self.role
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GroupingPolicyMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GroupingPolicyMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GroupingPolicyMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GroupsMetadata:
    """
    Groups metadata.

    :attr str group_id: The group id.
    :attr str permission: Eligible permission to the resource.
    """

    def __init__(
        self,
        group_id: str,
        permission: str,
    ) -> None:
        """
        Initialize a GroupsMetadata object.

        :param str group_id: The group id.
        :param str permission: Eligible permission to the resource.
        """
        self.group_id = group_id
        self.permission = permission

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GroupsMetadata':
        """Initialize a GroupsMetadata object from a json dictionary."""
        args = {}
        if 'group_id' in _dict:
            args['group_id'] = _dict.get('group_id')
        else:
            raise ValueError('Required property \'group_id\' not present in GroupsMetadata JSON')
        if 'permission' in _dict:
            args['permission'] = _dict.get('permission')
        else:
            raise ValueError('Required property \'permission\' not present in GroupsMetadata JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GroupsMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'group_id') and self.group_id is not None:
            _dict['group_id'] = self.group_id
        if hasattr(self, 'permission') and self.permission is not None:
            _dict['permission'] = self.permission
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GroupsMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GroupsMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GroupsMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class PermissionEnum(str, Enum):
        """
        Eligible permission to the resource.
        """

        CAN_ADMINISTER = 'can_administer'
        CAN_MANAGE = 'can_manage'
        CAN_USE = 'can_use'


class Metastore:
    """
    Metastore.

    :attr str catalog_name: (optional) Name for the metastore.
    :attr str hostname: (optional) IBM thrift uri hostname.
    :attr str managed_by: (optional) Managed by.
    :attr str status: (optional) Metastore status.
    :attr List[str] tags: (optional) Tags.
    :attr List[str] actions: (optional)
    :attr List[str] associated_buckets: (optional) Associated buckets items.
    :attr str created_by: (optional) Created by.
    :attr str thrift_uri: (optional) Customer thrift uri.
    :attr str catalog_type: (optional) Table type.
    :attr str description: (optional) Description.
    :attr List[str] associated_databases: (optional) Associated databases items.
    :attr List[str] associated_engines: (optional) Associated engines items.
    :attr str created_on: (optional) Created on.
    :attr str port: (optional) IBM thrift uri port.
    """

    def __init__(
        self,
        *,
        catalog_name: str = None,
        hostname: str = None,
        managed_by: str = None,
        status: str = None,
        tags: List[str] = None,
        actions: List[str] = None,
        associated_buckets: List[str] = None,
        created_by: str = None,
        thrift_uri: str = None,
        catalog_type: str = None,
        description: str = None,
        associated_databases: List[str] = None,
        associated_engines: List[str] = None,
        created_on: str = None,
        port: str = None,
    ) -> None:
        """
        Initialize a Metastore object.

        :param str catalog_name: (optional) Name for the metastore.
        :param str hostname: (optional) IBM thrift uri hostname.
        :param str managed_by: (optional) Managed by.
        :param str status: (optional) Metastore status.
        :param List[str] tags: (optional) Tags.
        :param List[str] actions: (optional)
        :param List[str] associated_buckets: (optional) Associated buckets items.
        :param str created_by: (optional) Created by.
        :param str thrift_uri: (optional) Customer thrift uri.
        :param str catalog_type: (optional) Table type.
        :param str description: (optional) Description.
        :param List[str] associated_databases: (optional) Associated databases
               items.
        :param List[str] associated_engines: (optional) Associated engines items.
        :param str created_on: (optional) Created on.
        :param str port: (optional) IBM thrift uri port.
        """
        self.catalog_name = catalog_name
        self.hostname = hostname
        self.managed_by = managed_by
        self.status = status
        self.tags = tags
        self.actions = actions
        self.associated_buckets = associated_buckets
        self.created_by = created_by
        self.thrift_uri = thrift_uri
        self.catalog_type = catalog_type
        self.description = description
        self.associated_databases = associated_databases
        self.associated_engines = associated_engines
        self.created_on = created_on
        self.port = port

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'Metastore':
        """Initialize a Metastore object from a json dictionary."""
        args = {}
        if 'catalog_name' in _dict:
            args['catalog_name'] = _dict.get('catalog_name')
        if 'hostname' in _dict:
            args['hostname'] = _dict.get('hostname')
        if 'managed_by' in _dict:
            args['managed_by'] = _dict.get('managed_by')
        if 'status' in _dict:
            args['status'] = _dict.get('status')
        if 'tags' in _dict:
            args['tags'] = _dict.get('tags')
        if 'actions' in _dict:
            args['actions'] = _dict.get('actions')
        if 'associated_buckets' in _dict:
            args['associated_buckets'] = _dict.get('associated_buckets')
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'thrift_uri' in _dict:
            args['thrift_uri'] = _dict.get('thrift_uri')
        if 'catalog_type' in _dict:
            args['catalog_type'] = _dict.get('catalog_type')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'associated_databases' in _dict:
            args['associated_databases'] = _dict.get('associated_databases')
        if 'associated_engines' in _dict:
            args['associated_engines'] = _dict.get('associated_engines')
        if 'created_on' in _dict:
            args['created_on'] = _dict.get('created_on')
        if 'port' in _dict:
            args['port'] = _dict.get('port')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a Metastore object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'catalog_name') and self.catalog_name is not None:
            _dict['catalog_name'] = self.catalog_name
        if hasattr(self, 'hostname') and self.hostname is not None:
            _dict['hostname'] = self.hostname
        if hasattr(self, 'managed_by') and self.managed_by is not None:
            _dict['managed_by'] = self.managed_by
        if hasattr(self, 'status') and self.status is not None:
            _dict['status'] = self.status
        if hasattr(self, 'tags') and self.tags is not None:
            _dict['tags'] = self.tags
        if hasattr(self, 'actions') and self.actions is not None:
            _dict['actions'] = self.actions
        if hasattr(self, 'associated_buckets') and self.associated_buckets is not None:
            _dict['associated_buckets'] = self.associated_buckets
        if hasattr(self, 'created_by') and self.created_by is not None:
            _dict['created_by'] = self.created_by
        if hasattr(self, 'thrift_uri') and self.thrift_uri is not None:
            _dict['thrift_uri'] = self.thrift_uri
        if hasattr(self, 'catalog_type') and self.catalog_type is not None:
            _dict['catalog_type'] = self.catalog_type
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'associated_databases') and self.associated_databases is not None:
            _dict['associated_databases'] = self.associated_databases
        if hasattr(self, 'associated_engines') and self.associated_engines is not None:
            _dict['associated_engines'] = self.associated_engines
        if hasattr(self, 'created_on') and self.created_on is not None:
            _dict['created_on'] = self.created_on
        if hasattr(self, 'port') and self.port is not None:
            _dict['port'] = self.port
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this Metastore object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'Metastore') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'Metastore') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class ManagedByEnum(str, Enum):
        """
        Managed by.
        """

        IBM = 'ibm'
        CUSTOMER = 'customer'


class NodeDescription:
    """
    NodeDescription.

    :attr str node_type: (optional) Node type.
    :attr int quantity: (optional) Quantity.
    """

    def __init__(
        self,
        *,
        node_type: str = None,
        quantity: int = None,
    ) -> None:
        """
        Initialize a NodeDescription object.

        :param str node_type: (optional) Node type.
        :param int quantity: (optional) Quantity.
        """
        self.node_type = node_type
        self.quantity = quantity

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'NodeDescription':
        """Initialize a NodeDescription object from a json dictionary."""
        args = {}
        if 'node_type' in _dict:
            args['node_type'] = _dict.get('node_type')
        if 'quantity' in _dict:
            args['quantity'] = _dict.get('quantity')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a NodeDescription object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'node_type') and self.node_type is not None:
            _dict['node_type'] = self.node_type
        if hasattr(self, 'quantity') and self.quantity is not None:
            _dict['quantity'] = self.quantity
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this NodeDescription object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'NodeDescription') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'NodeDescription') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class NodeDescriptionBody:
    """
    Node details.

    :attr str node_type: (optional) Node Type, r5, m, i..
    :attr int quantity: (optional) Number of nodes.
    """

    def __init__(
        self,
        *,
        node_type: str = None,
        quantity: int = None,
    ) -> None:
        """
        Initialize a NodeDescriptionBody object.

        :param str node_type: (optional) Node Type, r5, m, i..
        :param int quantity: (optional) Number of nodes.
        """
        self.node_type = node_type
        self.quantity = quantity

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'NodeDescriptionBody':
        """Initialize a NodeDescriptionBody object from a json dictionary."""
        args = {}
        if 'node_type' in _dict:
            args['node_type'] = _dict.get('node_type')
        if 'quantity' in _dict:
            args['quantity'] = _dict.get('quantity')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a NodeDescriptionBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'node_type') and self.node_type is not None:
            _dict['node_type'] = self.node_type
        if hasattr(self, 'quantity') and self.quantity is not None:
            _dict['quantity'] = self.quantity
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this NodeDescriptionBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'NodeDescriptionBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'NodeDescriptionBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class PauseEngineCreatedBody:
    """
    PauseEngineBody OK.

    :attr SuccessResponse response: (optional) Response of success.
    """

    def __init__(
        self,
        *,
        response: 'SuccessResponse' = None,
    ) -> None:
        """
        Initialize a PauseEngineCreatedBody object.

        :param SuccessResponse response: (optional) Response of success.
        """
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PauseEngineCreatedBody':
        """Initialize a PauseEngineCreatedBody object from a json dictionary."""
        args = {}
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PauseEngineCreatedBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'response') and self.response is not None:
            if isinstance(self.response, dict):
                _dict['response'] = self.response
            else:
                _dict['response'] = self.response.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PauseEngineCreatedBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PauseEngineCreatedBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PauseEngineCreatedBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class PolicyListSchema:
    """
    PolicyListSchema.

    :attr List[PolicySchema] policies: policy collection.
    :attr int total_count: Total number of policies.
    """

    def __init__(
        self,
        policies: List['PolicySchema'],
        total_count: int,
    ) -> None:
        """
        Initialize a PolicyListSchema object.

        :param List[PolicySchema] policies: policy collection.
        :param int total_count: Total number of policies.
        """
        self.policies = policies
        self.total_count = total_count

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PolicyListSchema':
        """Initialize a PolicyListSchema object from a json dictionary."""
        args = {}
        if 'policies' in _dict:
            args['policies'] = [PolicySchema.from_dict(v) for v in _dict.get('policies')]
        else:
            raise ValueError('Required property \'policies\' not present in PolicyListSchema JSON')
        if 'total_count' in _dict:
            args['total_count'] = _dict.get('total_count')
        else:
            raise ValueError('Required property \'total_count\' not present in PolicyListSchema JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PolicyListSchema object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'policies') and self.policies is not None:
            policies_list = []
            for v in self.policies:
                if isinstance(v, dict):
                    policies_list.append(v)
                else:
                    policies_list.append(v.to_dict())
            _dict['policies'] = policies_list
        if hasattr(self, 'total_count') and self.total_count is not None:
            _dict['total_count'] = self.total_count
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PolicyListSchema object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PolicyListSchema') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PolicyListSchema') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class PolicyMetadata:
    """
    PolicyMetadata.

    :attr str subject: (optional) subject.
    :attr List[str] actions: (optional) action array.
    :attr str domain: (optional) domain.
    :attr str object: (optional) object.
    """

    def __init__(
        self,
        *,
        subject: str = None,
        actions: List[str] = None,
        domain: str = None,
        object: str = None,
    ) -> None:
        """
        Initialize a PolicyMetadata object.

        :param str subject: (optional) subject.
        :param List[str] actions: (optional) action array.
        :param str domain: (optional) domain.
        :param str object: (optional) object.
        """
        self.subject = subject
        self.actions = actions
        self.domain = domain
        self.object = object

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PolicyMetadata':
        """Initialize a PolicyMetadata object from a json dictionary."""
        args = {}
        if 'subject' in _dict:
            args['subject'] = _dict.get('subject')
        if 'actions' in _dict:
            args['actions'] = _dict.get('actions')
        if 'domain' in _dict:
            args['domain'] = _dict.get('domain')
        if 'object' in _dict:
            args['object'] = _dict.get('object')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PolicyMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'subject') and self.subject is not None:
            _dict['subject'] = self.subject
        if hasattr(self, 'actions') and self.actions is not None:
            _dict['actions'] = self.actions
        if hasattr(self, 'domain') and self.domain is not None:
            _dict['domain'] = self.domain
        if hasattr(self, 'object') and self.object is not None:
            _dict['object'] = self.object
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PolicyMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PolicyMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PolicyMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class PolicySchema:
    """
    data policy.

    :attr int rule_count: (optional) Total number of rules.
    :attr List[Rule] rules: (optional) rules.
    :attr str status: (optional) data policy status.
    :attr str catalog_name: (optional) catalog name.
    :attr str data_artifact: (optional) data artifact.
    :attr DataPolicyMetadata metadata: (optional)
    :attr str policy_name: (optional) the displayed name for the policy.
    """

    def __init__(
        self,
        *,
        rule_count: int = None,
        rules: List['Rule'] = None,
        status: str = None,
        catalog_name: str = None,
        data_artifact: str = None,
        metadata: 'DataPolicyMetadata' = None,
        policy_name: str = None,
    ) -> None:
        """
        Initialize a PolicySchema object.

        :param int rule_count: (optional) Total number of rules.
        :param List[Rule] rules: (optional) rules.
        :param str status: (optional) data policy status.
        :param str catalog_name: (optional) catalog name.
        :param str data_artifact: (optional) data artifact.
        :param DataPolicyMetadata metadata: (optional)
        :param str policy_name: (optional) the displayed name for the policy.
        """
        self.rule_count = rule_count
        self.rules = rules
        self.status = status
        self.catalog_name = catalog_name
        self.data_artifact = data_artifact
        self.metadata = metadata
        self.policy_name = policy_name

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PolicySchema':
        """Initialize a PolicySchema object from a json dictionary."""
        args = {}
        if 'rule_count' in _dict:
            args['rule_count'] = _dict.get('rule_count')
        if 'rules' in _dict:
            args['rules'] = [Rule.from_dict(v) for v in _dict.get('rules')]
        if 'status' in _dict:
            args['status'] = _dict.get('status')
        if 'catalog_name' in _dict:
            args['catalog_name'] = _dict.get('catalog_name')
        if 'data_artifact' in _dict:
            args['data_artifact'] = _dict.get('data_artifact')
        if 'metadata' in _dict:
            args['metadata'] = DataPolicyMetadata.from_dict(_dict.get('metadata'))
        if 'policy_name' in _dict:
            args['policy_name'] = _dict.get('policy_name')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PolicySchema object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'rule_count') and self.rule_count is not None:
            _dict['rule_count'] = self.rule_count
        if hasattr(self, 'rules') and self.rules is not None:
            rules_list = []
            for v in self.rules:
                if isinstance(v, dict):
                    rules_list.append(v)
                else:
                    rules_list.append(v.to_dict())
            _dict['rules'] = rules_list
        if hasattr(self, 'status') and self.status is not None:
            _dict['status'] = self.status
        if hasattr(self, 'catalog_name') and self.catalog_name is not None:
            _dict['catalog_name'] = self.catalog_name
        if hasattr(self, 'data_artifact') and self.data_artifact is not None:
            _dict['data_artifact'] = self.data_artifact
        if hasattr(self, 'metadata') and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict['metadata'] = self.metadata
            else:
                _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'policy_name') and self.policy_name is not None:
            _dict['policy_name'] = self.policy_name
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PolicySchema object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PolicySchema') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PolicySchema') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class StatusEnum(str, Enum):
        """
        data policy status.
        """

        ACTIVE = 'active'
        INACTIVE = 'inactive'


class PolicySchemaList:
    """
    AMS schema List.

    :attr List[GetCatalogUsersSchema] catalog_policies: (optional) catalog policies
          definition.
    :attr List[PolicySchema] data_policies: (optional) data policies definition.
    :attr List[GetEngineUsersSchema] engine_policies: (optional) engine policies
          definition.
    """

    def __init__(
        self,
        *,
        catalog_policies: List['GetCatalogUsersSchema'] = None,
        data_policies: List['PolicySchema'] = None,
        engine_policies: List['GetEngineUsersSchema'] = None,
    ) -> None:
        """
        Initialize a PolicySchemaList object.

        :param List[GetCatalogUsersSchema] catalog_policies: (optional) catalog
               policies definition.
        :param List[PolicySchema] data_policies: (optional) data policies
               definition.
        :param List[GetEngineUsersSchema] engine_policies: (optional) engine
               policies definition.
        """
        self.catalog_policies = catalog_policies
        self.data_policies = data_policies
        self.engine_policies = engine_policies

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PolicySchemaList':
        """Initialize a PolicySchemaList object from a json dictionary."""
        args = {}
        if 'catalog_policies' in _dict:
            args['catalog_policies'] = [GetCatalogUsersSchema.from_dict(v) for v in _dict.get('catalog_policies')]
        if 'data_policies' in _dict:
            args['data_policies'] = [PolicySchema.from_dict(v) for v in _dict.get('data_policies')]
        if 'engine_policies' in _dict:
            args['engine_policies'] = [GetEngineUsersSchema.from_dict(v) for v in _dict.get('engine_policies')]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PolicySchemaList object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'catalog_policies') and self.catalog_policies is not None:
            catalog_policies_list = []
            for v in self.catalog_policies:
                if isinstance(v, dict):
                    catalog_policies_list.append(v)
                else:
                    catalog_policies_list.append(v.to_dict())
            _dict['catalog_policies'] = catalog_policies_list
        if hasattr(self, 'data_policies') and self.data_policies is not None:
            data_policies_list = []
            for v in self.data_policies:
                if isinstance(v, dict):
                    data_policies_list.append(v)
                else:
                    data_policies_list.append(v.to_dict())
            _dict['data_policies'] = data_policies_list
        if hasattr(self, 'engine_policies') and self.engine_policies is not None:
            engine_policies_list = []
            for v in self.engine_policies:
                if isinstance(v, dict):
                    engine_policies_list.append(v)
                else:
                    engine_policies_list.append(v.to_dict())
            _dict['engine_policies'] = engine_policies_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PolicySchemaList object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PolicySchemaList') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PolicySchemaList') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class PolicyVersionResultSchema:
    """
    AMS policy version result.

    :attr List[CatalogPolicies] catalog_policies: (optional) The catalog policy
          version list.
    :attr List[DataPolicies] data_policies: (optional) The data policy version list.
    :attr List[DbConnPolicies] database_policies: (optional) The Db connection
          policy version list.
    :attr List[EnginePolicies] engine_policies: (optional) The engine policy version
          list.
    :attr List[BucketPolicies] bucket_policies: (optional) The bucket policy version
          list.
    """

    def __init__(
        self,
        *,
        catalog_policies: List['CatalogPolicies'] = None,
        data_policies: List['DataPolicies'] = None,
        database_policies: List['DbConnPolicies'] = None,
        engine_policies: List['EnginePolicies'] = None,
        bucket_policies: List['BucketPolicies'] = None,
    ) -> None:
        """
        Initialize a PolicyVersionResultSchema object.

        :param List[CatalogPolicies] catalog_policies: (optional) The catalog
               policy version list.
        :param List[DataPolicies] data_policies: (optional) The data policy version
               list.
        :param List[DbConnPolicies] database_policies: (optional) The Db connection
               policy version list.
        :param List[EnginePolicies] engine_policies: (optional) The engine policy
               version list.
        :param List[BucketPolicies] bucket_policies: (optional) The bucket policy
               version list.
        """
        self.catalog_policies = catalog_policies
        self.data_policies = data_policies
        self.database_policies = database_policies
        self.engine_policies = engine_policies
        self.bucket_policies = bucket_policies

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PolicyVersionResultSchema':
        """Initialize a PolicyVersionResultSchema object from a json dictionary."""
        args = {}
        if 'catalog_policies' in _dict:
            args['catalog_policies'] = [CatalogPolicies.from_dict(v) for v in _dict.get('catalog_policies')]
        if 'data_policies' in _dict:
            args['data_policies'] = [DataPolicies.from_dict(v) for v in _dict.get('data_policies')]
        if 'database_policies' in _dict:
            args['database_policies'] = [DbConnPolicies.from_dict(v) for v in _dict.get('database_policies')]
        if 'engine_policies' in _dict:
            args['engine_policies'] = [EnginePolicies.from_dict(v) for v in _dict.get('engine_policies')]
        if 'bucket_policies' in _dict:
            args['bucket_policies'] = [BucketPolicies.from_dict(v) for v in _dict.get('bucket_policies')]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PolicyVersionResultSchema object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'catalog_policies') and self.catalog_policies is not None:
            catalog_policies_list = []
            for v in self.catalog_policies:
                if isinstance(v, dict):
                    catalog_policies_list.append(v)
                else:
                    catalog_policies_list.append(v.to_dict())
            _dict['catalog_policies'] = catalog_policies_list
        if hasattr(self, 'data_policies') and self.data_policies is not None:
            data_policies_list = []
            for v in self.data_policies:
                if isinstance(v, dict):
                    data_policies_list.append(v)
                else:
                    data_policies_list.append(v.to_dict())
            _dict['data_policies'] = data_policies_list
        if hasattr(self, 'database_policies') and self.database_policies is not None:
            database_policies_list = []
            for v in self.database_policies:
                if isinstance(v, dict):
                    database_policies_list.append(v)
                else:
                    database_policies_list.append(v.to_dict())
            _dict['database_policies'] = database_policies_list
        if hasattr(self, 'engine_policies') and self.engine_policies is not None:
            engine_policies_list = []
            for v in self.engine_policies:
                if isinstance(v, dict):
                    engine_policies_list.append(v)
                else:
                    engine_policies_list.append(v.to_dict())
            _dict['engine_policies'] = engine_policies_list
        if hasattr(self, 'bucket_policies') and self.bucket_policies is not None:
            bucket_policies_list = []
            for v in self.bucket_policies:
                if isinstance(v, dict):
                    bucket_policies_list.append(v)
                else:
                    bucket_policies_list.append(v.to_dict())
            _dict['bucket_policies'] = bucket_policies_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PolicyVersionResultSchema object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PolicyVersionResultSchema') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PolicyVersionResultSchema') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class Query:
    """
    Query.

    :attr str created_by: Created by.
    :attr str created_on: Created on.
    :attr str description: Description.
    :attr str engine_id: Engine ID.
    :attr str query_name: Query name.
    :attr str query_string: Query string.
    """

    def __init__(
        self,
        created_by: str,
        created_on: str,
        description: str,
        engine_id: str,
        query_name: str,
        query_string: str,
    ) -> None:
        """
        Initialize a Query object.

        :param str created_by: Created by.
        :param str created_on: Created on.
        :param str description: Description.
        :param str engine_id: Engine ID.
        :param str query_name: Query name.
        :param str query_string: Query string.
        """
        self.created_by = created_by
        self.created_on = created_on
        self.description = description
        self.engine_id = engine_id
        self.query_name = query_name
        self.query_string = query_string

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'Query':
        """Initialize a Query object from a json dictionary."""
        args = {}
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        else:
            raise ValueError('Required property \'created_by\' not present in Query JSON')
        if 'created_on' in _dict:
            args['created_on'] = _dict.get('created_on')
        else:
            raise ValueError('Required property \'created_on\' not present in Query JSON')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        else:
            raise ValueError('Required property \'description\' not present in Query JSON')
        if 'engine_id' in _dict:
            args['engine_id'] = _dict.get('engine_id')
        else:
            raise ValueError('Required property \'engine_id\' not present in Query JSON')
        if 'query_name' in _dict:
            args['query_name'] = _dict.get('query_name')
        else:
            raise ValueError('Required property \'query_name\' not present in Query JSON')
        if 'query_string' in _dict:
            args['query_string'] = _dict.get('query_string')
        else:
            raise ValueError('Required property \'query_string\' not present in Query JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a Query object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'created_by') and self.created_by is not None:
            _dict['created_by'] = self.created_by
        if hasattr(self, 'created_on') and self.created_on is not None:
            _dict['created_on'] = self.created_on
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'engine_id') and self.engine_id is not None:
            _dict['engine_id'] = self.engine_id
        if hasattr(self, 'query_name') and self.query_name is not None:
            _dict['query_name'] = self.query_name
        if hasattr(self, 'query_string') and self.query_string is not None:
            _dict['query_string'] = self.query_string
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this Query object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'Query') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'Query') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class RegisterBucketCreatedBody:
    """
    RegisterBucketCreatedBody.

    :attr RegisterBucketCreatedBodyBucket bucket:
    :attr SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        bucket: 'RegisterBucketCreatedBodyBucket',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a RegisterBucketCreatedBody object.

        :param RegisterBucketCreatedBodyBucket bucket:
        :param SuccessResponse response: Response of success.
        """
        self.bucket = bucket
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RegisterBucketCreatedBody':
        """Initialize a RegisterBucketCreatedBody object from a json dictionary."""
        args = {}
        if 'bucket' in _dict:
            args['bucket'] = RegisterBucketCreatedBodyBucket.from_dict(_dict.get('bucket'))
        else:
            raise ValueError('Required property \'bucket\' not present in RegisterBucketCreatedBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in RegisterBucketCreatedBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RegisterBucketCreatedBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'bucket') and self.bucket is not None:
            if isinstance(self.bucket, dict):
                _dict['bucket'] = self.bucket
            else:
                _dict['bucket'] = self.bucket.to_dict()
        if hasattr(self, 'response') and self.response is not None:
            if isinstance(self.response, dict):
                _dict['response'] = self.response
            else:
                _dict['response'] = self.response.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RegisterBucketCreatedBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RegisterBucketCreatedBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RegisterBucketCreatedBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class RegisterBucketCreatedBodyBucket:
    """
    RegisterBucketCreatedBodyBucket.

    :attr str bucket_display_name: (optional) Bucket display name.
    :attr str bucket_id: (optional) Bucket ID.
    """

    def __init__(
        self,
        *,
        bucket_display_name: str = None,
        bucket_id: str = None,
    ) -> None:
        """
        Initialize a RegisterBucketCreatedBodyBucket object.

        :param str bucket_display_name: (optional) Bucket display name.
        :param str bucket_id: (optional) Bucket ID.
        """
        self.bucket_display_name = bucket_display_name
        self.bucket_id = bucket_id

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RegisterBucketCreatedBodyBucket':
        """Initialize a RegisterBucketCreatedBodyBucket object from a json dictionary."""
        args = {}
        if 'bucket_display_name' in _dict:
            args['bucket_display_name'] = _dict.get('bucket_display_name')
        if 'bucket_id' in _dict:
            args['bucket_id'] = _dict.get('bucket_id')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RegisterBucketCreatedBodyBucket object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'bucket_display_name') and self.bucket_display_name is not None:
            _dict['bucket_display_name'] = self.bucket_display_name
        if hasattr(self, 'bucket_id') and self.bucket_id is not None:
            _dict['bucket_id'] = self.bucket_id
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RegisterBucketCreatedBodyBucket object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RegisterBucketCreatedBodyBucket') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RegisterBucketCreatedBodyBucket') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class RegisterDatabaseCatalogBodyDatabaseDetails:
    """
    database details.

    :attr str password: (optional) Psssword.
    :attr str port: (optional) Port.
    :attr bool ssl: (optional) SSL Mode.
    :attr str tables: (optional) Only for Kafka - Add kafka tables.
    :attr str username: (optional) Username.
    :attr str database_name: (optional) Database name.
    :attr str hostname: (optional) Host name.
    """

    def __init__(
        self,
        *,
        password: str = None,
        port: str = None,
        ssl: bool = None,
        tables: str = None,
        username: str = None,
        database_name: str = None,
        hostname: str = None,
    ) -> None:
        """
        Initialize a RegisterDatabaseCatalogBodyDatabaseDetails object.

        :param str password: (optional) Psssword.
        :param str port: (optional) Port.
        :param bool ssl: (optional) SSL Mode.
        :param str tables: (optional) Only for Kafka - Add kafka tables.
        :param str username: (optional) Username.
        :param str database_name: (optional) Database name.
        :param str hostname: (optional) Host name.
        """
        self.password = password
        self.port = port
        self.ssl = ssl
        self.tables = tables
        self.username = username
        self.database_name = database_name
        self.hostname = hostname

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RegisterDatabaseCatalogBodyDatabaseDetails':
        """Initialize a RegisterDatabaseCatalogBodyDatabaseDetails object from a json dictionary."""
        args = {}
        if 'password' in _dict:
            args['password'] = _dict.get('password')
        if 'port' in _dict:
            args['port'] = _dict.get('port')
        if 'ssl' in _dict:
            args['ssl'] = _dict.get('ssl')
        if 'tables' in _dict:
            args['tables'] = _dict.get('tables')
        if 'username' in _dict:
            args['username'] = _dict.get('username')
        if 'database_name' in _dict:
            args['database_name'] = _dict.get('database_name')
        if 'hostname' in _dict:
            args['hostname'] = _dict.get('hostname')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RegisterDatabaseCatalogBodyDatabaseDetails object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'password') and self.password is not None:
            _dict['password'] = self.password
        if hasattr(self, 'port') and self.port is not None:
            _dict['port'] = self.port
        if hasattr(self, 'ssl') and self.ssl is not None:
            _dict['ssl'] = self.ssl
        if hasattr(self, 'tables') and self.tables is not None:
            _dict['tables'] = self.tables
        if hasattr(self, 'username') and self.username is not None:
            _dict['username'] = self.username
        if hasattr(self, 'database_name') and self.database_name is not None:
            _dict['database_name'] = self.database_name
        if hasattr(self, 'hostname') and self.hostname is not None:
            _dict['hostname'] = self.hostname
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RegisterDatabaseCatalogBodyDatabaseDetails object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RegisterDatabaseCatalogBodyDatabaseDetails') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RegisterDatabaseCatalogBodyDatabaseDetails') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ReplaceDataPolicyCreatedBody:
    """
    Replace data policy success.

    :attr ReplaceDataPolicySchema data_policy: Replace data policy.
    :attr DataPolicyMetadata metadata:
    :attr SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        data_policy: 'ReplaceDataPolicySchema',
        metadata: 'DataPolicyMetadata',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a ReplaceDataPolicyCreatedBody object.

        :param ReplaceDataPolicySchema data_policy: Replace data policy.
        :param DataPolicyMetadata metadata:
        :param SuccessResponse response: Response of success.
        """
        self.data_policy = data_policy
        self.metadata = metadata
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ReplaceDataPolicyCreatedBody':
        """Initialize a ReplaceDataPolicyCreatedBody object from a json dictionary."""
        args = {}
        if 'data_policy' in _dict:
            args['data_policy'] = ReplaceDataPolicySchema.from_dict(_dict.get('data_policy'))
        else:
            raise ValueError('Required property \'data_policy\' not present in ReplaceDataPolicyCreatedBody JSON')
        if 'metadata' in _dict:
            args['metadata'] = DataPolicyMetadata.from_dict(_dict.get('metadata'))
        else:
            raise ValueError('Required property \'metadata\' not present in ReplaceDataPolicyCreatedBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in ReplaceDataPolicyCreatedBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ReplaceDataPolicyCreatedBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'data_policy') and self.data_policy is not None:
            if isinstance(self.data_policy, dict):
                _dict['data_policy'] = self.data_policy
            else:
                _dict['data_policy'] = self.data_policy.to_dict()
        if hasattr(self, 'metadata') and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict['metadata'] = self.metadata
            else:
                _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'response') and self.response is not None:
            if isinstance(self.response, dict):
                _dict['response'] = self.response
            else:
                _dict['response'] = self.response.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ReplaceDataPolicyCreatedBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ReplaceDataPolicyCreatedBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ReplaceDataPolicyCreatedBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ReplaceDataPolicySchema:
    """
    Replace data policy.

    :attr str catalog_name: catalog name.
    :attr str data_artifact: data artifact.
    :attr str description: (optional) a more detailed description of the policy.
    :attr List[Rule] rules: rules.
    :attr str status: (optional) data policy status.
    """

    def __init__(
        self,
        catalog_name: str,
        data_artifact: str,
        rules: List['Rule'],
        *,
        description: str = None,
        status: str = None,
    ) -> None:
        """
        Initialize a ReplaceDataPolicySchema object.

        :param str catalog_name: catalog name.
        :param str data_artifact: data artifact.
        :param List[Rule] rules: rules.
        :param str description: (optional) a more detailed description of the
               policy.
        :param str status: (optional) data policy status.
        """
        self.catalog_name = catalog_name
        self.data_artifact = data_artifact
        self.description = description
        self.rules = rules
        self.status = status

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ReplaceDataPolicySchema':
        """Initialize a ReplaceDataPolicySchema object from a json dictionary."""
        args = {}
        if 'catalog_name' in _dict:
            args['catalog_name'] = _dict.get('catalog_name')
        else:
            raise ValueError('Required property \'catalog_name\' not present in ReplaceDataPolicySchema JSON')
        if 'data_artifact' in _dict:
            args['data_artifact'] = _dict.get('data_artifact')
        else:
            raise ValueError('Required property \'data_artifact\' not present in ReplaceDataPolicySchema JSON')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'rules' in _dict:
            args['rules'] = [Rule.from_dict(v) for v in _dict.get('rules')]
        else:
            raise ValueError('Required property \'rules\' not present in ReplaceDataPolicySchema JSON')
        if 'status' in _dict:
            args['status'] = _dict.get('status')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ReplaceDataPolicySchema object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'catalog_name') and self.catalog_name is not None:
            _dict['catalog_name'] = self.catalog_name
        if hasattr(self, 'data_artifact') and self.data_artifact is not None:
            _dict['data_artifact'] = self.data_artifact
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'rules') and self.rules is not None:
            rules_list = []
            for v in self.rules:
                if isinstance(v, dict):
                    rules_list.append(v)
                else:
                    rules_list.append(v.to_dict())
            _dict['rules'] = rules_list
        if hasattr(self, 'status') and self.status is not None:
            _dict['status'] = self.status
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ReplaceDataPolicySchema object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ReplaceDataPolicySchema') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ReplaceDataPolicySchema') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class StatusEnum(str, Enum):
        """
        data policy status.
        """

        ACTIVE = 'active'
        INACTIVE = 'inactive'


class ResourceWithResult:
    """
    Resource with result.

    :attr str action: action.
    :attr str resource_name: Resource name.
    :attr str resource_type: Resource type.
    :attr bool result: resource evaluation result.
    """

    def __init__(
        self,
        action: str,
        resource_name: str,
        resource_type: str,
        result: bool,
    ) -> None:
        """
        Initialize a ResourceWithResult object.

        :param str action: action.
        :param str resource_name: Resource name.
        :param str resource_type: Resource type.
        :param bool result: resource evaluation result.
        """
        self.action = action
        self.resource_name = resource_name
        self.resource_type = resource_type
        self.result = result

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ResourceWithResult':
        """Initialize a ResourceWithResult object from a json dictionary."""
        args = {}
        if 'action' in _dict:
            args['action'] = _dict.get('action')
        else:
            raise ValueError('Required property \'action\' not present in ResourceWithResult JSON')
        if 'resource_name' in _dict:
            args['resource_name'] = _dict.get('resource_name')
        else:
            raise ValueError('Required property \'resource_name\' not present in ResourceWithResult JSON')
        if 'resource_type' in _dict:
            args['resource_type'] = _dict.get('resource_type')
        else:
            raise ValueError('Required property \'resource_type\' not present in ResourceWithResult JSON')
        if 'result' in _dict:
            args['result'] = _dict.get('result')
        else:
            raise ValueError('Required property \'result\' not present in ResourceWithResult JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ResourceWithResult object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'action') and self.action is not None:
            _dict['action'] = self.action
        if hasattr(self, 'resource_name') and self.resource_name is not None:
            _dict['resource_name'] = self.resource_name
        if hasattr(self, 'resource_type') and self.resource_type is not None:
            _dict['resource_type'] = self.resource_type
        if hasattr(self, 'result') and self.result is not None:
            _dict['result'] = self.result
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ResourceWithResult object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ResourceWithResult') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ResourceWithResult') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ResourcesMetadata:
    """
    Resource.

    :attr str action: resource action to be evaluated.
    :attr str resource_name: Resource name.
    :attr str resource_type: Resource type.
    """

    def __init__(
        self,
        action: str,
        resource_name: str,
        resource_type: str,
    ) -> None:
        """
        Initialize a ResourcesMetadata object.

        :param str action: resource action to be evaluated.
        :param str resource_name: Resource name.
        :param str resource_type: Resource type.
        """
        self.action = action
        self.resource_name = resource_name
        self.resource_type = resource_type

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ResourcesMetadata':
        """Initialize a ResourcesMetadata object from a json dictionary."""
        args = {}
        if 'action' in _dict:
            args['action'] = _dict.get('action')
        else:
            raise ValueError('Required property \'action\' not present in ResourcesMetadata JSON')
        if 'resource_name' in _dict:
            args['resource_name'] = _dict.get('resource_name')
        else:
            raise ValueError('Required property \'resource_name\' not present in ResourcesMetadata JSON')
        if 'resource_type' in _dict:
            args['resource_type'] = _dict.get('resource_type')
        else:
            raise ValueError('Required property \'resource_type\' not present in ResourcesMetadata JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ResourcesMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'action') and self.action is not None:
            _dict['action'] = self.action
        if hasattr(self, 'resource_name') and self.resource_name is not None:
            _dict['resource_name'] = self.resource_name
        if hasattr(self, 'resource_type') and self.resource_type is not None:
            _dict['resource_type'] = self.resource_type
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ResourcesMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ResourcesMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ResourcesMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class ResourceTypeEnum(str, Enum):
        """
        Resource type.
        """

        ENGINE = 'engine'
        CATALOG = 'catalog'
        BUCKET = 'bucket'
        DATABASE = 'database'


class ResumeEngineCreatedBody:
    """
    resumeEngine OK.

    :attr SuccessResponse response: (optional) Response of success.
    """

    def __init__(
        self,
        *,
        response: 'SuccessResponse' = None,
    ) -> None:
        """
        Initialize a ResumeEngineCreatedBody object.

        :param SuccessResponse response: (optional) Response of success.
        """
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ResumeEngineCreatedBody':
        """Initialize a ResumeEngineCreatedBody object from a json dictionary."""
        args = {}
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ResumeEngineCreatedBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'response') and self.response is not None:
            if isinstance(self.response, dict):
                _dict['response'] = self.response
            else:
                _dict['response'] = self.response.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ResumeEngineCreatedBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ResumeEngineCreatedBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ResumeEngineCreatedBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class Rule:
    """
    Rule.

    :attr List[str] actions: the actions to enforce when the data policy triggers.
    :attr str effect: (optional) data policy effect.
    :attr RuleGrantee grantee: user name, group id or tag value.
    """

    def __init__(
        self,
        actions: List[str],
        grantee: 'RuleGrantee',
        *,
        effect: str = None,
    ) -> None:
        """
        Initialize a Rule object.

        :param List[str] actions: the actions to enforce when the data policy
               triggers.
        :param RuleGrantee grantee: user name, group id or tag value.
        :param str effect: (optional) data policy effect.
        """
        self.actions = actions
        self.effect = effect
        self.grantee = grantee

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'Rule':
        """Initialize a Rule object from a json dictionary."""
        args = {}
        if 'actions' in _dict:
            args['actions'] = _dict.get('actions')
        else:
            raise ValueError('Required property \'actions\' not present in Rule JSON')
        if 'effect' in _dict:
            args['effect'] = _dict.get('effect')
        if 'grantee' in _dict:
            args['grantee'] = RuleGrantee.from_dict(_dict.get('grantee'))
        else:
            raise ValueError('Required property \'grantee\' not present in Rule JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a Rule object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'actions') and self.actions is not None:
            _dict['actions'] = self.actions
        if hasattr(self, 'effect') and self.effect is not None:
            _dict['effect'] = self.effect
        if hasattr(self, 'grantee') and self.grantee is not None:
            if isinstance(self.grantee, dict):
                _dict['grantee'] = self.grantee
            else:
                _dict['grantee'] = self.grantee.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this Rule object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'Rule') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'Rule') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class ActionsEnum(str, Enum):
        """
        actions.
        """

        ALL = 'all'
        CREATE = 'create'
        DROP = 'drop'
        ALTER = 'alter'
        INSERT = 'insert'
        GRANT = 'grant'
        REVOKE = 'revoke'
        DELETE = 'delete'
        SELECT = 'select'
        USE = 'use'
        SHOW = 'show'
        VIEW = 'view'
        TRUNCATE = 'truncate'

    class EffectEnum(str, Enum):
        """
        data policy effect.
        """

        ALLOW = 'allow'
        DENY = 'deny'


class RuleGrantee:
    """
    user name, group id or tag value.

    :attr str value: grantee value.
    :attr str key: grantee key.
    :attr str type: grantee type.
    """

    def __init__(
        self,
        value: str,
        key: str,
        type: str,
    ) -> None:
        """
        Initialize a RuleGrantee object.

        :param str value: grantee value.
        :param str key: grantee key.
        :param str type: grantee type.
        """
        self.value = value
        self.key = key
        self.type = type

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RuleGrantee':
        """Initialize a RuleGrantee object from a json dictionary."""
        args = {}
        if 'value' in _dict:
            args['value'] = _dict.get('value')
        else:
            raise ValueError('Required property \'value\' not present in RuleGrantee JSON')
        if 'key' in _dict:
            args['key'] = _dict.get('key')
        else:
            raise ValueError('Required property \'key\' not present in RuleGrantee JSON')
        if 'type' in _dict:
            args['type'] = _dict.get('type')
        else:
            raise ValueError('Required property \'type\' not present in RuleGrantee JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RuleGrantee object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'value') and self.value is not None:
            _dict['value'] = self.value
        if hasattr(self, 'key') and self.key is not None:
            _dict['key'] = self.key
        if hasattr(self, 'type') and self.type is not None:
            _dict['type'] = self.type
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RuleGrantee object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RuleGrantee') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RuleGrantee') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class KeyEnum(str, Enum):
        """
        grantee key.
        """

        USER_NAME = 'user_name'
        GROUP_ID = 'group_id'
        ATTRIBUTE_NAME = 'attribute_name'

    class TypeEnum(str, Enum):
        """
        grantee type.
        """

        USER_IDENTITY = 'user_identity'
        TAG = 'tag'


class SuccessResponse:
    """
    Response of success.

    :attr str message_code: (optional) Message code.
    :attr str message: (optional) Message.
    """

    def __init__(
        self,
        *,
        message_code: str = None,
        message: str = None,
    ) -> None:
        """
        Initialize a SuccessResponse object.

        :param str message_code: (optional) Message code.
        :param str message: (optional) Message.
        """
        self.message_code = message_code
        self.message = message

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessResponse':
        """Initialize a SuccessResponse object from a json dictionary."""
        args = {}
        if '_messageCode_' in _dict:
            args['message_code'] = _dict.get('_messageCode_')
        if 'message' in _dict:
            args['message'] = _dict.get('message')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessResponse object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'message_code') and self.message_code is not None:
            _dict['_messageCode_'] = self.message_code
        if hasattr(self, 'message') and self.message is not None:
            _dict['message'] = self.message
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SuccessResponse object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SuccessResponse') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SuccessResponse') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class TableSnapshot:
    """
    TableSnapshot.

    :attr str operation: (optional) Operation.
    :attr str snapshot_id: (optional) Snapshot id.
    :attr dict summary: (optional) Summary.
    :attr str committed_at: (optional) Committed at.
    """

    def __init__(
        self,
        *,
        operation: str = None,
        snapshot_id: str = None,
        summary: dict = None,
        committed_at: str = None,
    ) -> None:
        """
        Initialize a TableSnapshot object.

        :param str operation: (optional) Operation.
        :param str snapshot_id: (optional) Snapshot id.
        :param dict summary: (optional) Summary.
        :param str committed_at: (optional) Committed at.
        """
        self.operation = operation
        self.snapshot_id = snapshot_id
        self.summary = summary
        self.committed_at = committed_at

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'TableSnapshot':
        """Initialize a TableSnapshot object from a json dictionary."""
        args = {}
        if 'operation' in _dict:
            args['operation'] = _dict.get('operation')
        if 'snapshot_id' in _dict:
            args['snapshot_id'] = _dict.get('snapshot_id')
        if 'summary' in _dict:
            args['summary'] = _dict.get('summary')
        if 'committed_at' in _dict:
            args['committed_at'] = _dict.get('committed_at')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a TableSnapshot object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'operation') and self.operation is not None:
            _dict['operation'] = self.operation
        if hasattr(self, 'snapshot_id') and self.snapshot_id is not None:
            _dict['snapshot_id'] = self.snapshot_id
        if hasattr(self, 'summary') and self.summary is not None:
            _dict['summary'] = self.summary
        if hasattr(self, 'committed_at') and self.committed_at is not None:
            _dict['committed_at'] = self.committed_at
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this TableSnapshot object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'TableSnapshot') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'TableSnapshot') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class UpdateDatabaseBodyDatabaseDetails:
    """
    database details.

    :attr str password: (optional) Password.
    :attr str username: (optional) Username.
    """

    def __init__(
        self,
        *,
        password: str = None,
        username: str = None,
    ) -> None:
        """
        Initialize a UpdateDatabaseBodyDatabaseDetails object.

        :param str password: (optional) Password.
        :param str username: (optional) Username.
        """
        self.password = password
        self.username = username

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'UpdateDatabaseBodyDatabaseDetails':
        """Initialize a UpdateDatabaseBodyDatabaseDetails object from a json dictionary."""
        args = {}
        if 'password' in _dict:
            args['password'] = _dict.get('password')
        if 'username' in _dict:
            args['username'] = _dict.get('username')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a UpdateDatabaseBodyDatabaseDetails object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'password') and self.password is not None:
            _dict['password'] = self.password
        if hasattr(self, 'username') and self.username is not None:
            _dict['username'] = self.username
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this UpdateDatabaseBodyDatabaseDetails object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'UpdateDatabaseBodyDatabaseDetails') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'UpdateDatabaseBodyDatabaseDetails') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class UpdateTableBodyAddColumnsItems:
    """
    Add_columns items.

    :attr str column_comment: (optional) Comment.
    :attr str column_name: (optional) Column name.
    :attr str data_type: (optional) Data type.
    """

    def __init__(
        self,
        *,
        column_comment: str = None,
        column_name: str = None,
        data_type: str = None,
    ) -> None:
        """
        Initialize a UpdateTableBodyAddColumnsItems object.

        :param str column_comment: (optional) Comment.
        :param str column_name: (optional) Column name.
        :param str data_type: (optional) Data type.
        """
        self.column_comment = column_comment
        self.column_name = column_name
        self.data_type = data_type

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'UpdateTableBodyAddColumnsItems':
        """Initialize a UpdateTableBodyAddColumnsItems object from a json dictionary."""
        args = {}
        if 'column_comment' in _dict:
            args['column_comment'] = _dict.get('column_comment')
        if 'column_name' in _dict:
            args['column_name'] = _dict.get('column_name')
        if 'data_type' in _dict:
            args['data_type'] = _dict.get('data_type')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a UpdateTableBodyAddColumnsItems object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'column_comment') and self.column_comment is not None:
            _dict['column_comment'] = self.column_comment
        if hasattr(self, 'column_name') and self.column_name is not None:
            _dict['column_name'] = self.column_name
        if hasattr(self, 'data_type') and self.data_type is not None:
            _dict['data_type'] = self.data_type
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this UpdateTableBodyAddColumnsItems object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'UpdateTableBodyAddColumnsItems') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'UpdateTableBodyAddColumnsItems') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class UpdateTableBodyDropColumnsItems:
    """
    Drop_columns items.

    :attr str column_name: (optional) Column name.
    """

    def __init__(
        self,
        *,
        column_name: str = None,
    ) -> None:
        """
        Initialize a UpdateTableBodyDropColumnsItems object.

        :param str column_name: (optional) Column name.
        """
        self.column_name = column_name

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'UpdateTableBodyDropColumnsItems':
        """Initialize a UpdateTableBodyDropColumnsItems object from a json dictionary."""
        args = {}
        if 'column_name' in _dict:
            args['column_name'] = _dict.get('column_name')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a UpdateTableBodyDropColumnsItems object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'column_name') and self.column_name is not None:
            _dict['column_name'] = self.column_name
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this UpdateTableBodyDropColumnsItems object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'UpdateTableBodyDropColumnsItems') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'UpdateTableBodyDropColumnsItems') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class UpdateTableBodyRenameColumnsItems:
    """
    Rename_columns items.

    :attr str column_name: (optional) Column name.
    :attr str new_column_name: (optional) New column name.
    """

    def __init__(
        self,
        *,
        column_name: str = None,
        new_column_name: str = None,
    ) -> None:
        """
        Initialize a UpdateTableBodyRenameColumnsItems object.

        :param str column_name: (optional) Column name.
        :param str new_column_name: (optional) New column name.
        """
        self.column_name = column_name
        self.new_column_name = new_column_name

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'UpdateTableBodyRenameColumnsItems':
        """Initialize a UpdateTableBodyRenameColumnsItems object from a json dictionary."""
        args = {}
        if 'column_name' in _dict:
            args['column_name'] = _dict.get('column_name')
        if 'new_column_name' in _dict:
            args['new_column_name'] = _dict.get('new_column_name')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a UpdateTableBodyRenameColumnsItems object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'column_name') and self.column_name is not None:
            _dict['column_name'] = self.column_name
        if hasattr(self, 'new_column_name') and self.new_column_name is not None:
            _dict['new_column_name'] = self.new_column_name
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this UpdateTableBodyRenameColumnsItems object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'UpdateTableBodyRenameColumnsItems') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'UpdateTableBodyRenameColumnsItems') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class UsersMetadata:
    """
    Users metadata.

    :attr str permission: Eligible permission to the resource.
    :attr str user_name: The user name.
    """

    def __init__(
        self,
        permission: str,
        user_name: str,
    ) -> None:
        """
        Initialize a UsersMetadata object.

        :param str permission: Eligible permission to the resource.
        :param str user_name: The user name.
        """
        self.permission = permission
        self.user_name = user_name

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'UsersMetadata':
        """Initialize a UsersMetadata object from a json dictionary."""
        args = {}
        if 'permission' in _dict:
            args['permission'] = _dict.get('permission')
        else:
            raise ValueError('Required property \'permission\' not present in UsersMetadata JSON')
        if 'user_name' in _dict:
            args['user_name'] = _dict.get('user_name')
        else:
            raise ValueError('Required property \'user_name\' not present in UsersMetadata JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a UsersMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'permission') and self.permission is not None:
            _dict['permission'] = self.permission
        if hasattr(self, 'user_name') and self.user_name is not None:
            _dict['user_name'] = self.user_name
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this UsersMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'UsersMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'UsersMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class PermissionEnum(str, Enum):
        """
        Eligible permission to the resource.
        """

        CAN_ADMINISTER = 'can_administer'
        CAN_MANAGE = 'can_manage'
        CAN_USE = 'can_use'
