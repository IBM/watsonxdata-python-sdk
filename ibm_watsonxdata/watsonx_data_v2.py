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

# IBM OpenAPI SDK Code Generator Version: 3.82.1-2082d402-20231115-195014

"""
This is the Public API for IBM watsonx.data

API Version: 2.0.0
"""

from enum import Enum
from typing import BinaryIO, Dict, List, Optional
import json

from ibm_cloud_sdk_core import BaseService, DetailedResponse
from ibm_cloud_sdk_core.authenticators.authenticator import Authenticator
from ibm_cloud_sdk_core.get_authenticator import get_authenticator_from_environment
from ibm_cloud_sdk_core.utils import convert_model

from .common import get_sdk_headers

##############################################################################
# Service
##############################################################################


class WatsonxDataV2(BaseService):
    """The watsonx.data V2 service."""

    DEFAULT_SERVICE_URL = 'https://ibmcloud/lakehouse/api/v2'
    DEFAULT_SERVICE_NAME = 'watsonx_data'

    @classmethod
    def new_instance(
        cls,
        service_name: str = DEFAULT_SERVICE_NAME,
    ) -> 'WatsonxDataV2':
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
    # buckets
    #########################

    def list_bucket_registrations(
        self,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get bucket registrations.

        Get list of registered buckets.

        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListBucketRegistrationsOKBody` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='list_bucket_registrations',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/bucket_registrations'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def create_bucket_registration(
        self,
        bucket_details: 'BucketDetails',
        bucket_type: str,
        catalog_name: str,
        description: str,
        managed_by: str,
        table_type: str,
        *,
        bucket_display_name: Optional[str] = None,
        bucket_tags: Optional[List[str]] = None,
        catalog_tags: Optional[List[str]] = None,
        region: Optional[str] = None,
        state: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Register bucket.

        Register a new bucket.

        :param BucketDetails bucket_details: bucket details.
        :param str bucket_type: bucket type.
        :param str catalog_name: catalog name.
        :param str description: bucket description.
        :param str managed_by: managed by.
        :param str table_type: Table type.
        :param str bucket_display_name: (optional) bucket display name.
        :param List[str] bucket_tags: (optional) tags.
        :param List[str] catalog_tags: (optional) catalog tags.
        :param str region: (optional) region where the bucket is located.
        :param str state: (optional) mark bucket active or inactive.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `CreateBucketRegistrationCreatedBody` object
        """

        if bucket_details is None:
            raise ValueError('bucket_details must be provided')
        if bucket_type is None:
            raise ValueError('bucket_type must be provided')
        if catalog_name is None:
            raise ValueError('catalog_name must be provided')
        if description is None:
            raise ValueError('description must be provided')
        if managed_by is None:
            raise ValueError('managed_by must be provided')
        if table_type is None:
            raise ValueError('table_type must be provided')
        bucket_details = convert_model(bucket_details)
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_bucket_registration',
        )
        headers.update(sdk_headers)

        data = {
            'bucket_details': bucket_details,
            'bucket_type': bucket_type,
            'catalog_name': catalog_name,
            'description': description,
            'managed_by': managed_by,
            'table_type': table_type,
            'bucket_display_name': bucket_display_name,
            'bucket_tags': bucket_tags,
            'catalog_tags': catalog_tags,
            'region': region,
            'state': state,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/bucket_registrations'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_bucket_registration(
        self,
        bucket_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get bucket.

        Get a registered bucket.

        :param str bucket_id: bucket id.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetBucketRegistrationOKBody` object
        """

        if not bucket_id:
            raise ValueError('bucket_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_bucket_registration',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['bucket_id']
        path_param_values = self.encode_path_vars(bucket_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/bucket_registrations/{bucket_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_bucket_registration(
        self,
        bucket_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Unregister Bucket.

        Unregister a bucket.

        :param str bucket_id: bucket id.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not bucket_id:
            raise ValueError('bucket_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='delete_bucket_registration',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['bucket_id']
        path_param_values = self.encode_path_vars(bucket_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/bucket_registrations/{bucket_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def update_bucket_registration(
        self,
        bucket_id: str,
        body: List['JsonPatchOperation'],
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Update bucket.

        Update bucket details & credentials.

        :param str bucket_id: bucket id.
        :param List[JsonPatchOperation] body: Request body.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `UpdateBucketRegistrationOKBody` object
        """

        if not bucket_id:
            raise ValueError('bucket_id must be provided')
        if body is None:
            raise ValueError('body must be provided')
        body = [convert_model(x) for x in body]
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='update_bucket_registration',
        )
        headers.update(sdk_headers)

        data = json.dumps(body)
        headers['content-type'] = 'application/json-patch+json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['bucket_id']
        path_param_values = self.encode_path_vars(bucket_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/bucket_registrations/{bucket_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='PATCH',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def create_activate_bucket(
        self,
        bucket_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Activate Bucket.

        Activate a registered bucket.

        :param str bucket_id: bucket id.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `CreateActivateBucketCreatedBody` object
        """

        if not bucket_id:
            raise ValueError('bucket_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_activate_bucket',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['bucket_id']
        path_param_values = self.encode_path_vars(bucket_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/bucket_registrations/{bucket_id}/activate'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_deactivate_bucket(
        self,
        bucket_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Deactivate Bucket.

        Deactivate a bucket.

        :param str bucket_id: bucket id.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not bucket_id:
            raise ValueError('bucket_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='delete_deactivate_bucket',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['bucket_id']
        path_param_values = self.encode_path_vars(bucket_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/bucket_registrations/{bucket_id}/deactivate'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def list_bucket_objects(
        self,
        bucket_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        List bucket objects.

        Fetch all objects from a given bucket.

        :param str bucket_id: bucket id.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListBucketObjectsOKBody` object
        """

        if not bucket_id:
            raise ValueError('bucket_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='list_bucket_objects',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['bucket_id']
        path_param_values = self.encode_path_vars(bucket_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/bucket_registrations/{bucket_id}/objects'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def test_bucket_connection(
        self,
        access_key: str,
        bucket_name: str,
        bucket_type: str,
        endpoint: str,
        region: str,
        secret_key: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Check bucket credentials to be valid.

        Check whether provided bucket credentials are valid or not.

        :param str access_key: access key to access the bucket.
        :param str bucket_name: name of the bucket to be checked.
        :param str bucket_type: type of bucket that is selected.
        :param str endpoint: endpoint to reach the bucket.
        :param str region: bucket region.
        :param str secret_key: secret key to access the bucket.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `TestBucketConnectionOKBody` object
        """

        if access_key is None:
            raise ValueError('access_key must be provided')
        if bucket_name is None:
            raise ValueError('bucket_name must be provided')
        if bucket_type is None:
            raise ValueError('bucket_type must be provided')
        if endpoint is None:
            raise ValueError('endpoint must be provided')
        if region is None:
            raise ValueError('region must be provided')
        if secret_key is None:
            raise ValueError('secret_key must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='test_bucket_connection',
        )
        headers.update(sdk_headers)

        data = {
            'access_key': access_key,
            'bucket_name': bucket_name,
            'bucket_type': bucket_type,
            'endpoint': endpoint,
            'region': region,
            'secret_key': secret_key,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/test_bucket_connection'
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

    def create_driver_database_catalog(
        self,
        database_display_name: str,
        database_type: str,
        catalog_name: str,
        hostname: str,
        port: str,
        *,
        driver: Optional[BinaryIO] = None,
        driver_content_type: Optional[str] = None,
        driver_file_name: Optional[str] = None,
        certificate: Optional[str] = None,
        certificate_extension: Optional[str] = None,
        ssl: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        database_name: Optional[str] = None,
        description: Optional[str] = None,
        created_on: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Add/Create database with driver.

        Add or create a new database with driver.

        :param str database_display_name: Database display name.
        :param str database_type: Connector type.
        :param str catalog_name: Catalog name.
        :param str hostname: Host name.
        :param str port: Port.
        :param BinaryIO driver: (optional) Driver file to upload.
        :param str driver_content_type: (optional) The content type of driver.
        :param str driver_file_name: (optional) Name of the driver file.
        :param str certificate: (optional) contents of a pem/crt file.
        :param str certificate_extension: (optional) extension of the certificate
               file.
        :param str ssl: (optional) SSL Mode.
        :param str username: (optional) Username.
        :param str password: (optional) Psssword.
        :param str database_name: (optional) Database name.
        :param str description: (optional) Database description.
        :param str created_on: (optional) Created on.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `CreateDriverDatabaseCatalogCreatedBody` object
        """

        if not database_display_name:
            raise ValueError('database_display_name must be provided')
        if not database_type:
            raise ValueError('database_type must be provided')
        if not catalog_name:
            raise ValueError('catalog_name must be provided')
        if not hostname:
            raise ValueError('hostname must be provided')
        if not port:
            raise ValueError('port must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_driver_database_catalog',
        )
        headers.update(sdk_headers)

        form_data = []
        form_data.append(('database_display_name', (None, database_display_name, 'text/plain')))
        form_data.append(('database_type', (None, database_type, 'text/plain')))
        form_data.append(('catalog_name', (None, catalog_name, 'text/plain')))
        form_data.append(('hostname', (None, hostname, 'text/plain')))
        form_data.append(('port', (None, port, 'text/plain')))
        if driver:
            form_data.append(('driver', (None, driver, driver_content_type or 'application/octet-stream')))
        if driver_file_name:
            form_data.append(('driver_file_name', (None, driver_file_name, 'text/plain')))
        if certificate:
            form_data.append(('certificate', (None, certificate, 'text/plain')))
        if certificate_extension:
            form_data.append(('certificate_extension', (None, certificate_extension, 'text/plain')))
        if ssl:
            form_data.append(('ssl', (None, ssl, 'text/plain')))
        if username:
            form_data.append(('username', (None, username, 'text/plain')))
        if password:
            form_data.append(('password', (None, password, 'text/plain')))
        if database_name:
            form_data.append(('database_name', (None, database_name, 'text/plain')))
        if description:
            form_data.append(('description', (None, description, 'text/plain')))
        if created_on:
            form_data.append(('created_on', (None, created_on, 'text/plain')))

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/database_driver_registrations'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            files=form_data,
        )

        response = self.send(request, **kwargs)
        return response

    def list_database_registrations(
        self,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get databases.

        Get list of databases.

        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListDatabaseRegistrationsOKBody` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='list_database_registrations',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/database_registrations'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def create_database_registration(
        self,
        catalog_name: str,
        database_display_name: str,
        database_type: str,
        *,
        created_on: Optional[int] = None,
        database_details: Optional['RegisterDatabaseCatalogBodyDatabaseDetails'] = None,
        database_properties: Optional[List['RegisterDatabaseCatalogBodyDatabasePropertiesItems']] = None,
        description: Optional[str] = None,
        tags: Optional[List[str]] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Add/Create database.

        Add or create a new database.

        :param str catalog_name: Catalog name.
        :param str database_display_name: Database display name.
        :param str database_type: Connector type.
        :param int created_on: (optional) Created on.
        :param RegisterDatabaseCatalogBodyDatabaseDetails database_details:
               (optional) database details.
        :param List[RegisterDatabaseCatalogBodyDatabasePropertiesItems]
               database_properties: (optional) This will hold all the properties for a
               custom database.
        :param str description: (optional) Database description.
        :param List[str] tags: (optional) tags.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `CreateDatabaseRegistrationCreatedBody` object
        """

        if catalog_name is None:
            raise ValueError('catalog_name must be provided')
        if database_display_name is None:
            raise ValueError('database_display_name must be provided')
        if database_type is None:
            raise ValueError('database_type must be provided')
        if database_details is not None:
            database_details = convert_model(database_details)
        if database_properties is not None:
            database_properties = [convert_model(x) for x in database_properties]
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_database_registration',
        )
        headers.update(sdk_headers)

        data = {
            'catalog_name': catalog_name,
            'database_display_name': database_display_name,
            'database_type': database_type,
            'created_on': created_on,
            'database_details': database_details,
            'database_properties': database_properties,
            'description': description,
            'tags': tags,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/database_registrations'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_database(
        self,
        database_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get database.

        Get list of databases.

        :param str database_id: database id.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetDatabaseOKBody` object
        """

        if not database_id:
            raise ValueError('database_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_database',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['database_id']
        path_param_values = self.encode_path_vars(database_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/database_registrations/{database_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_database_catalog(
        self,
        database_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Delete database.

        Delete a database.

        :param str database_id: database id.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not database_id:
            raise ValueError('database_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='delete_database_catalog',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['database_id']
        path_param_values = self.encode_path_vars(database_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/database_registrations/{database_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def update_database(
        self,
        database_id: str,
        body: List['JsonPatchOperation'],
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Update database.

        Update database details.

        :param str database_id: database id.
        :param List[JsonPatchOperation] body: Request body.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `UpdateDatabaseOKBody` object
        """

        if not database_id:
            raise ValueError('database_id must be provided')
        if body is None:
            raise ValueError('body must be provided')
        body = [convert_model(x) for x in body]
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='update_database',
        )
        headers.update(sdk_headers)

        data = json.dumps(body)
        headers['content-type'] = 'application/json-patch+json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['database_id']
        path_param_values = self.encode_path_vars(database_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/database_registrations/{database_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='PATCH',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def validate_database_connection(
        self,
        database_details: 'ValidateDatabaseBodyDatabaseDetails',
        database_type: str,
        *,
        certificate: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Validate database connection.

        API to validate the database connection.

        :param ValidateDatabaseBodyDatabaseDetails database_details: database
               details.
        :param str database_type: Type of db connection.
        :param str certificate: (optional) contents of a pem/crt file.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ValidateDatabaseConnectionOKBody` object
        """

        if database_details is None:
            raise ValueError('database_details must be provided')
        if database_type is None:
            raise ValueError('database_type must be provided')
        database_details = convert_model(database_details)
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='validate_database_connection',
        )
        headers.update(sdk_headers)

        data = {
            'database_details': database_details,
            'database_type': database_type,
            'certificate': certificate,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/test_database_connection'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # engines
    #########################

    def list_db2_engines(
        self,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get list of db2 engines.

        Get list of all db2 engines.

        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListDb2EnginesOKBody` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='list_db2_engines',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/db2_engines'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def create_db2_engine(
        self,
        origin: str,
        type: str,
        *,
        description: Optional[str] = None,
        engine_details: Optional['CreateDb2EngineDetails'] = None,
        engine_display_name: Optional[str] = None,
        tags: Optional[List[str]] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Create db2 engine.

        Create a new db2 engine.

        :param str origin: Origin - created or registered.
        :param str type: Engine type.
        :param str description: (optional) Engine description.
        :param CreateDb2EngineDetails engine_details: (optional) External engine
               details.
        :param str engine_display_name: (optional) Engine display name.
        :param List[str] tags: (optional) Tags.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `CreateDb2EngineCreatedBody` object
        """

        if origin is None:
            raise ValueError('origin must be provided')
        if type is None:
            raise ValueError('type must be provided')
        if engine_details is not None:
            engine_details = convert_model(engine_details)
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_db2_engine',
        )
        headers.update(sdk_headers)

        data = {
            'origin': origin,
            'type': type,
            'description': description,
            'engine_details': engine_details,
            'engine_display_name': engine_display_name,
            'tags': tags,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/db2_engines'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_db2_engine(
        self,
        engine_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Delete db2 engine.

        Delete a db2 engine.

        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='delete_db2_engine',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/db2_engines/{engine_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def update_db2_engine(
        self,
        engine_id: str,
        body: List['JsonPatchOperation'],
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Update db2 engine.

        Update details of db2 engine.

        :param str engine_id: engine id.
        :param List[JsonPatchOperation] body: Update Engine Body.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `UpdateDb2EngineOKBody` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if body is None:
            raise ValueError('body must be provided')
        body = [convert_model(x) for x in body]
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='update_db2_engine',
        )
        headers.update(sdk_headers)

        data = json.dumps(body)
        headers['content-type'] = 'application/json-patch+json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/db2_engines/{engine_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='PATCH',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def list_engines(
        self,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get all engines.

        Get all engine details.

        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListEnginesOKBody` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='list_engines',
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
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get deployments.

        Get list of all deployments.

        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetDeploymentsOKBody` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_deployments',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/instance'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def list_netezza_engines(
        self,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get list of netezza engines.

        Get list of all netezza engines.

        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListNetezzaEnginesOKBody` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='list_netezza_engines',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/netezza_engines'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def create_netezza_engine(
        self,
        origin: str,
        type: str,
        *,
        description: Optional[str] = None,
        engine_details: Optional['CreateNetezzaEngineDetails'] = None,
        engine_display_name: Optional[str] = None,
        tags: Optional[List[str]] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Create netezza engine.

        Create a new netezza engine.

        :param str origin: Origin - created or registered.
        :param str type: Engine type.
        :param str description: (optional) Engine description.
        :param CreateNetezzaEngineDetails engine_details: (optional) External
               engine details.
        :param str engine_display_name: (optional) Engine display name.
        :param List[str] tags: (optional) Tags.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `CreateNetezzaEngineCreatedBody` object
        """

        if origin is None:
            raise ValueError('origin must be provided')
        if type is None:
            raise ValueError('type must be provided')
        if engine_details is not None:
            engine_details = convert_model(engine_details)
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_netezza_engine',
        )
        headers.update(sdk_headers)

        data = {
            'origin': origin,
            'type': type,
            'description': description,
            'engine_details': engine_details,
            'engine_display_name': engine_display_name,
            'tags': tags,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/netezza_engines'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_netezza_engine(
        self,
        engine_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Delete netezza engine.

        Delete a netezza engine.

        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='delete_netezza_engine',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/netezza_engines/{engine_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def update_netezza_engine(
        self,
        engine_id: str,
        body: List['JsonPatchOperation'],
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Update netezza engine.

        Update details of netezza engine.

        :param str engine_id: engine id.
        :param List[JsonPatchOperation] body: Update Engine Body.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `UpdateNetezzaEngineOKBody` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if body is None:
            raise ValueError('body must be provided')
        body = [convert_model(x) for x in body]
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='update_netezza_engine',
        )
        headers.update(sdk_headers)

        data = json.dumps(body)
        headers['content-type'] = 'application/json-patch+json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/netezza_engines/{engine_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='PATCH',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def list_other_engines(
        self,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        List other engines.

        list all other engine details.

        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListOtherEnginesOKBody` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='list_other_engines',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/other_engines'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def create_other_engine(
        self,
        *,
        description: Optional[str] = None,
        engine_details: Optional['OtherEngineDetails'] = None,
        engine_display_name: Optional[str] = None,
        tags: Optional[List[str]] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Create other engine.

        Create a new engine.

        :param str description: (optional) engine description.
        :param OtherEngineDetails engine_details: (optional) External engine
               details.
        :param str engine_display_name: (optional) engine display name.
        :param List[str] tags: (optional) other engine tags.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `CreateOtherEngineCreatedBody` object
        """

        if engine_details is not None:
            engine_details = convert_model(engine_details)
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_other_engine',
        )
        headers.update(sdk_headers)

        data = {
            'description': description,
            'engine_details': engine_details,
            'engine_display_name': engine_display_name,
            'tags': tags,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/other_engines'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_other_engine(
        self,
        engine_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Delete engine.

        Delete an engine from lakehouse.

        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='delete_other_engine',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/other_engines/{engine_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def list_presto_engines(
        self,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get list of presto engines.

        Get list of all presto engines.

        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListPrestoEnginesOKBody` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='list_presto_engines',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/presto_engines'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def create_engine(
        self,
        origin: str,
        type: str,
        *,
        associated_catalogs: Optional[List[str]] = None,
        description: Optional[str] = None,
        engine_details: Optional['EngineDetailsBody'] = None,
        engine_display_name: Optional[str] = None,
        first_time_use: Optional[bool] = None,
        region: Optional[str] = None,
        tags: Optional[List[str]] = None,
        version: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Create presto engine.

        Create a new presto engine.

        :param str origin: Origin - created or registered.
        :param str type: Engine type presto, others like netezza.
        :param List[str] associated_catalogs: (optional) Associated catalogs.
        :param str description: (optional) Engine description.
        :param EngineDetailsBody engine_details: (optional) Node details.
        :param str engine_display_name: (optional) Engine display name.
        :param bool first_time_use: (optional) Optional parameter for UI - set as
               true when first time use.
        :param str region: (optional) Region (cloud).
        :param List[str] tags: (optional) Tags.
        :param str version: (optional) Version like 0.278 for presto or else.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `CreateEngineCreatedBody` object
        """

        if origin is None:
            raise ValueError('origin must be provided')
        if type is None:
            raise ValueError('type must be provided')
        if engine_details is not None:
            engine_details = convert_model(engine_details)
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_engine',
        )
        headers.update(sdk_headers)

        data = {
            'origin': origin,
            'type': type,
            'associated_catalogs': associated_catalogs,
            'description': description,
            'engine_details': engine_details,
            'engine_display_name': engine_display_name,
            'first_time_use': first_time_use,
            'region': region,
            'tags': tags,
            'version': version,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/presto_engines'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_presto_engine(
        self,
        engine_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get presto engine.

        Get details of one presto engine.

        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetPrestoEngineOKBody` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_presto_engine',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/presto_engines/{engine_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_engine(
        self,
        engine_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Delete presto engine.

        Delete a presto engine.

        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='delete_engine',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/presto_engines/{engine_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def update_engine(
        self,
        engine_id: str,
        body: List['JsonPatchOperation'],
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Update presto engine.

        Update details of presto engine.

        :param str engine_id: engine id.
        :param List[JsonPatchOperation] body: Update Engine Body.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `UpdateEngineOKBody` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if body is None:
            raise ValueError('body must be provided')
        body = [convert_model(x) for x in body]
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='update_engine',
        )
        headers.update(sdk_headers)

        data = json.dumps(body)
        headers['content-type'] = 'application/json-patch+json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/presto_engines/{engine_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='PATCH',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def list_presto_engine_catalogs(
        self,
        engine_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get presto engine catalogs.

        Get list of all catalogs attached to a presto engine.

        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListPrestoEngineCatalogsOKBody` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='list_presto_engine_catalogs',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/presto_engines/{engine_id}/catalogs'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def replace_presto_engine_catalogs(
        self,
        engine_id: str,
        catalog_names: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Associate catalogs to presto engine.

        Associate one or more catalogs to a presto engine.

        :param str engine_id: engine id.
        :param str catalog_names: comma separated catalog names.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ReplacePrestoEngineCatalogsCreatedBody` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if not catalog_names:
            raise ValueError('catalog_names must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='replace_presto_engine_catalogs',
        )
        headers.update(sdk_headers)

        params = {
            'catalog_names': catalog_names,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/presto_engines/{engine_id}/catalogs'.format(**path_param_dict)
        request = self.prepare_request(
            method='PUT',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_presto_engine_catalogs(
        self,
        engine_id: str,
        catalog_names: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Disassociate catalogs from a presto engine.

        Disassociate one or more catalogs from a presto engine.

        :param str engine_id: engine id.
        :param str catalog_names: Catalog id(s) to be stopped, comma separated.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if not catalog_names:
            raise ValueError('catalog_names must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='delete_presto_engine_catalogs',
        )
        headers.update(sdk_headers)

        params = {
            'catalog_names': catalog_names,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/presto_engines/{engine_id}/catalogs'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def get_presto_engine_catalog(
        self,
        engine_id: str,
        catalog_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get presto engine catalog.

        Get catalog attached to presto engine.

        :param str engine_id: engine id.
        :param str catalog_id: catalog id.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetPrestoEngineCatalogOKBody` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if not catalog_id:
            raise ValueError('catalog_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_presto_engine_catalog',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id', 'catalog_id']
        path_param_values = self.encode_path_vars(engine_id, catalog_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/presto_engines/{engine_id}/catalogs/{catalog_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def create_engine_pause(
        self,
        engine_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Pause presto engine.

        Pause a running presto engine.

        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `CreateEnginePauseCreatedBody` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_engine_pause',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/presto_engines/{engine_id}/pause'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def run_explain_statement(
        self,
        engine_id: str,
        statement: str,
        *,
        format: Optional[str] = None,
        type: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Explain query.

        Explain a query statement.

        :param str engine_id: Engine id.
        :param str statement: Presto query to determine explain plan.
        :param str format: (optional) Format.
        :param str type: (optional) Type.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `RunExplainStatementOKBody` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if statement is None:
            raise ValueError('statement must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='run_explain_statement',
        )
        headers.update(sdk_headers)

        data = {
            'statement': statement,
            'format': format,
            'type': type,
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
        url = '/presto_engines/{engine_id}/query_explain'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def run_explain_analyze_statement(
        self,
        engine_id: str,
        statement: str,
        *,
        verbose: Optional[bool] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Explain analyze.

        Return query metrics after query is complete.

        :param str engine_id: Engine id.
        :param str statement: Presto query to show explain analyze.
        :param bool verbose: (optional) Verbose.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `RunExplainAnalyzeStatementOKBody` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if statement is None:
            raise ValueError('statement must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='run_explain_analyze_statement',
        )
        headers.update(sdk_headers)

        data = {
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

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/presto_engines/{engine_id}/query_explain_analyze'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def create_engine_restart(
        self,
        engine_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Restart a presto engine.

        Restart an existing presto engine.

        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `CreateEngineRestartCreatedBody` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_engine_restart',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/presto_engines/{engine_id}/restart'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def create_engine_resume(
        self,
        engine_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Resume presto engine.

        Resume a paused presto engine.

        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `CreateEngineResumeCreatedBody` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_engine_resume',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/presto_engines/{engine_id}/resume'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def create_engine_scale(
        self,
        engine_id: str,
        *,
        coordinator: Optional['NodeDescription'] = None,
        worker: Optional['NodeDescription'] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Scale a presto engine.

        Scale an existing presto engine.

        :param str engine_id: engine id.
        :param NodeDescription coordinator: (optional) NodeDescription.
        :param NodeDescription worker: (optional) NodeDescription.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `CreateEngineScaleCreatedBody` object
        """

        if not engine_id:
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
            service_version='V2',
            operation_id='create_engine_scale',
        )
        headers.update(sdk_headers)

        data = {
            'coordinator': coordinator,
            'worker': worker,
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
        url = '/presto_engines/{engine_id}/scale'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def list_spark_engines(
        self,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        List all spark engines.

        List all spark engines.

        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListSparkEnginesOKBody` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='list_spark_engines',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/spark_engines'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def create_spark_engine(
        self,
        origin: str,
        type: str,
        *,
        description: Optional[str] = None,
        engine_details: Optional['SparkEngineDetailsPrototype'] = None,
        engine_display_name: Optional[str] = None,
        tags: Optional[List[str]] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Create spark engine.

        Create a new spark  engine.

        :param str origin: Origin - created or registered.
        :param str type: Engine type spark, others like netezza.
        :param str description: (optional) Engine description.
        :param SparkEngineDetailsPrototype engine_details: (optional) Node details.
        :param str engine_display_name: (optional) Engine display name.
        :param List[str] tags: (optional) Tags.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `CreateSparkEngineCreatedBody` object
        """

        if origin is None:
            raise ValueError('origin must be provided')
        if type is None:
            raise ValueError('type must be provided')
        if engine_details is not None:
            engine_details = convert_model(engine_details)
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_spark_engine',
        )
        headers.update(sdk_headers)

        data = {
            'origin': origin,
            'type': type,
            'description': description,
            'engine_details': engine_details,
            'engine_display_name': engine_display_name,
            'tags': tags,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/spark_engines'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_spark_engine(
        self,
        engine_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Delete spark engine.

        Delete a spark engine.

        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='delete_spark_engine',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/spark_engines/{engine_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def update_spark_engine(
        self,
        engine_id: str,
        body: List['JsonPatchOperation'],
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Update spark engine.

        Update details of spark engine.

        :param str engine_id: engine id.
        :param List[JsonPatchOperation] body: Update Engine Body.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `UpdateSparkEngineOKBody` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if body is None:
            raise ValueError('body must be provided')
        body = [convert_model(x) for x in body]
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='update_spark_engine',
        )
        headers.update(sdk_headers)

        data = json.dumps(body)
        headers['content-type'] = 'application/json-patch+json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/spark_engines/{engine_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='PATCH',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def list_spark_engine_applications(
        self,
        engine_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        List all applications in a spark engine.

        List all applications in a spark engine.

        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListSparkEngineApplicationsOKBody` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='list_spark_engine_applications',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/spark_engines/{engine_id}/applications'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def create_spark_engine_application(
        self,
        engine_id: str,
        application_details: 'SparkApplicationDetails',
        *,
        job_endpoint: Optional[str] = None,
        service_instance_id: Optional[str] = None,
        type: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Submit engine applications.

        Submit engine applications.

        :param str engine_id: engine id.
        :param SparkApplicationDetails application_details: Application details.
        :param str job_endpoint: (optional) Job endpoint.
        :param str service_instance_id: (optional) Service Instance ID for POST.
        :param str type: (optional) Engine Type.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `CreateSparkEngineApplicationCreatedBody` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if application_details is None:
            raise ValueError('application_details must be provided')
        application_details = convert_model(application_details)
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_spark_engine_application',
        )
        headers.update(sdk_headers)

        data = {
            'application_details': application_details,
            'job_endpoint': job_endpoint,
            'service_instance_id': service_instance_id,
            'type': type,
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
        url = '/spark_engines/{engine_id}/applications'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_spark_engine_applications(
        self,
        engine_id: str,
        application_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Stop Spark Applications.

        Stop a running spark application.

        :param str engine_id: engine id.
        :param str application_id: Application id(s) to be stopped, comma
               separated.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if not application_id:
            raise ValueError('application_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='delete_spark_engine_applications',
        )
        headers.update(sdk_headers)

        params = {
            'application_id': application_id,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/spark_engines/{engine_id}/applications'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def get_spark_engine_application_status(
        self,
        engine_id: str,
        application_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get spark application.

        Get status of spark application.

        :param str engine_id: engine id.
        :param str application_id: Application id.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSparkEngineApplicationStatusOKBody` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if not application_id:
            raise ValueError('application_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_spark_engine_application_status',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id', 'application_id']
        path_param_values = self.encode_path_vars(engine_id, application_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/spark_engines/{engine_id}/applications/{application_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
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
            service_version='V2',
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
    # catalogs
    #########################

    def list_catalogs(
        self,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        List all registered catalogs.

        List all registered catalogs.

        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListCatalogsOKBody` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='list_catalogs',
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

    def get_catalog(
        self,
        catalog_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get catalog properties by catalog_id.

        Get catalog properties of a catalog identified by catalog_id.

        :param str catalog_id: catalog ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetCatalogOKBody` object
        """

        if not catalog_id:
            raise ValueError('catalog_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_catalog',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['catalog_id']
        path_param_values = self.encode_path_vars(catalog_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/catalogs/{catalog_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def list_schemas(
        self,
        engine_id: str,
        catalog_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        List all schemas.

        List all schemas in catalog.

        :param str engine_id: Engine name.
        :param str catalog_id: Catalog name.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListSchemasOKBody` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if not catalog_id:
            raise ValueError('catalog_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='list_schemas',
        )
        headers.update(sdk_headers)

        params = {
            'engine_id': engine_id,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['catalog_id']
        path_param_values = self.encode_path_vars(catalog_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/catalogs/{catalog_id}/schemas'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def create_schema(
        self,
        engine_id: str,
        catalog_id: str,
        custom_path: str,
        schema_name: str,
        *,
        bucket_name: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Create schema.

        Create a new schema.

        :param str engine_id: Engine name.
        :param str catalog_id: Catalog name.
        :param str custom_path: Path associated with bucket.
        :param str schema_name: Schema name.
        :param str bucket_name: (optional) Bucket associated to metastore where
               schema will be added.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `CreateSchemaCreatedBody` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if not catalog_id:
            raise ValueError('catalog_id must be provided')
        if custom_path is None:
            raise ValueError('custom_path must be provided')
        if schema_name is None:
            raise ValueError('schema_name must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_schema',
        )
        headers.update(sdk_headers)

        params = {
            'engine_id': engine_id,
        }

        data = {
            'custom_path': custom_path,
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

        path_param_keys = ['catalog_id']
        path_param_values = self.encode_path_vars(catalog_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/catalogs/{catalog_id}/schemas'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            params=params,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_schema(
        self,
        engine_id: str,
        catalog_id: str,
        schema_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Delete schema.

        Delete a schema.

        :param str engine_id: Engine name.
        :param str catalog_id: Catalog name.
        :param str schema_id: URL encoded Schema name.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if not catalog_id:
            raise ValueError('catalog_id must be provided')
        if not schema_id:
            raise ValueError('schema_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='delete_schema',
        )
        headers.update(sdk_headers)

        params = {
            'engine_id': engine_id,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['catalog_id', 'schema_id']
        path_param_values = self.encode_path_vars(catalog_id, schema_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/catalogs/{catalog_id}/schemas/{schema_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def list_tables(
        self,
        catalog_id: str,
        schema_id: str,
        engine_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get tables.

        List all tables in a schema in a catalog for a given engine.

        :param str catalog_id: catalog id.
        :param str schema_id: URL encoded schema name.
        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListTablesOKBody` object
        """

        if not catalog_id:
            raise ValueError('catalog_id must be provided')
        if not schema_id:
            raise ValueError('schema_id must be provided')
        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='list_tables',
        )
        headers.update(sdk_headers)

        params = {
            'engine_id': engine_id,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['catalog_id', 'schema_id']
        path_param_values = self.encode_path_vars(catalog_id, schema_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/catalogs/{catalog_id}/schemas/{schema_id}/tables'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def get_table(
        self,
        catalog_id: str,
        schema_id: str,
        table_id: str,
        engine_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get columns.

        List columns in given catalog/schema and table.

        :param str catalog_id: catalog id.
        :param str schema_id: URL encoded schema name.
        :param str table_id: URL encoded table name.
        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetTableOKBody` object
        """

        if not catalog_id:
            raise ValueError('catalog_id must be provided')
        if not schema_id:
            raise ValueError('schema_id must be provided')
        if not table_id:
            raise ValueError('table_id must be provided')
        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_table',
        )
        headers.update(sdk_headers)

        params = {
            'engine_id': engine_id,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['catalog_id', 'schema_id', 'table_id']
        path_param_values = self.encode_path_vars(catalog_id, schema_id, table_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/catalogs/{catalog_id}/schemas/{schema_id}/tables/{table_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_table(
        self,
        catalog_id: str,
        schema_id: str,
        table_id: str,
        engine_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Delete table.

        Delete one or multiple tables for a given schema and catalog.

        :param str catalog_id: catalog id.
        :param str schema_id: URL encoded schema name.
        :param str table_id: URL encoded table name.
        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not catalog_id:
            raise ValueError('catalog_id must be provided')
        if not schema_id:
            raise ValueError('schema_id must be provided')
        if not table_id:
            raise ValueError('table_id must be provided')
        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='delete_table',
        )
        headers.update(sdk_headers)

        params = {
            'engine_id': engine_id,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['catalog_id', 'schema_id', 'table_id']
        path_param_values = self.encode_path_vars(catalog_id, schema_id, table_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/catalogs/{catalog_id}/schemas/{schema_id}/tables/{table_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def update_table(
        self,
        catalog_id: str,
        schema_id: str,
        table_id: str,
        engine_id: str,
        body: List['JsonPatchOperation'],
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Alter table.

        Update the given table - rename table, add/drop/rename columns.

        :param str catalog_id: catalog id.
        :param str schema_id: URL encoded schema name.
        :param str table_id: URL encoded table name.
        :param str engine_id: engine id.
        :param List[JsonPatchOperation] body: Request body.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `UpdateTableOKBody` object
        """

        if not catalog_id:
            raise ValueError('catalog_id must be provided')
        if not schema_id:
            raise ValueError('schema_id must be provided')
        if not table_id:
            raise ValueError('table_id must be provided')
        if not engine_id:
            raise ValueError('engine_id must be provided')
        if body is None:
            raise ValueError('body must be provided')
        body = [convert_model(x) for x in body]
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='update_table',
        )
        headers.update(sdk_headers)

        params = {
            'engine_id': engine_id,
        }

        data = json.dumps(body)
        headers['content-type'] = 'application/json-patch+json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['catalog_id', 'schema_id', 'table_id']
        path_param_values = self.encode_path_vars(catalog_id, schema_id, table_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/catalogs/{catalog_id}/schemas/{schema_id}/tables/{table_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='PATCH',
            url=url,
            headers=headers,
            params=params,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def list_table_snapshots(
        self,
        engine_id: str,
        catalog_id: str,
        schema_id: str,
        table_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get table snapshots.

        List all table snapshots.

        :param str engine_id: Engine name.
        :param str catalog_id: Catalog ID.
        :param str schema_id: Schema ID.
        :param str table_id: Table ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListTableSnapshotsOKBody` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if not catalog_id:
            raise ValueError('catalog_id must be provided')
        if not schema_id:
            raise ValueError('schema_id must be provided')
        if not table_id:
            raise ValueError('table_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='list_table_snapshots',
        )
        headers.update(sdk_headers)

        params = {
            'engine_id': engine_id,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['catalog_id', 'schema_id', 'table_id']
        path_param_values = self.encode_path_vars(catalog_id, schema_id, table_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/catalogs/{catalog_id}/schemas/{schema_id}/tables/{table_id}/snapshots'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def replace_snapshot(
        self,
        engine_id: str,
        catalog_id: str,
        schema_id: str,
        table_id: str,
        snapshot_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Rollback snapshot.

        Rollback to a table snapshot.

        :param str engine_id: Engine name.
        :param str catalog_id: Catalog ID.
        :param str schema_id: Schema ID.
        :param str table_id: Table ID.
        :param str snapshot_id: Snapshot ID.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ReplaceSnapshotCreatedBody` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if not catalog_id:
            raise ValueError('catalog_id must be provided')
        if not schema_id:
            raise ValueError('schema_id must be provided')
        if not table_id:
            raise ValueError('table_id must be provided')
        if not snapshot_id:
            raise ValueError('snapshot_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='replace_snapshot',
        )
        headers.update(sdk_headers)

        params = {
            'engine_id': engine_id,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['catalog_id', 'schema_id', 'table_id', 'snapshot_id']
        path_param_values = self.encode_path_vars(catalog_id, schema_id, table_id, snapshot_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/catalogs/{catalog_id}/schemas/{schema_id}/tables/{table_id}/snapshots/{snapshot_id}'.format(
            **path_param_dict
        )
        request = self.prepare_request(
            method='PUT',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def update_sync_catalog(
        self,
        catalog_id: str,
        body: List['JsonPatchOperation'],
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        External Iceberg table registration.

        Synchronize the external Iceberg table registration for a catalog identified by
        catalog_id.

        :param str catalog_id: catalog ID.
        :param List[JsonPatchOperation] body: Request body.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `UpdateSyncCatalogOKBody` object
        """

        if not catalog_id:
            raise ValueError('catalog_id must be provided')
        if body is None:
            raise ValueError('body must be provided')
        body = [convert_model(x) for x in body]
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='update_sync_catalog',
        )
        headers.update(sdk_headers)

        data = json.dumps(body)
        headers['content-type'] = 'application/json-patch+json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['catalog_id']
        path_param_values = self.encode_path_vars(catalog_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/catalogs/{catalog_id}/sync'.format(**path_param_dict)
        request = self.prepare_request(
            method='PATCH',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response


##############################################################################
# Models
##############################################################################


class BucketDetails:
    """
    bucket details.

    :param str access_key: (optional) Access key ID, encrypted during bucket
          registration.
    :param str bucket_name: actual bucket name.
    :param str endpoint: (optional) Cos endpoint.
    :param str secret_key: (optional) Secret access key, encrypted during bucket
          registration.
    """

    def __init__(
        self,
        bucket_name: str,
        *,
        access_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        secret_key: Optional[str] = None,
    ) -> None:
        """
        Initialize a BucketDetails object.

        :param str bucket_name: actual bucket name.
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


class BucketRegistration:
    """
    Bucket.

    :param str access_key: (optional) access key.
    :param List[str] actions: (optional) Actions.
    :param List[str] associated_catalogs: Associated catalogs.
    :param str bucket_display_name: (optional) bucket display name.
    :param str bucket_id: (optional) bucket ID auto generated during bucket
          registration.
    :param str bucket_name: actual bucket name.
    :param str bucket_type: Bucket type.
    :param str created_by: Username who created the bucket.
    :param str created_on: Creation date.
    :param str description: bucket description.
    :param str endpoint: bucket endpoint.
    :param str managed_by: managed by.
    :param str region: (optional) Region where the bucket is located.
    :param str secret_key: (optional) secret key.
    :param str state: mark bucket active or inactive.
    :param List[str] tags: Tags.
    """

    def __init__(
        self,
        associated_catalogs: List[str],
        bucket_name: str,
        bucket_type: str,
        created_by: str,
        created_on: str,
        description: str,
        endpoint: str,
        managed_by: str,
        state: str,
        tags: List[str],
        *,
        access_key: Optional[str] = None,
        actions: Optional[List[str]] = None,
        bucket_display_name: Optional[str] = None,
        bucket_id: Optional[str] = None,
        region: Optional[str] = None,
        secret_key: Optional[str] = None,
    ) -> None:
        """
        Initialize a BucketRegistration object.

        :param List[str] associated_catalogs: Associated catalogs.
        :param str bucket_name: actual bucket name.
        :param str bucket_type: Bucket type.
        :param str created_by: Username who created the bucket.
        :param str created_on: Creation date.
        :param str description: bucket description.
        :param str endpoint: bucket endpoint.
        :param str managed_by: managed by.
        :param str state: mark bucket active or inactive.
        :param List[str] tags: Tags.
        :param str access_key: (optional) access key.
        :param List[str] actions: (optional) Actions.
        :param str bucket_display_name: (optional) bucket display name.
        :param str bucket_id: (optional) bucket ID auto generated during bucket
               registration.
        :param str region: (optional) Region where the bucket is located.
        :param str secret_key: (optional) secret key.
        """
        self.access_key = access_key
        self.actions = actions
        self.associated_catalogs = associated_catalogs
        self.bucket_display_name = bucket_display_name
        self.bucket_id = bucket_id
        self.bucket_name = bucket_name
        self.bucket_type = bucket_type
        self.created_by = created_by
        self.created_on = created_on
        self.description = description
        self.endpoint = endpoint
        self.managed_by = managed_by
        self.region = region
        self.secret_key = secret_key
        self.state = state
        self.tags = tags

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'BucketRegistration':
        """Initialize a BucketRegistration object from a json dictionary."""
        args = {}
        if 'access_key' in _dict:
            args['access_key'] = _dict.get('access_key')
        if 'actions' in _dict:
            args['actions'] = _dict.get('actions')
        if 'associated_catalogs' in _dict:
            args['associated_catalogs'] = _dict.get('associated_catalogs')
        else:
            raise ValueError('Required property \'associated_catalogs\' not present in BucketRegistration JSON')
        if 'bucket_display_name' in _dict:
            args['bucket_display_name'] = _dict.get('bucket_display_name')
        if 'bucket_id' in _dict:
            args['bucket_id'] = _dict.get('bucket_id')
        if 'bucket_name' in _dict:
            args['bucket_name'] = _dict.get('bucket_name')
        else:
            raise ValueError('Required property \'bucket_name\' not present in BucketRegistration JSON')
        if 'bucket_type' in _dict:
            args['bucket_type'] = _dict.get('bucket_type')
        else:
            raise ValueError('Required property \'bucket_type\' not present in BucketRegistration JSON')
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        else:
            raise ValueError('Required property \'created_by\' not present in BucketRegistration JSON')
        if 'created_on' in _dict:
            args['created_on'] = _dict.get('created_on')
        else:
            raise ValueError('Required property \'created_on\' not present in BucketRegistration JSON')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        else:
            raise ValueError('Required property \'description\' not present in BucketRegistration JSON')
        if 'endpoint' in _dict:
            args['endpoint'] = _dict.get('endpoint')
        else:
            raise ValueError('Required property \'endpoint\' not present in BucketRegistration JSON')
        if 'managed_by' in _dict:
            args['managed_by'] = _dict.get('managed_by')
        else:
            raise ValueError('Required property \'managed_by\' not present in BucketRegistration JSON')
        if 'region' in _dict:
            args['region'] = _dict.get('region')
        if 'secret_key' in _dict:
            args['secret_key'] = _dict.get('secret_key')
        if 'state' in _dict:
            args['state'] = _dict.get('state')
        else:
            raise ValueError('Required property \'state\' not present in BucketRegistration JSON')
        if 'tags' in _dict:
            args['tags'] = _dict.get('tags')
        else:
            raise ValueError('Required property \'tags\' not present in BucketRegistration JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a BucketRegistration object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'access_key') and self.access_key is not None:
            _dict['access_key'] = self.access_key
        if hasattr(self, 'actions') and self.actions is not None:
            _dict['actions'] = self.actions
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
        if hasattr(self, 'region') and self.region is not None:
            _dict['region'] = self.region
        if hasattr(self, 'secret_key') and self.secret_key is not None:
            _dict['secret_key'] = self.secret_key
        if hasattr(self, 'state') and self.state is not None:
            _dict['state'] = self.state
        if hasattr(self, 'tags') and self.tags is not None:
            _dict['tags'] = self.tags
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this BucketRegistration object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'BucketRegistration') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'BucketRegistration') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class BucketTypeEnum(str, Enum):
        """
        Bucket type.
        """

        AMAZON_S3 = 'amazon_s3'
        AWS_S3 = 'aws_s3'
        MINIO = 'minio'
        IBM_COS = 'ibm_cos'
        IBM_CEPH = 'ibm_ceph'

    class ManagedByEnum(str, Enum):
        """
        managed by.
        """

        IBM = 'ibm'
        CUSTOMER = 'customer'

    class StateEnum(str, Enum):
        """
        mark bucket active or inactive.
        """

        ACTIVE = 'active'
        INACTIVE = 'inactive'


class BucketStatusResponse:
    """
    object defining the response of checking if the credentials of a bucket are valid.

    :param bool state: bucket credentials are valid or not.
    :param str state_message: message response as per the credentials validated.
    """

    def __init__(
        self,
        state: bool,
        state_message: str,
    ) -> None:
        """
        Initialize a BucketStatusResponse object.

        :param bool state: bucket credentials are valid or not.
        :param str state_message: message response as per the credentials
               validated.
        """
        self.state = state
        self.state_message = state_message

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'BucketStatusResponse':
        """Initialize a BucketStatusResponse object from a json dictionary."""
        args = {}
        if 'state' in _dict:
            args['state'] = _dict.get('state')
        else:
            raise ValueError('Required property \'state\' not present in BucketStatusResponse JSON')
        if 'state_message' in _dict:
            args['state_message'] = _dict.get('state_message')
        else:
            raise ValueError('Required property \'state_message\' not present in BucketStatusResponse JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a BucketStatusResponse object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'state') and self.state is not None:
            _dict['state'] = self.state
        if hasattr(self, 'state_message') and self.state_message is not None:
            _dict['state_message'] = self.state_message
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this BucketStatusResponse object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'BucketStatusResponse') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'BucketStatusResponse') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class Catalog:
    """
    EngineCatalog.

    :param str catalog_name: (optional) Name for the catalog.
    :param str creation_date: (optional) Creation date.
    """

    def __init__(
        self,
        *,
        catalog_name: Optional[str] = None,
        creation_date: Optional[str] = None,
    ) -> None:
        """
        Initialize a Catalog object.

        :param str catalog_name: (optional) Name for the catalog.
        :param str creation_date: (optional) Creation date.
        """
        self.catalog_name = catalog_name
        self.creation_date = creation_date

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'Catalog':
        """Initialize a Catalog object from a json dictionary."""
        args = {}
        if 'catalog_name' in _dict:
            args['catalog_name'] = _dict.get('catalog_name')
        if 'creation_date' in _dict:
            args['creation_date'] = _dict.get('creation_date')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a Catalog object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'catalog_name') and self.catalog_name is not None:
            _dict['catalog_name'] = self.catalog_name
        if hasattr(self, 'creation_date') and self.creation_date is not None:
            _dict['creation_date'] = self.creation_date
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this Catalog object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'Catalog') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'Catalog') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CatalogDetail:
    """
    Define the catalog details.

    :param List[str] actions: (optional) list of allowed actions.
    :param List[str] associated_buckets: (optional) Associated buckets items.
    :param List[str] associated_databases: (optional) Associated databases items.
    :param List[str] associated_engines: (optional) Associated engines items.
    :param str catalog_name: (optional) Name for the catalog.
    :param str catalog_type: (optional) Table type.
    :param str created_by: (optional) Created by.
    :param str created_on: (optional) Created on.
    :param str description: (optional) Description.
    :param str hostname: (optional) IBM thrift uri hostname.
    :param str last_sync_at: (optional) Last sync time.
    :param str managed_by: (optional) Managed by.
    :param str metastore: (optional) Catalog name.
    :param str port: (optional) IBM thrift uri port.
    :param str status: (optional) Catalog status.
    :param str sync_description: (optional) Sync description.
    :param List[str] sync_exception: (optional) Tables not sync because data is
          corrupted.
    :param str sync_status: (optional) Sync status.
    :param List[str] tags: (optional) Tags.
    :param str thrift_uri: (optional) Customer thrift uri.
    """

    def __init__(
        self,
        *,
        actions: Optional[List[str]] = None,
        associated_buckets: Optional[List[str]] = None,
        associated_databases: Optional[List[str]] = None,
        associated_engines: Optional[List[str]] = None,
        catalog_name: Optional[str] = None,
        catalog_type: Optional[str] = None,
        created_by: Optional[str] = None,
        created_on: Optional[str] = None,
        description: Optional[str] = None,
        hostname: Optional[str] = None,
        last_sync_at: Optional[str] = None,
        managed_by: Optional[str] = None,
        metastore: Optional[str] = None,
        port: Optional[str] = None,
        status: Optional[str] = None,
        sync_description: Optional[str] = None,
        sync_exception: Optional[List[str]] = None,
        sync_status: Optional[str] = None,
        tags: Optional[List[str]] = None,
        thrift_uri: Optional[str] = None,
    ) -> None:
        """
        Initialize a CatalogDetail object.

        :param List[str] actions: (optional) list of allowed actions.
        :param List[str] associated_buckets: (optional) Associated buckets items.
        :param List[str] associated_databases: (optional) Associated databases
               items.
        :param List[str] associated_engines: (optional) Associated engines items.
        :param str catalog_name: (optional) Name for the catalog.
        :param str catalog_type: (optional) Table type.
        :param str created_by: (optional) Created by.
        :param str created_on: (optional) Created on.
        :param str description: (optional) Description.
        :param str hostname: (optional) IBM thrift uri hostname.
        :param str last_sync_at: (optional) Last sync time.
        :param str managed_by: (optional) Managed by.
        :param str metastore: (optional) Catalog name.
        :param str port: (optional) IBM thrift uri port.
        :param str status: (optional) Catalog status.
        :param str sync_description: (optional) Sync description.
        :param List[str] sync_exception: (optional) Tables not sync because data is
               corrupted.
        :param str sync_status: (optional) Sync status.
        :param List[str] tags: (optional) Tags.
        :param str thrift_uri: (optional) Customer thrift uri.
        """
        self.actions = actions
        self.associated_buckets = associated_buckets
        self.associated_databases = associated_databases
        self.associated_engines = associated_engines
        self.catalog_name = catalog_name
        self.catalog_type = catalog_type
        self.created_by = created_by
        self.created_on = created_on
        self.description = description
        self.hostname = hostname
        self.last_sync_at = last_sync_at
        self.managed_by = managed_by
        self.metastore = metastore
        self.port = port
        self.status = status
        self.sync_description = sync_description
        self.sync_exception = sync_exception
        self.sync_status = sync_status
        self.tags = tags
        self.thrift_uri = thrift_uri

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CatalogDetail':
        """Initialize a CatalogDetail object from a json dictionary."""
        args = {}
        if 'actions' in _dict:
            args['actions'] = _dict.get('actions')
        if 'associated_buckets' in _dict:
            args['associated_buckets'] = _dict.get('associated_buckets')
        if 'associated_databases' in _dict:
            args['associated_databases'] = _dict.get('associated_databases')
        if 'associated_engines' in _dict:
            args['associated_engines'] = _dict.get('associated_engines')
        if 'catalog_name' in _dict:
            args['catalog_name'] = _dict.get('catalog_name')
        if 'catalog_type' in _dict:
            args['catalog_type'] = _dict.get('catalog_type')
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'created_on' in _dict:
            args['created_on'] = _dict.get('created_on')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'hostname' in _dict:
            args['hostname'] = _dict.get('hostname')
        if 'last_sync_at' in _dict:
            args['last_sync_at'] = _dict.get('last_sync_at')
        if 'managed_by' in _dict:
            args['managed_by'] = _dict.get('managed_by')
        if 'metastore' in _dict:
            args['metastore'] = _dict.get('metastore')
        if 'port' in _dict:
            args['port'] = _dict.get('port')
        if 'status' in _dict:
            args['status'] = _dict.get('status')
        if 'sync_description' in _dict:
            args['sync_description'] = _dict.get('sync_description')
        if 'sync_exception' in _dict:
            args['sync_exception'] = _dict.get('sync_exception')
        if 'sync_status' in _dict:
            args['sync_status'] = _dict.get('sync_status')
        if 'tags' in _dict:
            args['tags'] = _dict.get('tags')
        if 'thrift_uri' in _dict:
            args['thrift_uri'] = _dict.get('thrift_uri')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CatalogDetail object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'actions') and self.actions is not None:
            _dict['actions'] = self.actions
        if hasattr(self, 'associated_buckets') and self.associated_buckets is not None:
            _dict['associated_buckets'] = self.associated_buckets
        if hasattr(self, 'associated_databases') and self.associated_databases is not None:
            _dict['associated_databases'] = self.associated_databases
        if hasattr(self, 'associated_engines') and self.associated_engines is not None:
            _dict['associated_engines'] = self.associated_engines
        if hasattr(self, 'catalog_name') and self.catalog_name is not None:
            _dict['catalog_name'] = self.catalog_name
        if hasattr(self, 'catalog_type') and self.catalog_type is not None:
            _dict['catalog_type'] = self.catalog_type
        if hasattr(self, 'created_by') and self.created_by is not None:
            _dict['created_by'] = self.created_by
        if hasattr(self, 'created_on') and self.created_on is not None:
            _dict['created_on'] = self.created_on
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'hostname') and self.hostname is not None:
            _dict['hostname'] = self.hostname
        if hasattr(self, 'last_sync_at') and self.last_sync_at is not None:
            _dict['last_sync_at'] = self.last_sync_at
        if hasattr(self, 'managed_by') and self.managed_by is not None:
            _dict['managed_by'] = self.managed_by
        if hasattr(self, 'metastore') and self.metastore is not None:
            _dict['metastore'] = self.metastore
        if hasattr(self, 'port') and self.port is not None:
            _dict['port'] = self.port
        if hasattr(self, 'status') and self.status is not None:
            _dict['status'] = self.status
        if hasattr(self, 'sync_description') and self.sync_description is not None:
            _dict['sync_description'] = self.sync_description
        if hasattr(self, 'sync_exception') and self.sync_exception is not None:
            _dict['sync_exception'] = self.sync_exception
        if hasattr(self, 'sync_status') and self.sync_status is not None:
            _dict['sync_status'] = self.sync_status
        if hasattr(self, 'tags') and self.tags is not None:
            _dict['tags'] = self.tags
        if hasattr(self, 'thrift_uri') and self.thrift_uri is not None:
            _dict['thrift_uri'] = self.thrift_uri
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CatalogDetail object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CatalogDetail') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CatalogDetail') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class ManagedByEnum(str, Enum):
        """
        Managed by.
        """

        IBM = 'ibm'
        CUSTOMER = 'customer'


class Column:
    """
    Column.

    :param str column_name: (optional) Column name.
    :param str comment: (optional) Comment.
    :param str extra: (optional) Extra.
    :param str type: (optional) Data type.
    """

    def __init__(
        self,
        *,
        column_name: Optional[str] = None,
        comment: Optional[str] = None,
        extra: Optional[str] = None,
        type: Optional[str] = None,
    ) -> None:
        """
        Initialize a Column object.

        :param str column_name: (optional) Column name.
        :param str comment: (optional) Comment.
        :param str extra: (optional) Extra.
        :param str type: (optional) Data type.
        """
        self.column_name = column_name
        self.comment = comment
        self.extra = extra
        self.type = type

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'Column':
        """Initialize a Column object from a json dictionary."""
        args = {}
        if 'column_name' in _dict:
            args['column_name'] = _dict.get('column_name')
        if 'comment' in _dict:
            args['comment'] = _dict.get('comment')
        if 'extra' in _dict:
            args['extra'] = _dict.get('extra')
        if 'type' in _dict:
            args['type'] = _dict.get('type')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a Column object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'column_name') and self.column_name is not None:
            _dict['column_name'] = self.column_name
        if hasattr(self, 'comment') and self.comment is not None:
            _dict['comment'] = self.comment
        if hasattr(self, 'extra') and self.extra is not None:
            _dict['extra'] = self.extra
        if hasattr(self, 'type') and self.type is not None:
            _dict['type'] = self.type
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this Column object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'Column') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'Column') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CreateActivateBucketCreatedBody:
    """
    Activate bucket.

    :param SuccessResponse response: (optional) Response of success.
    """

    def __init__(
        self,
        *,
        response: Optional['SuccessResponse'] = None,
    ) -> None:
        """
        Initialize a CreateActivateBucketCreatedBody object.

        :param SuccessResponse response: (optional) Response of success.
        """
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CreateActivateBucketCreatedBody':
        """Initialize a CreateActivateBucketCreatedBody object from a json dictionary."""
        args = {}
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateActivateBucketCreatedBody object from a json dictionary."""
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
        """Return a `str` version of this CreateActivateBucketCreatedBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CreateActivateBucketCreatedBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CreateActivateBucketCreatedBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CreateBucketRegistrationCreatedBody:
    """
    CreateBucketRegistrations OK.

    :param BucketRegistration bucket_registration: Bucket.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        bucket_registration: 'BucketRegistration',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a CreateBucketRegistrationCreatedBody object.

        :param BucketRegistration bucket_registration: Bucket.
        :param SuccessResponse response: Response of success.
        """
        self.bucket_registration = bucket_registration
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CreateBucketRegistrationCreatedBody':
        """Initialize a CreateBucketRegistrationCreatedBody object from a json dictionary."""
        args = {}
        if 'bucket_registration' in _dict:
            args['bucket_registration'] = BucketRegistration.from_dict(_dict.get('bucket_registration'))
        else:
            raise ValueError(
                'Required property \'bucket_registration\' not present in CreateBucketRegistrationCreatedBody JSON'
            )
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in CreateBucketRegistrationCreatedBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateBucketRegistrationCreatedBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'bucket_registration') and self.bucket_registration is not None:
            if isinstance(self.bucket_registration, dict):
                _dict['bucket_registration'] = self.bucket_registration
            else:
                _dict['bucket_registration'] = self.bucket_registration.to_dict()
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
        """Return a `str` version of this CreateBucketRegistrationCreatedBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CreateBucketRegistrationCreatedBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CreateBucketRegistrationCreatedBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CreateDatabaseRegistrationCreatedBody:
    """
    database register response.

    :param DatabaseRegistration database_registration: database registration object.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        database_registration: 'DatabaseRegistration',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a CreateDatabaseRegistrationCreatedBody object.

        :param DatabaseRegistration database_registration: database registration
               object.
        :param SuccessResponse response: Response of success.
        """
        self.database_registration = database_registration
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CreateDatabaseRegistrationCreatedBody':
        """Initialize a CreateDatabaseRegistrationCreatedBody object from a json dictionary."""
        args = {}
        if 'database_registration' in _dict:
            args['database_registration'] = DatabaseRegistration.from_dict(_dict.get('database_registration'))
        else:
            raise ValueError(
                'Required property \'database_registration\' not present in CreateDatabaseRegistrationCreatedBody JSON'
            )
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in CreateDatabaseRegistrationCreatedBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateDatabaseRegistrationCreatedBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'database_registration') and self.database_registration is not None:
            if isinstance(self.database_registration, dict):
                _dict['database_registration'] = self.database_registration
            else:
                _dict['database_registration'] = self.database_registration.to_dict()
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
        """Return a `str` version of this CreateDatabaseRegistrationCreatedBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CreateDatabaseRegistrationCreatedBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CreateDatabaseRegistrationCreatedBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CreateDb2EngineCreatedBody:
    """
    create engine successful.

    :param Db2Engine engine: Db2 engine details.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        engine: 'Db2Engine',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a CreateDb2EngineCreatedBody object.

        :param Db2Engine engine: Db2 engine details.
        :param SuccessResponse response: Response of success.
        """
        self.engine = engine
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CreateDb2EngineCreatedBody':
        """Initialize a CreateDb2EngineCreatedBody object from a json dictionary."""
        args = {}
        if 'engine' in _dict:
            args['engine'] = Db2Engine.from_dict(_dict.get('engine'))
        else:
            raise ValueError('Required property \'engine\' not present in CreateDb2EngineCreatedBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in CreateDb2EngineCreatedBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateDb2EngineCreatedBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'engine') and self.engine is not None:
            if isinstance(self.engine, dict):
                _dict['engine'] = self.engine
            else:
                _dict['engine'] = self.engine.to_dict()
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
        """Return a `str` version of this CreateDb2EngineCreatedBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CreateDb2EngineCreatedBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CreateDb2EngineCreatedBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CreateDb2EngineDetails:
    """
    External engine details.

    :param str connection_string: (optional) External engine connection string.
    """

    def __init__(
        self,
        *,
        connection_string: Optional[str] = None,
    ) -> None:
        """
        Initialize a CreateDb2EngineDetails object.

        :param str connection_string: (optional) External engine connection string.
        """
        self.connection_string = connection_string

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CreateDb2EngineDetails':
        """Initialize a CreateDb2EngineDetails object from a json dictionary."""
        args = {}
        if 'connection_string' in _dict:
            args['connection_string'] = _dict.get('connection_string')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateDb2EngineDetails object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'connection_string') and self.connection_string is not None:
            _dict['connection_string'] = self.connection_string
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CreateDb2EngineDetails object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CreateDb2EngineDetails') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CreateDb2EngineDetails') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CreateDriverDatabaseCatalogCreatedBody:
    """
    response obj.

    :param CreateDriverDatabaseCatalogCreatedBodyDatabase database: response
          database.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        database: 'CreateDriverDatabaseCatalogCreatedBodyDatabase',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a CreateDriverDatabaseCatalogCreatedBody object.

        :param CreateDriverDatabaseCatalogCreatedBodyDatabase database: response
               database.
        :param SuccessResponse response: Response of success.
        """
        self.database = database
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CreateDriverDatabaseCatalogCreatedBody':
        """Initialize a CreateDriverDatabaseCatalogCreatedBody object from a json dictionary."""
        args = {}
        if 'database' in _dict:
            args['database'] = CreateDriverDatabaseCatalogCreatedBodyDatabase.from_dict(_dict.get('database'))
        else:
            raise ValueError(
                'Required property \'database\' not present in CreateDriverDatabaseCatalogCreatedBody JSON'
            )
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError(
                'Required property \'response\' not present in CreateDriverDatabaseCatalogCreatedBody JSON'
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateDriverDatabaseCatalogCreatedBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'database') and self.database is not None:
            if isinstance(self.database, dict):
                _dict['database'] = self.database
            else:
                _dict['database'] = self.database.to_dict()
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
        """Return a `str` version of this CreateDriverDatabaseCatalogCreatedBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CreateDriverDatabaseCatalogCreatedBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CreateDriverDatabaseCatalogCreatedBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CreateDriverDatabaseCatalogCreatedBodyDatabase:
    """
    response database.

    :param str database_display_name: (optional) Database display name.
    :param str database_id: (optional) Database ID.
    """

    def __init__(
        self,
        *,
        database_display_name: Optional[str] = None,
        database_id: Optional[str] = None,
    ) -> None:
        """
        Initialize a CreateDriverDatabaseCatalogCreatedBodyDatabase object.

        :param str database_display_name: (optional) Database display name.
        :param str database_id: (optional) Database ID.
        """
        self.database_display_name = database_display_name
        self.database_id = database_id

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CreateDriverDatabaseCatalogCreatedBodyDatabase':
        """Initialize a CreateDriverDatabaseCatalogCreatedBodyDatabase object from a json dictionary."""
        args = {}
        if 'database_display_name' in _dict:
            args['database_display_name'] = _dict.get('database_display_name')
        if 'database_id' in _dict:
            args['database_id'] = _dict.get('database_id')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateDriverDatabaseCatalogCreatedBodyDatabase object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'database_display_name') and self.database_display_name is not None:
            _dict['database_display_name'] = self.database_display_name
        if hasattr(self, 'database_id') and self.database_id is not None:
            _dict['database_id'] = self.database_id
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CreateDriverDatabaseCatalogCreatedBodyDatabase object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CreateDriverDatabaseCatalogCreatedBodyDatabase') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CreateDriverDatabaseCatalogCreatedBodyDatabase') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CreateEngineCreatedBody:
    """
    create presto engine successful.

    :param PrestoEngine engine: EngineDetail.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        engine: 'PrestoEngine',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a CreateEngineCreatedBody object.

        :param PrestoEngine engine: EngineDetail.
        :param SuccessResponse response: Response of success.
        """
        self.engine = engine
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CreateEngineCreatedBody':
        """Initialize a CreateEngineCreatedBody object from a json dictionary."""
        args = {}
        if 'engine' in _dict:
            args['engine'] = PrestoEngine.from_dict(_dict.get('engine'))
        else:
            raise ValueError('Required property \'engine\' not present in CreateEngineCreatedBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in CreateEngineCreatedBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateEngineCreatedBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'engine') and self.engine is not None:
            if isinstance(self.engine, dict):
                _dict['engine'] = self.engine
            else:
                _dict['engine'] = self.engine.to_dict()
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
        """Return a `str` version of this CreateEngineCreatedBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CreateEngineCreatedBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CreateEngineCreatedBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CreateEnginePauseCreatedBody:
    """
    Pause.

    :param SuccessResponse response: (optional) Response of success.
    """

    def __init__(
        self,
        *,
        response: Optional['SuccessResponse'] = None,
    ) -> None:
        """
        Initialize a CreateEnginePauseCreatedBody object.

        :param SuccessResponse response: (optional) Response of success.
        """
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CreateEnginePauseCreatedBody':
        """Initialize a CreateEnginePauseCreatedBody object from a json dictionary."""
        args = {}
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateEnginePauseCreatedBody object from a json dictionary."""
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
        """Return a `str` version of this CreateEnginePauseCreatedBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CreateEnginePauseCreatedBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CreateEnginePauseCreatedBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CreateEngineRestartCreatedBody:
    """
    restart engine.

    :param SuccessResponse response: (optional) Response of success.
    """

    def __init__(
        self,
        *,
        response: Optional['SuccessResponse'] = None,
    ) -> None:
        """
        Initialize a CreateEngineRestartCreatedBody object.

        :param SuccessResponse response: (optional) Response of success.
        """
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CreateEngineRestartCreatedBody':
        """Initialize a CreateEngineRestartCreatedBody object from a json dictionary."""
        args = {}
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateEngineRestartCreatedBody object from a json dictionary."""
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
        """Return a `str` version of this CreateEngineRestartCreatedBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CreateEngineRestartCreatedBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CreateEngineRestartCreatedBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CreateEngineResumeCreatedBody:
    """
    resume.

    :param SuccessResponse response: (optional) Response of success.
    """

    def __init__(
        self,
        *,
        response: Optional['SuccessResponse'] = None,
    ) -> None:
        """
        Initialize a CreateEngineResumeCreatedBody object.

        :param SuccessResponse response: (optional) Response of success.
        """
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CreateEngineResumeCreatedBody':
        """Initialize a CreateEngineResumeCreatedBody object from a json dictionary."""
        args = {}
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateEngineResumeCreatedBody object from a json dictionary."""
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
        """Return a `str` version of this CreateEngineResumeCreatedBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CreateEngineResumeCreatedBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CreateEngineResumeCreatedBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CreateEngineScaleCreatedBody:
    """
    scale engine.

    :param SuccessResponse response: (optional) Response of success.
    """

    def __init__(
        self,
        *,
        response: Optional['SuccessResponse'] = None,
    ) -> None:
        """
        Initialize a CreateEngineScaleCreatedBody object.

        :param SuccessResponse response: (optional) Response of success.
        """
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CreateEngineScaleCreatedBody':
        """Initialize a CreateEngineScaleCreatedBody object from a json dictionary."""
        args = {}
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateEngineScaleCreatedBody object from a json dictionary."""
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
        """Return a `str` version of this CreateEngineScaleCreatedBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CreateEngineScaleCreatedBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CreateEngineScaleCreatedBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CreateNetezzaEngineCreatedBody:
    """
    create engine successful.

    :param NetezzaEngine engine: Netezza engine details.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        engine: 'NetezzaEngine',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a CreateNetezzaEngineCreatedBody object.

        :param NetezzaEngine engine: Netezza engine details.
        :param SuccessResponse response: Response of success.
        """
        self.engine = engine
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CreateNetezzaEngineCreatedBody':
        """Initialize a CreateNetezzaEngineCreatedBody object from a json dictionary."""
        args = {}
        if 'engine' in _dict:
            args['engine'] = NetezzaEngine.from_dict(_dict.get('engine'))
        else:
            raise ValueError('Required property \'engine\' not present in CreateNetezzaEngineCreatedBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in CreateNetezzaEngineCreatedBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateNetezzaEngineCreatedBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'engine') and self.engine is not None:
            if isinstance(self.engine, dict):
                _dict['engine'] = self.engine
            else:
                _dict['engine'] = self.engine.to_dict()
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
        """Return a `str` version of this CreateNetezzaEngineCreatedBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CreateNetezzaEngineCreatedBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CreateNetezzaEngineCreatedBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CreateNetezzaEngineDetails:
    """
    External engine details.

    :param str connection_string: (optional) External engine connection string.
    """

    def __init__(
        self,
        *,
        connection_string: Optional[str] = None,
    ) -> None:
        """
        Initialize a CreateNetezzaEngineDetails object.

        :param str connection_string: (optional) External engine connection string.
        """
        self.connection_string = connection_string

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CreateNetezzaEngineDetails':
        """Initialize a CreateNetezzaEngineDetails object from a json dictionary."""
        args = {}
        if 'connection_string' in _dict:
            args['connection_string'] = _dict.get('connection_string')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateNetezzaEngineDetails object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'connection_string') and self.connection_string is not None:
            _dict['connection_string'] = self.connection_string
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CreateNetezzaEngineDetails object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CreateNetezzaEngineDetails') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CreateNetezzaEngineDetails') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CreateOtherEngineCreatedBody:
    """
    create engine successful.

    :param OtherEngine engine: external engine details.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        engine: 'OtherEngine',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a CreateOtherEngineCreatedBody object.

        :param OtherEngine engine: external engine details.
        :param SuccessResponse response: Response of success.
        """
        self.engine = engine
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CreateOtherEngineCreatedBody':
        """Initialize a CreateOtherEngineCreatedBody object from a json dictionary."""
        args = {}
        if 'engine' in _dict:
            args['engine'] = OtherEngine.from_dict(_dict.get('engine'))
        else:
            raise ValueError('Required property \'engine\' not present in CreateOtherEngineCreatedBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in CreateOtherEngineCreatedBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateOtherEngineCreatedBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'engine') and self.engine is not None:
            if isinstance(self.engine, dict):
                _dict['engine'] = self.engine
            else:
                _dict['engine'] = self.engine.to_dict()
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
        """Return a `str` version of this CreateOtherEngineCreatedBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CreateOtherEngineCreatedBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CreateOtherEngineCreatedBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CreateSchemaCreatedBody:
    """
    success response.

    :param SuccessResponse response: (optional) Response of success.
    """

    def __init__(
        self,
        *,
        response: Optional['SuccessResponse'] = None,
    ) -> None:
        """
        Initialize a CreateSchemaCreatedBody object.

        :param SuccessResponse response: (optional) Response of success.
        """
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CreateSchemaCreatedBody':
        """Initialize a CreateSchemaCreatedBody object from a json dictionary."""
        args = {}
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateSchemaCreatedBody object from a json dictionary."""
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
        """Return a `str` version of this CreateSchemaCreatedBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CreateSchemaCreatedBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CreateSchemaCreatedBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CreateSparkEngineApplicationCreatedBody:
    """
    create engine successful.

    :param SuccessResponse response: Response of success.
    :param SparkEngineApplication spark_engine_application:
          EngineSubmitApplicationBody.
    """

    def __init__(
        self,
        response: 'SuccessResponse',
        spark_engine_application: 'SparkEngineApplication',
    ) -> None:
        """
        Initialize a CreateSparkEngineApplicationCreatedBody object.

        :param SuccessResponse response: Response of success.
        :param SparkEngineApplication spark_engine_application:
               EngineSubmitApplicationBody.
        """
        self.response = response
        self.spark_engine_application = spark_engine_application

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CreateSparkEngineApplicationCreatedBody':
        """Initialize a CreateSparkEngineApplicationCreatedBody object from a json dictionary."""
        args = {}
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError(
                'Required property \'response\' not present in CreateSparkEngineApplicationCreatedBody JSON'
            )
        if 'spark_engine_application' in _dict:
            args['spark_engine_application'] = SparkEngineApplication.from_dict(_dict.get('spark_engine_application'))
        else:
            raise ValueError(
                'Required property \'spark_engine_application\' not present in CreateSparkEngineApplicationCreatedBody JSON'
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateSparkEngineApplicationCreatedBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'response') and self.response is not None:
            if isinstance(self.response, dict):
                _dict['response'] = self.response
            else:
                _dict['response'] = self.response.to_dict()
        if hasattr(self, 'spark_engine_application') and self.spark_engine_application is not None:
            if isinstance(self.spark_engine_application, dict):
                _dict['spark_engine_application'] = self.spark_engine_application
            else:
                _dict['spark_engine_application'] = self.spark_engine_application.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CreateSparkEngineApplicationCreatedBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CreateSparkEngineApplicationCreatedBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CreateSparkEngineApplicationCreatedBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CreateSparkEngineCreatedBody:
    """
    Create spark engine successful.

    :param SparkEngine engine: EngineDetail.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        engine: 'SparkEngine',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a CreateSparkEngineCreatedBody object.

        :param SparkEngine engine: EngineDetail.
        :param SuccessResponse response: Response of success.
        """
        self.engine = engine
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CreateSparkEngineCreatedBody':
        """Initialize a CreateSparkEngineCreatedBody object from a json dictionary."""
        args = {}
        if 'engine' in _dict:
            args['engine'] = SparkEngine.from_dict(_dict.get('engine'))
        else:
            raise ValueError('Required property \'engine\' not present in CreateSparkEngineCreatedBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in CreateSparkEngineCreatedBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateSparkEngineCreatedBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'engine') and self.engine is not None:
            if isinstance(self.engine, dict):
                _dict['engine'] = self.engine
            else:
                _dict['engine'] = self.engine.to_dict()
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
        """Return a `str` version of this CreateSparkEngineCreatedBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CreateSparkEngineCreatedBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CreateSparkEngineCreatedBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class DatabaseRegistration:
    """
    database registration object.

    :param List[str] actions: (optional) actions.
    :param List[str] associated_catalogs: (optional) associated catalogs.
    :param str created_by: (optional) Created by.
    :param str created_on: (optional) Created on.
    :param DatabaseRegistrationDatabaseDetails database_details: database details.
    :param str database_display_name: Database display name.
    :param str database_id: (optional) Database ID.
    :param List[str] database_properties: (optional) String containing the property
          key values saved for custom database.
    :param str database_type: Connector type.
    :param str description: (optional) Database description.
    :param List[str] tags: (optional) tags.
    """

    def __init__(
        self,
        database_details: 'DatabaseRegistrationDatabaseDetails',
        database_display_name: str,
        database_type: str,
        *,
        actions: Optional[List[str]] = None,
        associated_catalogs: Optional[List[str]] = None,
        created_by: Optional[str] = None,
        created_on: Optional[str] = None,
        database_id: Optional[str] = None,
        database_properties: Optional[List[str]] = None,
        description: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a DatabaseRegistration object.

        :param DatabaseRegistrationDatabaseDetails database_details: database
               details.
        :param str database_display_name: Database display name.
        :param str database_type: Connector type.
        :param List[str] actions: (optional) actions.
        :param List[str] associated_catalogs: (optional) associated catalogs.
        :param str created_by: (optional) Created by.
        :param str created_on: (optional) Created on.
        :param str database_id: (optional) Database ID.
        :param List[str] database_properties: (optional) String containing the
               property key values saved for custom database.
        :param str description: (optional) Database description.
        :param List[str] tags: (optional) tags.
        """
        self.actions = actions
        self.associated_catalogs = associated_catalogs
        self.created_by = created_by
        self.created_on = created_on
        self.database_details = database_details
        self.database_display_name = database_display_name
        self.database_id = database_id
        self.database_properties = database_properties
        self.database_type = database_type
        self.description = description
        self.tags = tags

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'DatabaseRegistration':
        """Initialize a DatabaseRegistration object from a json dictionary."""
        args = {}
        if 'actions' in _dict:
            args['actions'] = _dict.get('actions')
        if 'associated_catalogs' in _dict:
            args['associated_catalogs'] = _dict.get('associated_catalogs')
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'created_on' in _dict:
            args['created_on'] = _dict.get('created_on')
        if 'database_details' in _dict:
            args['database_details'] = DatabaseRegistrationDatabaseDetails.from_dict(_dict.get('database_details'))
        else:
            raise ValueError('Required property \'database_details\' not present in DatabaseRegistration JSON')
        if 'database_display_name' in _dict:
            args['database_display_name'] = _dict.get('database_display_name')
        else:
            raise ValueError('Required property \'database_display_name\' not present in DatabaseRegistration JSON')
        if 'database_id' in _dict:
            args['database_id'] = _dict.get('database_id')
        if 'database_properties' in _dict:
            args['database_properties'] = _dict.get('database_properties')
        if 'database_type' in _dict:
            args['database_type'] = _dict.get('database_type')
        else:
            raise ValueError('Required property \'database_type\' not present in DatabaseRegistration JSON')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'tags' in _dict:
            args['tags'] = _dict.get('tags')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a DatabaseRegistration object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'actions') and self.actions is not None:
            _dict['actions'] = self.actions
        if hasattr(self, 'associated_catalogs') and self.associated_catalogs is not None:
            _dict['associated_catalogs'] = self.associated_catalogs
        if hasattr(self, 'created_by') and self.created_by is not None:
            _dict['created_by'] = self.created_by
        if hasattr(self, 'created_on') and self.created_on is not None:
            _dict['created_on'] = self.created_on
        if hasattr(self, 'database_details') and self.database_details is not None:
            if isinstance(self.database_details, dict):
                _dict['database_details'] = self.database_details
            else:
                _dict['database_details'] = self.database_details.to_dict()
        if hasattr(self, 'database_display_name') and self.database_display_name is not None:
            _dict['database_display_name'] = self.database_display_name
        if hasattr(self, 'database_id') and self.database_id is not None:
            _dict['database_id'] = self.database_id
        if hasattr(self, 'database_properties') and self.database_properties is not None:
            _dict['database_properties'] = self.database_properties
        if hasattr(self, 'database_type') and self.database_type is not None:
            _dict['database_type'] = self.database_type
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'tags') and self.tags is not None:
            _dict['tags'] = self.tags
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this DatabaseRegistration object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'DatabaseRegistration') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'DatabaseRegistration') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class DatabaseRegistrationDatabaseDetails:
    """
    database details.

    :param str database_name: (optional) Database name.
    :param str hostname: Host name.
    :param str password: (optional) Password.
    :param int port: Port.
    :param bool sasl: (optional) SASL Mode.
    :param bool ssl: (optional) SSL Mode.
    :param str tables: (optional) Only for Kafka - Add kafka tables.
    :param str username: (optional) Username.
    """

    def __init__(
        self,
        hostname: str,
        port: int,
        *,
        database_name: Optional[str] = None,
        password: Optional[str] = None,
        sasl: Optional[bool] = None,
        ssl: Optional[bool] = None,
        tables: Optional[str] = None,
        username: Optional[str] = None,
    ) -> None:
        """
        Initialize a DatabaseRegistrationDatabaseDetails object.

        :param str hostname: Host name.
        :param int port: Port.
        :param str database_name: (optional) Database name.
        :param str password: (optional) Password.
        :param bool sasl: (optional) SASL Mode.
        :param bool ssl: (optional) SSL Mode.
        :param str tables: (optional) Only for Kafka - Add kafka tables.
        :param str username: (optional) Username.
        """
        self.database_name = database_name
        self.hostname = hostname
        self.password = password
        self.port = port
        self.sasl = sasl
        self.ssl = ssl
        self.tables = tables
        self.username = username

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'DatabaseRegistrationDatabaseDetails':
        """Initialize a DatabaseRegistrationDatabaseDetails object from a json dictionary."""
        args = {}
        if 'database_name' in _dict:
            args['database_name'] = _dict.get('database_name')
        if 'hostname' in _dict:
            args['hostname'] = _dict.get('hostname')
        else:
            raise ValueError('Required property \'hostname\' not present in DatabaseRegistrationDatabaseDetails JSON')
        if 'password' in _dict:
            args['password'] = _dict.get('password')
        if 'port' in _dict:
            args['port'] = _dict.get('port')
        else:
            raise ValueError('Required property \'port\' not present in DatabaseRegistrationDatabaseDetails JSON')
        if 'sasl' in _dict:
            args['sasl'] = _dict.get('sasl')
        if 'ssl' in _dict:
            args['ssl'] = _dict.get('ssl')
        if 'tables' in _dict:
            args['tables'] = _dict.get('tables')
        if 'username' in _dict:
            args['username'] = _dict.get('username')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a DatabaseRegistrationDatabaseDetails object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'database_name') and self.database_name is not None:
            _dict['database_name'] = self.database_name
        if hasattr(self, 'hostname') and self.hostname is not None:
            _dict['hostname'] = self.hostname
        if hasattr(self, 'password') and self.password is not None:
            _dict['password'] = self.password
        if hasattr(self, 'port') and self.port is not None:
            _dict['port'] = self.port
        if hasattr(self, 'sasl') and self.sasl is not None:
            _dict['sasl'] = self.sasl
        if hasattr(self, 'ssl') and self.ssl is not None:
            _dict['ssl'] = self.ssl
        if hasattr(self, 'tables') and self.tables is not None:
            _dict['tables'] = self.tables
        if hasattr(self, 'username') and self.username is not None:
            _dict['username'] = self.username
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this DatabaseRegistrationDatabaseDetails object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'DatabaseRegistrationDatabaseDetails') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'DatabaseRegistrationDatabaseDetails') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class Db2Engine:
    """
    Db2 engine details.

    :param List[str] actions: (optional) Actions.
    :param str build_version: (optional) watsonx.data build version.
    :param str created_by: (optional) Created user name.
    :param int created_on: (optional) Created time in epoch format.
    :param str description: (optional) Engine description.
    :param Db2EngineDetails engine_details: (optional) External engine details.
    :param str engine_display_name: (optional) Engine display name.
    :param str engine_id: (optional) Engine programmatic name.
    :param str host_name: (optional) Engine host name. In case of OCP based
          clusters, this is internal hostname.
    :param str origin: (optional) Origin - place holder.
    :param int port: (optional) Engine port.
    :param str status: (optional) Engine status.
    :param List[str] tags: (optional) Tags.
    :param str type: (optional) Engine type.
    """

    def __init__(
        self,
        *,
        actions: Optional[List[str]] = None,
        build_version: Optional[str] = None,
        created_by: Optional[str] = None,
        created_on: Optional[int] = None,
        description: Optional[str] = None,
        engine_details: Optional['Db2EngineDetails'] = None,
        engine_display_name: Optional[str] = None,
        engine_id: Optional[str] = None,
        host_name: Optional[str] = None,
        origin: Optional[str] = None,
        port: Optional[int] = None,
        status: Optional[str] = None,
        tags: Optional[List[str]] = None,
        type: Optional[str] = None,
    ) -> None:
        """
        Initialize a Db2Engine object.

        :param List[str] actions: (optional) Actions.
        :param str build_version: (optional) watsonx.data build version.
        :param str created_by: (optional) Created user name.
        :param int created_on: (optional) Created time in epoch format.
        :param str description: (optional) Engine description.
        :param Db2EngineDetails engine_details: (optional) External engine details.
        :param str engine_display_name: (optional) Engine display name.
        :param str engine_id: (optional) Engine programmatic name.
        :param str host_name: (optional) Engine host name. In case of OCP based
               clusters, this is internal hostname.
        :param str origin: (optional) Origin - place holder.
        :param int port: (optional) Engine port.
        :param str status: (optional) Engine status.
        :param List[str] tags: (optional) Tags.
        :param str type: (optional) Engine type.
        """
        self.actions = actions
        self.build_version = build_version
        self.created_by = created_by
        self.created_on = created_on
        self.description = description
        self.engine_details = engine_details
        self.engine_display_name = engine_display_name
        self.engine_id = engine_id
        self.host_name = host_name
        self.origin = origin
        self.port = port
        self.status = status
        self.tags = tags
        self.type = type

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'Db2Engine':
        """Initialize a Db2Engine object from a json dictionary."""
        args = {}
        if 'actions' in _dict:
            args['actions'] = _dict.get('actions')
        if 'build_version' in _dict:
            args['build_version'] = _dict.get('build_version')
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'created_on' in _dict:
            args['created_on'] = _dict.get('created_on')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'engine_details' in _dict:
            args['engine_details'] = Db2EngineDetails.from_dict(_dict.get('engine_details'))
        if 'engine_display_name' in _dict:
            args['engine_display_name'] = _dict.get('engine_display_name')
        if 'engine_id' in _dict:
            args['engine_id'] = _dict.get('engine_id')
        if 'host_name' in _dict:
            args['host_name'] = _dict.get('host_name')
        if 'origin' in _dict:
            args['origin'] = _dict.get('origin')
        if 'port' in _dict:
            args['port'] = _dict.get('port')
        if 'status' in _dict:
            args['status'] = _dict.get('status')
        if 'tags' in _dict:
            args['tags'] = _dict.get('tags')
        if 'type' in _dict:
            args['type'] = _dict.get('type')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a Db2Engine object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'actions') and self.actions is not None:
            _dict['actions'] = self.actions
        if hasattr(self, 'build_version') and self.build_version is not None:
            _dict['build_version'] = self.build_version
        if hasattr(self, 'created_by') and self.created_by is not None:
            _dict['created_by'] = self.created_by
        if hasattr(self, 'created_on') and self.created_on is not None:
            _dict['created_on'] = self.created_on
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'engine_details') and self.engine_details is not None:
            if isinstance(self.engine_details, dict):
                _dict['engine_details'] = self.engine_details
            else:
                _dict['engine_details'] = self.engine_details.to_dict()
        if hasattr(self, 'engine_display_name') and self.engine_display_name is not None:
            _dict['engine_display_name'] = self.engine_display_name
        if hasattr(self, 'engine_id') and self.engine_id is not None:
            _dict['engine_id'] = self.engine_id
        if hasattr(self, 'host_name') and self.host_name is not None:
            _dict['host_name'] = self.host_name
        if hasattr(self, 'origin') and self.origin is not None:
            _dict['origin'] = self.origin
        if hasattr(self, 'port') and self.port is not None:
            _dict['port'] = self.port
        if hasattr(self, 'status') and self.status is not None:
            _dict['status'] = self.status
        if hasattr(self, 'tags') and self.tags is not None:
            _dict['tags'] = self.tags
        if hasattr(self, 'type') and self.type is not None:
            _dict['type'] = self.type
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this Db2Engine object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'Db2Engine') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'Db2Engine') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class Db2EngineDetails:
    """
    External engine details.

    :param str connection_string: (optional) External engine connection string.
    :param str metastore_host: (optional) Metastore host.
    """

    def __init__(
        self,
        *,
        connection_string: Optional[str] = None,
        metastore_host: Optional[str] = None,
    ) -> None:
        """
        Initialize a Db2EngineDetails object.

        :param str connection_string: (optional) External engine connection string.
        :param str metastore_host: (optional) Metastore host.
        """
        self.connection_string = connection_string
        self.metastore_host = metastore_host

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'Db2EngineDetails':
        """Initialize a Db2EngineDetails object from a json dictionary."""
        args = {}
        if 'connection_string' in _dict:
            args['connection_string'] = _dict.get('connection_string')
        if 'metastore_host' in _dict:
            args['metastore_host'] = _dict.get('metastore_host')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a Db2EngineDetails object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'connection_string') and self.connection_string is not None:
            _dict['connection_string'] = self.connection_string
        if hasattr(self, 'metastore_host') and self.metastore_host is not None:
            _dict['metastore_host'] = self.metastore_host
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this Db2EngineDetails object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'Db2EngineDetails') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'Db2EngineDetails') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class Deployment:
    """
    Deployment.

    :param str cloud_type: (optional) Cloud type.
    :param bool enable_private_endpoints: (optional) Enable private endpoints.
    :param bool enable_public_endpoints: (optional) Enable public endpoints.
    :param bool first_time_use: Parameter for UI to validate if console is used for
          the first time.
    :param str formation_id: (optional) Formation id.
    :param str id: (optional) Id.
    :param str plan_id: (optional) Plan id.
    :param DeploymentPlatformOptions platform_options: (optional) Platform options.
    :param str region: (optional) Region.
    :param str resource_group_crn: (optional) Resource group crn for the formation.
    :param str type: (optional) Type.
    :param str version: (optional) Version.
    """

    def __init__(
        self,
        first_time_use: bool,
        *,
        cloud_type: Optional[str] = None,
        enable_private_endpoints: Optional[bool] = None,
        enable_public_endpoints: Optional[bool] = None,
        formation_id: Optional[str] = None,
        id: Optional[str] = None,
        plan_id: Optional[str] = None,
        platform_options: Optional['DeploymentPlatformOptions'] = None,
        region: Optional[str] = None,
        resource_group_crn: Optional[str] = None,
        type: Optional[str] = None,
        version: Optional[str] = None,
    ) -> None:
        """
        Initialize a Deployment object.

        :param bool first_time_use: Parameter for UI to validate if console is used
               for the first time.
        :param str cloud_type: (optional) Cloud type.
        :param bool enable_private_endpoints: (optional) Enable private endpoints.
        :param bool enable_public_endpoints: (optional) Enable public endpoints.
        :param str formation_id: (optional) Formation id.
        :param str id: (optional) Id.
        :param str plan_id: (optional) Plan id.
        :param DeploymentPlatformOptions platform_options: (optional) Platform
               options.
        :param str region: (optional) Region.
        :param str resource_group_crn: (optional) Resource group crn for the
               formation.
        :param str type: (optional) Type.
        :param str version: (optional) Version.
        """
        self.cloud_type = cloud_type
        self.enable_private_endpoints = enable_private_endpoints
        self.enable_public_endpoints = enable_public_endpoints
        self.first_time_use = first_time_use
        self.formation_id = formation_id
        self.id = id
        self.plan_id = plan_id
        self.platform_options = platform_options
        self.region = region
        self.resource_group_crn = resource_group_crn
        self.type = type
        self.version = version

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'Deployment':
        """Initialize a Deployment object from a json dictionary."""
        args = {}
        if 'cloud_type' in _dict:
            args['cloud_type'] = _dict.get('cloud_type')
        if 'enable_private_endpoints' in _dict:
            args['enable_private_endpoints'] = _dict.get('enable_private_endpoints')
        if 'enable_public_endpoints' in _dict:
            args['enable_public_endpoints'] = _dict.get('enable_public_endpoints')
        if 'first_time_use' in _dict:
            args['first_time_use'] = _dict.get('first_time_use')
        else:
            raise ValueError('Required property \'first_time_use\' not present in Deployment JSON')
        if 'formation_id' in _dict:
            args['formation_id'] = _dict.get('formation_id')
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'plan_id' in _dict:
            args['plan_id'] = _dict.get('plan_id')
        if 'platform_options' in _dict:
            args['platform_options'] = DeploymentPlatformOptions.from_dict(_dict.get('platform_options'))
        if 'region' in _dict:
            args['region'] = _dict.get('region')
        if 'resource_group_crn' in _dict:
            args['resource_group_crn'] = _dict.get('resource_group_crn')
        if 'type' in _dict:
            args['type'] = _dict.get('type')
        if 'version' in _dict:
            args['version'] = _dict.get('version')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a Deployment object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'cloud_type') and self.cloud_type is not None:
            _dict['cloud_type'] = self.cloud_type
        if hasattr(self, 'enable_private_endpoints') and self.enable_private_endpoints is not None:
            _dict['enable_private_endpoints'] = self.enable_private_endpoints
        if hasattr(self, 'enable_public_endpoints') and self.enable_public_endpoints is not None:
            _dict['enable_public_endpoints'] = self.enable_public_endpoints
        if hasattr(self, 'first_time_use') and self.first_time_use is not None:
            _dict['first_time_use'] = self.first_time_use
        if hasattr(self, 'formation_id') and self.formation_id is not None:
            _dict['formation_id'] = self.formation_id
        if hasattr(self, 'id') and self.id is not None:
            _dict['id'] = self.id
        if hasattr(self, 'plan_id') and self.plan_id is not None:
            _dict['plan_id'] = self.plan_id
        if hasattr(self, 'platform_options') and self.platform_options is not None:
            if isinstance(self.platform_options, dict):
                _dict['platform_options'] = self.platform_options
            else:
                _dict['platform_options'] = self.platform_options.to_dict()
        if hasattr(self, 'region') and self.region is not None:
            _dict['region'] = self.region
        if hasattr(self, 'resource_group_crn') and self.resource_group_crn is not None:
            _dict['resource_group_crn'] = self.resource_group_crn
        if hasattr(self, 'type') and self.type is not None:
            _dict['type'] = self.type
        if hasattr(self, 'version') and self.version is not None:
            _dict['version'] = self.version
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this Deployment object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'Deployment') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'Deployment') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class DeploymentPlatformOptions:
    """
    Platform options.

    :param str backup_encryption_key_crn: (optional) Backup encryption key crn.
    :param str disk_encryption_key_crn: (optional) Disk encryption key crn.
    :param str key_protect_key_id: (optional) Key protect key id.
    """

    def __init__(
        self,
        *,
        backup_encryption_key_crn: Optional[str] = None,
        disk_encryption_key_crn: Optional[str] = None,
        key_protect_key_id: Optional[str] = None,
    ) -> None:
        """
        Initialize a DeploymentPlatformOptions object.

        :param str backup_encryption_key_crn: (optional) Backup encryption key crn.
        :param str disk_encryption_key_crn: (optional) Disk encryption key crn.
        :param str key_protect_key_id: (optional) Key protect key id.
        """
        self.backup_encryption_key_crn = backup_encryption_key_crn
        self.disk_encryption_key_crn = disk_encryption_key_crn
        self.key_protect_key_id = key_protect_key_id

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'DeploymentPlatformOptions':
        """Initialize a DeploymentPlatformOptions object from a json dictionary."""
        args = {}
        if 'backup_encryption_key_crn' in _dict:
            args['backup_encryption_key_crn'] = _dict.get('backup_encryption_key_crn')
        if 'disk_encryption_key_crn' in _dict:
            args['disk_encryption_key_crn'] = _dict.get('disk_encryption_key_crn')
        if 'key_protect_key_id' in _dict:
            args['key_protect_key_id'] = _dict.get('key_protect_key_id')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a DeploymentPlatformOptions object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'backup_encryption_key_crn') and self.backup_encryption_key_crn is not None:
            _dict['backup_encryption_key_crn'] = self.backup_encryption_key_crn
        if hasattr(self, 'disk_encryption_key_crn') and self.disk_encryption_key_crn is not None:
            _dict['disk_encryption_key_crn'] = self.disk_encryption_key_crn
        if hasattr(self, 'key_protect_key_id') and self.key_protect_key_id is not None:
            _dict['key_protect_key_id'] = self.key_protect_key_id
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this DeploymentPlatformOptions object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'DeploymentPlatformOptions') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'DeploymentPlatformOptions') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class DeploymentsResponse:
    """
    DeploymentsResponse.

    :param Deployment deployment: (optional) Deployment.
    """

    def __init__(
        self,
        *,
        deployment: Optional['Deployment'] = None,
    ) -> None:
        """
        Initialize a DeploymentsResponse object.

        :param Deployment deployment: (optional) Deployment.
        """
        self.deployment = deployment

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'DeploymentsResponse':
        """Initialize a DeploymentsResponse object from a json dictionary."""
        args = {}
        if 'deployment' in _dict:
            args['deployment'] = Deployment.from_dict(_dict.get('deployment'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a DeploymentsResponse object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'deployment') and self.deployment is not None:
            if isinstance(self.deployment, dict):
                _dict['deployment'] = self.deployment
            else:
                _dict['deployment'] = self.deployment.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this DeploymentsResponse object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'DeploymentsResponse') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'DeploymentsResponse') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class Endpoints:
    """
    Endpoints.

    :param str applications_api: (optional) Application API.
    :param str history_server_endpoint: (optional) History server endpoint.
    :param str spark_access_endpoint: (optional) Spark kernel endpoint.
    :param str spark_jobs_v4_endpoint: (optional) Spark jobs V4 endpoint.
    :param str spark_kernel_endpoint: (optional) Spark kernel endpoint.
    :param str view_history_server: (optional) View history server.
    :param str wxd_application_endpoint: (optional) Wxd application endpoint.
    """

    def __init__(
        self,
        *,
        applications_api: Optional[str] = None,
        history_server_endpoint: Optional[str] = None,
        spark_access_endpoint: Optional[str] = None,
        spark_jobs_v4_endpoint: Optional[str] = None,
        spark_kernel_endpoint: Optional[str] = None,
        view_history_server: Optional[str] = None,
        wxd_application_endpoint: Optional[str] = None,
    ) -> None:
        """
        Initialize a Endpoints object.

        :param str applications_api: (optional) Application API.
        :param str history_server_endpoint: (optional) History server endpoint.
        :param str spark_access_endpoint: (optional) Spark kernel endpoint.
        :param str spark_jobs_v4_endpoint: (optional) Spark jobs V4 endpoint.
        :param str spark_kernel_endpoint: (optional) Spark kernel endpoint.
        :param str view_history_server: (optional) View history server.
        :param str wxd_application_endpoint: (optional) Wxd application endpoint.
        """
        self.applications_api = applications_api
        self.history_server_endpoint = history_server_endpoint
        self.spark_access_endpoint = spark_access_endpoint
        self.spark_jobs_v4_endpoint = spark_jobs_v4_endpoint
        self.spark_kernel_endpoint = spark_kernel_endpoint
        self.view_history_server = view_history_server
        self.wxd_application_endpoint = wxd_application_endpoint

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'Endpoints':
        """Initialize a Endpoints object from a json dictionary."""
        args = {}
        if 'applications_api' in _dict:
            args['applications_api'] = _dict.get('applications_api')
        if 'history_server_endpoint' in _dict:
            args['history_server_endpoint'] = _dict.get('history_server_endpoint')
        if 'spark_access_endpoint' in _dict:
            args['spark_access_endpoint'] = _dict.get('spark_access_endpoint')
        if 'spark_jobs_v4_endpoint' in _dict:
            args['spark_jobs_v4_endpoint'] = _dict.get('spark_jobs_v4_endpoint')
        if 'spark_kernel_endpoint' in _dict:
            args['spark_kernel_endpoint'] = _dict.get('spark_kernel_endpoint')
        if 'view_history_server' in _dict:
            args['view_history_server'] = _dict.get('view_history_server')
        if 'wxd_application_endpoint' in _dict:
            args['wxd_application_endpoint'] = _dict.get('wxd_application_endpoint')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a Endpoints object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'applications_api') and self.applications_api is not None:
            _dict['applications_api'] = self.applications_api
        if hasattr(self, 'history_server_endpoint') and self.history_server_endpoint is not None:
            _dict['history_server_endpoint'] = self.history_server_endpoint
        if hasattr(self, 'spark_access_endpoint') and self.spark_access_endpoint is not None:
            _dict['spark_access_endpoint'] = self.spark_access_endpoint
        if hasattr(self, 'spark_jobs_v4_endpoint') and self.spark_jobs_v4_endpoint is not None:
            _dict['spark_jobs_v4_endpoint'] = self.spark_jobs_v4_endpoint
        if hasattr(self, 'spark_kernel_endpoint') and self.spark_kernel_endpoint is not None:
            _dict['spark_kernel_endpoint'] = self.spark_kernel_endpoint
        if hasattr(self, 'view_history_server') and self.view_history_server is not None:
            _dict['view_history_server'] = self.view_history_server
        if hasattr(self, 'wxd_application_endpoint') and self.wxd_application_endpoint is not None:
            _dict['wxd_application_endpoint'] = self.wxd_application_endpoint
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this Endpoints object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'Endpoints') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'Endpoints') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class Engine:
    """
    All engine details.

    :param List[Db2Engine] db2_engines: (optional) list of db2 engines.
    :param List[MilvusService] milvus_services: (optional) list of milvus engines.
    :param List[NetezzaEngine] netezza_engines: (optional) list of netezza engines.
    :param List[PrestissimoEngine] prestissimo_engines: (optional) list of
          prestissimo engines.
    :param List[PrestoEngine] presto_engines: (optional) list of presto engines.
    :param List[SparkEngine] spark_engines: (optional) list of spark engines.
    """

    def __init__(
        self,
        *,
        db2_engines: Optional[List['Db2Engine']] = None,
        milvus_services: Optional[List['MilvusService']] = None,
        netezza_engines: Optional[List['NetezzaEngine']] = None,
        prestissimo_engines: Optional[List['PrestissimoEngine']] = None,
        presto_engines: Optional[List['PrestoEngine']] = None,
        spark_engines: Optional[List['SparkEngine']] = None,
    ) -> None:
        """
        Initialize a Engine object.

        :param List[Db2Engine] db2_engines: (optional) list of db2 engines.
        :param List[MilvusService] milvus_services: (optional) list of milvus
               engines.
        :param List[NetezzaEngine] netezza_engines: (optional) list of netezza
               engines.
        :param List[PrestissimoEngine] prestissimo_engines: (optional) list of
               prestissimo engines.
        :param List[PrestoEngine] presto_engines: (optional) list of presto
               engines.
        :param List[SparkEngine] spark_engines: (optional) list of spark engines.
        """
        self.db2_engines = db2_engines
        self.milvus_services = milvus_services
        self.netezza_engines = netezza_engines
        self.prestissimo_engines = prestissimo_engines
        self.presto_engines = presto_engines
        self.spark_engines = spark_engines

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'Engine':
        """Initialize a Engine object from a json dictionary."""
        args = {}
        if 'db2_engines' in _dict:
            args['db2_engines'] = [Db2Engine.from_dict(v) for v in _dict.get('db2_engines')]
        if 'milvus_services' in _dict:
            args['milvus_services'] = [MilvusService.from_dict(v) for v in _dict.get('milvus_services')]
        if 'netezza_engines' in _dict:
            args['netezza_engines'] = [NetezzaEngine.from_dict(v) for v in _dict.get('netezza_engines')]
        if 'prestissimo_engines' in _dict:
            args['prestissimo_engines'] = [PrestissimoEngine.from_dict(v) for v in _dict.get('prestissimo_engines')]
        if 'presto_engines' in _dict:
            args['presto_engines'] = [PrestoEngine.from_dict(v) for v in _dict.get('presto_engines')]
        if 'spark_engines' in _dict:
            args['spark_engines'] = [SparkEngine.from_dict(v) for v in _dict.get('spark_engines')]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a Engine object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'db2_engines') and self.db2_engines is not None:
            db2_engines_list = []
            for v in self.db2_engines:
                if isinstance(v, dict):
                    db2_engines_list.append(v)
                else:
                    db2_engines_list.append(v.to_dict())
            _dict['db2_engines'] = db2_engines_list
        if hasattr(self, 'milvus_services') and self.milvus_services is not None:
            milvus_services_list = []
            for v in self.milvus_services:
                if isinstance(v, dict):
                    milvus_services_list.append(v)
                else:
                    milvus_services_list.append(v.to_dict())
            _dict['milvus_services'] = milvus_services_list
        if hasattr(self, 'netezza_engines') and self.netezza_engines is not None:
            netezza_engines_list = []
            for v in self.netezza_engines:
                if isinstance(v, dict):
                    netezza_engines_list.append(v)
                else:
                    netezza_engines_list.append(v.to_dict())
            _dict['netezza_engines'] = netezza_engines_list
        if hasattr(self, 'prestissimo_engines') and self.prestissimo_engines is not None:
            prestissimo_engines_list = []
            for v in self.prestissimo_engines:
                if isinstance(v, dict):
                    prestissimo_engines_list.append(v)
                else:
                    prestissimo_engines_list.append(v.to_dict())
            _dict['prestissimo_engines'] = prestissimo_engines_list
        if hasattr(self, 'presto_engines') and self.presto_engines is not None:
            presto_engines_list = []
            for v in self.presto_engines:
                if isinstance(v, dict):
                    presto_engines_list.append(v)
                else:
                    presto_engines_list.append(v.to_dict())
            _dict['presto_engines'] = presto_engines_list
        if hasattr(self, 'spark_engines') and self.spark_engines is not None:
            spark_engines_list = []
            for v in self.spark_engines:
                if isinstance(v, dict):
                    spark_engines_list.append(v)
                else:
                    spark_engines_list.append(v.to_dict())
            _dict['spark_engines'] = spark_engines_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this Engine object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'Engine') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'Engine') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class EngineDetails:
    """
    External engine details.

    :param str connection_string: (optional) External engine connection string.
    :param Endpoints endpoints: (optional) Endpoints.
    :param str metastore_host: (optional) Metastore host.
    """

    def __init__(
        self,
        *,
        connection_string: Optional[str] = None,
        endpoints: Optional['Endpoints'] = None,
        metastore_host: Optional[str] = None,
    ) -> None:
        """
        Initialize a EngineDetails object.

        :param str connection_string: (optional) External engine connection string.
        :param Endpoints endpoints: (optional) Endpoints.
        :param str metastore_host: (optional) Metastore host.
        """
        self.connection_string = connection_string
        self.endpoints = endpoints
        self.metastore_host = metastore_host

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'EngineDetails':
        """Initialize a EngineDetails object from a json dictionary."""
        args = {}
        if 'connection_string' in _dict:
            args['connection_string'] = _dict.get('connection_string')
        if 'endpoints' in _dict:
            args['endpoints'] = Endpoints.from_dict(_dict.get('endpoints'))
        if 'metastore_host' in _dict:
            args['metastore_host'] = _dict.get('metastore_host')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a EngineDetails object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'connection_string') and self.connection_string is not None:
            _dict['connection_string'] = self.connection_string
        if hasattr(self, 'endpoints') and self.endpoints is not None:
            if isinstance(self.endpoints, dict):
                _dict['endpoints'] = self.endpoints
            else:
                _dict['endpoints'] = self.endpoints.to_dict()
        if hasattr(self, 'metastore_host') and self.metastore_host is not None:
            _dict['metastore_host'] = self.metastore_host
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this EngineDetails object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'EngineDetails') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'EngineDetails') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class EngineDetailsBody:
    """
    Node details.

    :param str api_key: (optional) api key to work with the saas IAE instance.
    :param str connection_string: (optional) External engine connection string.
    :param NodeDescriptionBody coordinator: (optional) Node details.
    :param str instance_id: (optional) Instance to access the instance.
    :param str managed_by: (optional) How is the spark instance managed.
    :param str size_config: (optional) Size config.
    :param NodeDescriptionBody worker: (optional) Node details.
    """

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        connection_string: Optional[str] = None,
        coordinator: Optional['NodeDescriptionBody'] = None,
        instance_id: Optional[str] = None,
        managed_by: Optional[str] = None,
        size_config: Optional[str] = None,
        worker: Optional['NodeDescriptionBody'] = None,
    ) -> None:
        """
        Initialize a EngineDetailsBody object.

        :param str api_key: (optional) api key to work with the saas IAE instance.
        :param str connection_string: (optional) External engine connection string.
        :param NodeDescriptionBody coordinator: (optional) Node details.
        :param str instance_id: (optional) Instance to access the instance.
        :param str managed_by: (optional) How is the spark instance managed.
        :param str size_config: (optional) Size config.
        :param NodeDescriptionBody worker: (optional) Node details.
        """
        self.api_key = api_key
        self.connection_string = connection_string
        self.coordinator = coordinator
        self.instance_id = instance_id
        self.managed_by = managed_by
        self.size_config = size_config
        self.worker = worker

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'EngineDetailsBody':
        """Initialize a EngineDetailsBody object from a json dictionary."""
        args = {}
        if 'api_key' in _dict:
            args['api_key'] = _dict.get('api_key')
        if 'connection_string' in _dict:
            args['connection_string'] = _dict.get('connection_string')
        if 'coordinator' in _dict:
            args['coordinator'] = NodeDescriptionBody.from_dict(_dict.get('coordinator'))
        if 'instance_id' in _dict:
            args['instance_id'] = _dict.get('instance_id')
        if 'managed_by' in _dict:
            args['managed_by'] = _dict.get('managed_by')
        if 'size_config' in _dict:
            args['size_config'] = _dict.get('size_config')
        if 'worker' in _dict:
            args['worker'] = NodeDescriptionBody.from_dict(_dict.get('worker'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a EngineDetailsBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'api_key') and self.api_key is not None:
            _dict['api_key'] = self.api_key
        if hasattr(self, 'connection_string') and self.connection_string is not None:
            _dict['connection_string'] = self.connection_string
        if hasattr(self, 'coordinator') and self.coordinator is not None:
            if isinstance(self.coordinator, dict):
                _dict['coordinator'] = self.coordinator
            else:
                _dict['coordinator'] = self.coordinator.to_dict()
        if hasattr(self, 'instance_id') and self.instance_id is not None:
            _dict['instance_id'] = self.instance_id
        if hasattr(self, 'managed_by') and self.managed_by is not None:
            _dict['managed_by'] = self.managed_by
        if hasattr(self, 'size_config') and self.size_config is not None:
            _dict['size_config'] = self.size_config
        if hasattr(self, 'worker') and self.worker is not None:
            if isinstance(self.worker, dict):
                _dict['worker'] = self.worker
            else:
                _dict['worker'] = self.worker.to_dict()
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
        CACHE_OPTIMIZED = 'cache_optimized'
        COMPUTE_OPTIMIZED = 'compute_optimized'
        SMALL = 'small'
        MEDIUM = 'medium'
        LARGE = 'large'
        CUSTOM = 'custom'


class GetBucketRegistrationOKBody:
    """
    GetBucketRegistration OK.

    :param BucketRegistration bucket_registration: Bucket.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        bucket_registration: 'BucketRegistration',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a GetBucketRegistrationOKBody object.

        :param BucketRegistration bucket_registration: Bucket.
        :param SuccessResponse response: Response of success.
        """
        self.bucket_registration = bucket_registration
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetBucketRegistrationOKBody':
        """Initialize a GetBucketRegistrationOKBody object from a json dictionary."""
        args = {}
        if 'bucket_registration' in _dict:
            args['bucket_registration'] = BucketRegistration.from_dict(_dict.get('bucket_registration'))
        else:
            raise ValueError(
                'Required property \'bucket_registration\' not present in GetBucketRegistrationOKBody JSON'
            )
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in GetBucketRegistrationOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetBucketRegistrationOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'bucket_registration') and self.bucket_registration is not None:
            if isinstance(self.bucket_registration, dict):
                _dict['bucket_registration'] = self.bucket_registration
            else:
                _dict['bucket_registration'] = self.bucket_registration.to_dict()
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
        """Return a `str` version of this GetBucketRegistrationOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetBucketRegistrationOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetBucketRegistrationOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetCatalogOKBody:
    """
    GetCatalog OK.

    :param CatalogDetail catalog: Define the catalog details.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        catalog: 'CatalogDetail',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a GetCatalogOKBody object.

        :param CatalogDetail catalog: Define the catalog details.
        :param SuccessResponse response: Response of success.
        """
        self.catalog = catalog
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetCatalogOKBody':
        """Initialize a GetCatalogOKBody object from a json dictionary."""
        args = {}
        if 'catalog' in _dict:
            args['catalog'] = CatalogDetail.from_dict(_dict.get('catalog'))
        else:
            raise ValueError('Required property \'catalog\' not present in GetCatalogOKBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in GetCatalogOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetCatalogOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'catalog') and self.catalog is not None:
            if isinstance(self.catalog, dict):
                _dict['catalog'] = self.catalog
            else:
                _dict['catalog'] = self.catalog.to_dict()
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
        """Return a `str` version of this GetCatalogOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetCatalogOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetCatalogOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetDatabaseOKBody:
    """
    get databases success response body.

    :param DatabaseRegistration database: database registration object.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        database: 'DatabaseRegistration',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a GetDatabaseOKBody object.

        :param DatabaseRegistration database: database registration object.
        :param SuccessResponse response: Response of success.
        """
        self.database = database
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetDatabaseOKBody':
        """Initialize a GetDatabaseOKBody object from a json dictionary."""
        args = {}
        if 'database' in _dict:
            args['database'] = DatabaseRegistration.from_dict(_dict.get('database'))
        else:
            raise ValueError('Required property \'database\' not present in GetDatabaseOKBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in GetDatabaseOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetDatabaseOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'database') and self.database is not None:
            if isinstance(self.database, dict):
                _dict['database'] = self.database
            else:
                _dict['database'] = self.database.to_dict()
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
        """Return a `str` version of this GetDatabaseOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetDatabaseOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetDatabaseOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetDeploymentsOKBody:
    """
    Response body structure for get deployments.

    :param DeploymentsResponse deploymentresponse: DeploymentsResponse.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        deploymentresponse: 'DeploymentsResponse',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a GetDeploymentsOKBody object.

        :param DeploymentsResponse deploymentresponse: DeploymentsResponse.
        :param SuccessResponse response: Response of success.
        """
        self.deploymentresponse = deploymentresponse
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetDeploymentsOKBody':
        """Initialize a GetDeploymentsOKBody object from a json dictionary."""
        args = {}
        if 'deploymentresponse' in _dict:
            args['deploymentresponse'] = DeploymentsResponse.from_dict(_dict.get('deploymentresponse'))
        else:
            raise ValueError('Required property \'deploymentresponse\' not present in GetDeploymentsOKBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in GetDeploymentsOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetDeploymentsOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'deploymentresponse') and self.deploymentresponse is not None:
            if isinstance(self.deploymentresponse, dict):
                _dict['deploymentresponse'] = self.deploymentresponse
            else:
                _dict['deploymentresponse'] = self.deploymentresponse.to_dict()
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
        """Return a `str` version of this GetDeploymentsOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetDeploymentsOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetDeploymentsOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetPrestoEngineCatalogOKBody:
    """
    getEngineCatalogs OK.

    :param CatalogDetail catalog: Define the catalog details.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        catalog: 'CatalogDetail',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a GetPrestoEngineCatalogOKBody object.

        :param CatalogDetail catalog: Define the catalog details.
        :param SuccessResponse response: Response of success.
        """
        self.catalog = catalog
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetPrestoEngineCatalogOKBody':
        """Initialize a GetPrestoEngineCatalogOKBody object from a json dictionary."""
        args = {}
        if 'catalog' in _dict:
            args['catalog'] = CatalogDetail.from_dict(_dict.get('catalog'))
        else:
            raise ValueError('Required property \'catalog\' not present in GetPrestoEngineCatalogOKBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in GetPrestoEngineCatalogOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetPrestoEngineCatalogOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'catalog') and self.catalog is not None:
            if isinstance(self.catalog, dict):
                _dict['catalog'] = self.catalog
            else:
                _dict['catalog'] = self.catalog.to_dict()
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
        """Return a `str` version of this GetPrestoEngineCatalogOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetPrestoEngineCatalogOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetPrestoEngineCatalogOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetPrestoEngineOKBody:
    """
    get engine.

    :param PrestoEngine engine: EngineDetail.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        engine: 'PrestoEngine',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a GetPrestoEngineOKBody object.

        :param PrestoEngine engine: EngineDetail.
        :param SuccessResponse response: Response of success.
        """
        self.engine = engine
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetPrestoEngineOKBody':
        """Initialize a GetPrestoEngineOKBody object from a json dictionary."""
        args = {}
        if 'engine' in _dict:
            args['engine'] = PrestoEngine.from_dict(_dict.get('engine'))
        else:
            raise ValueError('Required property \'engine\' not present in GetPrestoEngineOKBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in GetPrestoEngineOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetPrestoEngineOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'engine') and self.engine is not None:
            if isinstance(self.engine, dict):
                _dict['engine'] = self.engine
            else:
                _dict['engine'] = self.engine.to_dict()
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
        """Return a `str` version of this GetPrestoEngineOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetPrestoEngineOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetPrestoEngineOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetSparkEngineApplicationStatusOKBody:
    """
    getSparkApplication.

    :param SparkEngineApplicationStatus application: Engine Application Status.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        application: 'SparkEngineApplicationStatus',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a GetSparkEngineApplicationStatusOKBody object.

        :param SparkEngineApplicationStatus application: Engine Application Status.
        :param SuccessResponse response: Response of success.
        """
        self.application = application
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetSparkEngineApplicationStatusOKBody':
        """Initialize a GetSparkEngineApplicationStatusOKBody object from a json dictionary."""
        args = {}
        if 'application' in _dict:
            args['application'] = SparkEngineApplicationStatus.from_dict(_dict.get('application'))
        else:
            raise ValueError(
                'Required property \'application\' not present in GetSparkEngineApplicationStatusOKBody JSON'
            )
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in GetSparkEngineApplicationStatusOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetSparkEngineApplicationStatusOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'application') and self.application is not None:
            if isinstance(self.application, dict):
                _dict['application'] = self.application
            else:
                _dict['application'] = self.application.to_dict()
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
        """Return a `str` version of this GetSparkEngineApplicationStatusOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetSparkEngineApplicationStatusOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetSparkEngineApplicationStatusOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetTableOKBody:
    """
    GetColumns OK.

    :param List[Column] columns: Columns.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        columns: List['Column'],
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a GetTableOKBody object.

        :param List[Column] columns: Columns.
        :param SuccessResponse response: Response of success.
        """
        self.columns = columns
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetTableOKBody':
        """Initialize a GetTableOKBody object from a json dictionary."""
        args = {}
        if 'columns' in _dict:
            args['columns'] = [Column.from_dict(v) for v in _dict.get('columns')]
        else:
            raise ValueError('Required property \'columns\' not present in GetTableOKBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in GetTableOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetTableOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'columns') and self.columns is not None:
            columns_list = []
            for v in self.columns:
                if isinstance(v, dict):
                    columns_list.append(v)
                else:
                    columns_list.append(v.to_dict())
            _dict['columns'] = columns_list
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
        """Return a `str` version of this GetTableOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetTableOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetTableOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class JsonPatchOperation:
    """
    This model represents an individual patch operation to be performed on a JSON
    document, as defined by RFC 6902.

    :param str op: The operation to be performed.
    :param str path: The JSON Pointer that identifies the field that is the target
          of the operation.
    :param str from_: (optional) The JSON Pointer that identifies the field that is
          the source of the operation.
    :param object value: (optional) The value to be used within the operation.
    """

    def __init__(
        self,
        op: str,
        path: str,
        *,
        from_: Optional[str] = None,
        value: Optional[object] = None,
    ) -> None:
        """
        Initialize a JsonPatchOperation object.

        :param str op: The operation to be performed.
        :param str path: The JSON Pointer that identifies the field that is the
               target of the operation.
        :param str from_: (optional) The JSON Pointer that identifies the field
               that is the source of the operation.
        :param object value: (optional) The value to be used within the operation.
        """
        self.op = op
        self.path = path
        self.from_ = from_
        self.value = value

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'JsonPatchOperation':
        """Initialize a JsonPatchOperation object from a json dictionary."""
        args = {}
        if 'op' in _dict:
            args['op'] = _dict.get('op')
        else:
            raise ValueError('Required property \'op\' not present in JsonPatchOperation JSON')
        if 'path' in _dict:
            args['path'] = _dict.get('path')
        else:
            raise ValueError('Required property \'path\' not present in JsonPatchOperation JSON')
        if 'from' in _dict:
            args['from_'] = _dict.get('from')
        if 'value' in _dict:
            args['value'] = _dict.get('value')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a JsonPatchOperation object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'op') and self.op is not None:
            _dict['op'] = self.op
        if hasattr(self, 'path') and self.path is not None:
            _dict['path'] = self.path
        if hasattr(self, 'from_') and self.from_ is not None:
            _dict['from'] = self.from_
        if hasattr(self, 'value') and self.value is not None:
            _dict['value'] = self.value
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this JsonPatchOperation object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'JsonPatchOperation') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'JsonPatchOperation') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class OpEnum(str, Enum):
        """
        The operation to be performed.
        """

        ADD = 'add'
        REMOVE = 'remove'
        REPLACE = 'replace'
        MOVE = 'move'
        COPY = 'copy'
        TEST = 'test'


class ListBucketObjectsOKBody:
    """
    GetBucketObjects OK.

    :param List[str] objects: bucket objects.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        objects: List[str],
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a ListBucketObjectsOKBody object.

        :param List[str] objects: bucket objects.
        :param SuccessResponse response: Response of success.
        """
        self.objects = objects
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ListBucketObjectsOKBody':
        """Initialize a ListBucketObjectsOKBody object from a json dictionary."""
        args = {}
        if 'objects' in _dict:
            args['objects'] = _dict.get('objects')
        else:
            raise ValueError('Required property \'objects\' not present in ListBucketObjectsOKBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in ListBucketObjectsOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListBucketObjectsOKBody object from a json dictionary."""
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
        """Return a `str` version of this ListBucketObjectsOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ListBucketObjectsOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ListBucketObjectsOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ListBucketRegistrationsOKBody:
    """
    GetBucketRegistrations OK.

    :param List[BucketRegistration] bucket_registrations: Buckets.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        bucket_registrations: List['BucketRegistration'],
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a ListBucketRegistrationsOKBody object.

        :param List[BucketRegistration] bucket_registrations: Buckets.
        :param SuccessResponse response: Response of success.
        """
        self.bucket_registrations = bucket_registrations
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ListBucketRegistrationsOKBody':
        """Initialize a ListBucketRegistrationsOKBody object from a json dictionary."""
        args = {}
        if 'bucket_registrations' in _dict:
            args['bucket_registrations'] = [BucketRegistration.from_dict(v) for v in _dict.get('bucket_registrations')]
        else:
            raise ValueError(
                'Required property \'bucket_registrations\' not present in ListBucketRegistrationsOKBody JSON'
            )
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in ListBucketRegistrationsOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListBucketRegistrationsOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'bucket_registrations') and self.bucket_registrations is not None:
            bucket_registrations_list = []
            for v in self.bucket_registrations:
                if isinstance(v, dict):
                    bucket_registrations_list.append(v)
                else:
                    bucket_registrations_list.append(v.to_dict())
            _dict['bucket_registrations'] = bucket_registrations_list
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
        """Return a `str` version of this ListBucketRegistrationsOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ListBucketRegistrationsOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ListBucketRegistrationsOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ListCatalogsOKBody:
    """
    GetCatalogs OK.

    :param List[CatalogDetail] catalogs: Catalogs.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        catalogs: List['CatalogDetail'],
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a ListCatalogsOKBody object.

        :param List[CatalogDetail] catalogs: Catalogs.
        :param SuccessResponse response: Response of success.
        """
        self.catalogs = catalogs
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ListCatalogsOKBody':
        """Initialize a ListCatalogsOKBody object from a json dictionary."""
        args = {}
        if 'catalogs' in _dict:
            args['catalogs'] = [CatalogDetail.from_dict(v) for v in _dict.get('catalogs')]
        else:
            raise ValueError('Required property \'catalogs\' not present in ListCatalogsOKBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in ListCatalogsOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListCatalogsOKBody object from a json dictionary."""
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
        """Return a `str` version of this ListCatalogsOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ListCatalogsOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ListCatalogsOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ListDatabaseRegistrationsOKBody:
    """
    list db api response.

    :param List[DatabaseRegistration] database_registrations: Database body.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        database_registrations: List['DatabaseRegistration'],
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a ListDatabaseRegistrationsOKBody object.

        :param List[DatabaseRegistration] database_registrations: Database body.
        :param SuccessResponse response: Response of success.
        """
        self.database_registrations = database_registrations
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ListDatabaseRegistrationsOKBody':
        """Initialize a ListDatabaseRegistrationsOKBody object from a json dictionary."""
        args = {}
        if 'database_registrations' in _dict:
            args['database_registrations'] = [
                DatabaseRegistration.from_dict(v) for v in _dict.get('database_registrations')
            ]
        else:
            raise ValueError(
                'Required property \'database_registrations\' not present in ListDatabaseRegistrationsOKBody JSON'
            )
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in ListDatabaseRegistrationsOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListDatabaseRegistrationsOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'database_registrations') and self.database_registrations is not None:
            database_registrations_list = []
            for v in self.database_registrations:
                if isinstance(v, dict):
                    database_registrations_list.append(v)
                else:
                    database_registrations_list.append(v.to_dict())
            _dict['database_registrations'] = database_registrations_list
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
        """Return a `str` version of this ListDatabaseRegistrationsOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ListDatabaseRegistrationsOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ListDatabaseRegistrationsOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ListDb2EnginesOKBody:
    """
    list db2 engines.

    :param List[Db2Engine] db2_engines: list db2 engines.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        db2_engines: List['Db2Engine'],
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a ListDb2EnginesOKBody object.

        :param List[Db2Engine] db2_engines: list db2 engines.
        :param SuccessResponse response: Response of success.
        """
        self.db2_engines = db2_engines
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ListDb2EnginesOKBody':
        """Initialize a ListDb2EnginesOKBody object from a json dictionary."""
        args = {}
        if 'db2_engines' in _dict:
            args['db2_engines'] = [Db2Engine.from_dict(v) for v in _dict.get('db2_engines')]
        else:
            raise ValueError('Required property \'db2_engines\' not present in ListDb2EnginesOKBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in ListDb2EnginesOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListDb2EnginesOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'db2_engines') and self.db2_engines is not None:
            db2_engines_list = []
            for v in self.db2_engines:
                if isinstance(v, dict):
                    db2_engines_list.append(v)
                else:
                    db2_engines_list.append(v.to_dict())
            _dict['db2_engines'] = db2_engines_list
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
        """Return a `str` version of this ListDb2EnginesOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ListDb2EnginesOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ListDb2EnginesOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ListEnginesOKBody:
    """
    getEngines.

    :param Engine engines: All engine details.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        engines: 'Engine',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a ListEnginesOKBody object.

        :param Engine engines: All engine details.
        :param SuccessResponse response: Response of success.
        """
        self.engines = engines
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ListEnginesOKBody':
        """Initialize a ListEnginesOKBody object from a json dictionary."""
        args = {}
        if 'engines' in _dict:
            args['engines'] = Engine.from_dict(_dict.get('engines'))
        else:
            raise ValueError('Required property \'engines\' not present in ListEnginesOKBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in ListEnginesOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListEnginesOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'engines') and self.engines is not None:
            if isinstance(self.engines, dict):
                _dict['engines'] = self.engines
            else:
                _dict['engines'] = self.engines.to_dict()
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
        """Return a `str` version of this ListEnginesOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ListEnginesOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ListEnginesOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ListNetezzaEnginesOKBody:
    """
    list netezza engines.

    :param List[NetezzaEngine] netezza_engines: list netezza engines.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        netezza_engines: List['NetezzaEngine'],
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a ListNetezzaEnginesOKBody object.

        :param List[NetezzaEngine] netezza_engines: list netezza engines.
        :param SuccessResponse response: Response of success.
        """
        self.netezza_engines = netezza_engines
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ListNetezzaEnginesOKBody':
        """Initialize a ListNetezzaEnginesOKBody object from a json dictionary."""
        args = {}
        if 'netezza_engines' in _dict:
            args['netezza_engines'] = [NetezzaEngine.from_dict(v) for v in _dict.get('netezza_engines')]
        else:
            raise ValueError('Required property \'netezza_engines\' not present in ListNetezzaEnginesOKBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in ListNetezzaEnginesOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListNetezzaEnginesOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'netezza_engines') and self.netezza_engines is not None:
            netezza_engines_list = []
            for v in self.netezza_engines:
                if isinstance(v, dict):
                    netezza_engines_list.append(v)
                else:
                    netezza_engines_list.append(v.to_dict())
            _dict['netezza_engines'] = netezza_engines_list
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
        """Return a `str` version of this ListNetezzaEnginesOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ListNetezzaEnginesOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ListNetezzaEnginesOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ListOtherEnginesOKBody:
    """
    list other engines.

    :param List[OtherEngine] other_engines: list other engines.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        other_engines: List['OtherEngine'],
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a ListOtherEnginesOKBody object.

        :param List[OtherEngine] other_engines: list other engines.
        :param SuccessResponse response: Response of success.
        """
        self.other_engines = other_engines
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ListOtherEnginesOKBody':
        """Initialize a ListOtherEnginesOKBody object from a json dictionary."""
        args = {}
        if 'other_engines' in _dict:
            args['other_engines'] = [OtherEngine.from_dict(v) for v in _dict.get('other_engines')]
        else:
            raise ValueError('Required property \'other_engines\' not present in ListOtherEnginesOKBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in ListOtherEnginesOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListOtherEnginesOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'other_engines') and self.other_engines is not None:
            other_engines_list = []
            for v in self.other_engines:
                if isinstance(v, dict):
                    other_engines_list.append(v)
                else:
                    other_engines_list.append(v.to_dict())
            _dict['other_engines'] = other_engines_list
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
        """Return a `str` version of this ListOtherEnginesOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ListOtherEnginesOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ListOtherEnginesOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ListPrestoEngineCatalogsOKBody:
    """
    get engine catalogs.

    :param List[Catalog] catalogs: Engine Catalogs.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        catalogs: List['Catalog'],
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a ListPrestoEngineCatalogsOKBody object.

        :param List[Catalog] catalogs: Engine Catalogs.
        :param SuccessResponse response: Response of success.
        """
        self.catalogs = catalogs
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ListPrestoEngineCatalogsOKBody':
        """Initialize a ListPrestoEngineCatalogsOKBody object from a json dictionary."""
        args = {}
        if 'catalogs' in _dict:
            args['catalogs'] = [Catalog.from_dict(v) for v in _dict.get('catalogs')]
        else:
            raise ValueError('Required property \'catalogs\' not present in ListPrestoEngineCatalogsOKBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in ListPrestoEngineCatalogsOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListPrestoEngineCatalogsOKBody object from a json dictionary."""
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
        """Return a `str` version of this ListPrestoEngineCatalogsOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ListPrestoEngineCatalogsOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ListPrestoEngineCatalogsOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ListPrestoEnginesOKBody:
    """
    list Engines.

    :param List[PrestoEngine] presto_engines: list presto engines.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        presto_engines: List['PrestoEngine'],
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a ListPrestoEnginesOKBody object.

        :param List[PrestoEngine] presto_engines: list presto engines.
        :param SuccessResponse response: Response of success.
        """
        self.presto_engines = presto_engines
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ListPrestoEnginesOKBody':
        """Initialize a ListPrestoEnginesOKBody object from a json dictionary."""
        args = {}
        if 'presto_engines' in _dict:
            args['presto_engines'] = [PrestoEngine.from_dict(v) for v in _dict.get('presto_engines')]
        else:
            raise ValueError('Required property \'presto_engines\' not present in ListPrestoEnginesOKBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in ListPrestoEnginesOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListPrestoEnginesOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'presto_engines') and self.presto_engines is not None:
            presto_engines_list = []
            for v in self.presto_engines:
                if isinstance(v, dict):
                    presto_engines_list.append(v)
                else:
                    presto_engines_list.append(v.to_dict())
            _dict['presto_engines'] = presto_engines_list
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
        """Return a `str` version of this ListPrestoEnginesOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ListPrestoEnginesOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ListPrestoEnginesOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ListSchemasOKBody:
    """
    GetSchemas OK.

    :param SuccessResponse response: Response of success.
    :param List[str] schemas: Schemas.
    """

    def __init__(
        self,
        response: 'SuccessResponse',
        schemas: List[str],
    ) -> None:
        """
        Initialize a ListSchemasOKBody object.

        :param SuccessResponse response: Response of success.
        :param List[str] schemas: Schemas.
        """
        self.response = response
        self.schemas = schemas

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ListSchemasOKBody':
        """Initialize a ListSchemasOKBody object from a json dictionary."""
        args = {}
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in ListSchemasOKBody JSON')
        if 'schemas' in _dict:
            args['schemas'] = _dict.get('schemas')
        else:
            raise ValueError('Required property \'schemas\' not present in ListSchemasOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListSchemasOKBody object from a json dictionary."""
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
        """Return a `str` version of this ListSchemasOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ListSchemasOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ListSchemasOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ListSparkEngineApplication:
    """
    Engine Application Detail.

    :param str application_id: (optional) Application ID.
    :param str auto_termination_time: (optional) Auto Termination Time.
    :param str creation_time: (optional) Creation Time.
    :param str end_time: (optional) End Time.
    :param str failed_time: (optional) Failed Time.
    :param str finish_time: (optional) Finish Time.
    :param str id: (optional) Application ID.
    :param ListSparkEngineApplicationRuntime runtime: (optional) application run
          time.
    :param str spark_application_id: (optional) Spark application ID.
    :param str spark_application_name: (optional) Spark application name.
    :param str start_time: (optional) Start Time.
    :param str state: (optional) Application State.
    :param str submission_time: (optional) Application submission time.
    :param str template_id: (optional) Submission Time.
    """

    def __init__(
        self,
        *,
        application_id: Optional[str] = None,
        auto_termination_time: Optional[str] = None,
        creation_time: Optional[str] = None,
        end_time: Optional[str] = None,
        failed_time: Optional[str] = None,
        finish_time: Optional[str] = None,
        id: Optional[str] = None,
        runtime: Optional['ListSparkEngineApplicationRuntime'] = None,
        spark_application_id: Optional[str] = None,
        spark_application_name: Optional[str] = None,
        start_time: Optional[str] = None,
        state: Optional[str] = None,
        submission_time: Optional[str] = None,
        template_id: Optional[str] = None,
    ) -> None:
        """
        Initialize a ListSparkEngineApplication object.

        :param str application_id: (optional) Application ID.
        :param str auto_termination_time: (optional) Auto Termination Time.
        :param str creation_time: (optional) Creation Time.
        :param str end_time: (optional) End Time.
        :param str failed_time: (optional) Failed Time.
        :param str finish_time: (optional) Finish Time.
        :param str id: (optional) Application ID.
        :param ListSparkEngineApplicationRuntime runtime: (optional) application
               run time.
        :param str spark_application_id: (optional) Spark application ID.
        :param str spark_application_name: (optional) Spark application name.
        :param str start_time: (optional) Start Time.
        :param str state: (optional) Application State.
        :param str submission_time: (optional) Application submission time.
        :param str template_id: (optional) Submission Time.
        """
        self.application_id = application_id
        self.auto_termination_time = auto_termination_time
        self.creation_time = creation_time
        self.end_time = end_time
        self.failed_time = failed_time
        self.finish_time = finish_time
        self.id = id
        self.runtime = runtime
        self.spark_application_id = spark_application_id
        self.spark_application_name = spark_application_name
        self.start_time = start_time
        self.state = state
        self.submission_time = submission_time
        self.template_id = template_id

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ListSparkEngineApplication':
        """Initialize a ListSparkEngineApplication object from a json dictionary."""
        args = {}
        if 'application_id' in _dict:
            args['application_id'] = _dict.get('application_id')
        if 'auto_termination_time' in _dict:
            args['auto_termination_time'] = _dict.get('auto_termination_time')
        if 'creation_time' in _dict:
            args['creation_time'] = _dict.get('creation_time')
        if 'end_time' in _dict:
            args['end_time'] = _dict.get('end_time')
        if 'failed_time' in _dict:
            args['failed_time'] = _dict.get('failed_time')
        if 'finish_time' in _dict:
            args['finish_time'] = _dict.get('finish_time')
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'runtime' in _dict:
            args['runtime'] = ListSparkEngineApplicationRuntime.from_dict(_dict.get('runtime'))
        if 'spark_application_id' in _dict:
            args['spark_application_id'] = _dict.get('spark_application_id')
        if 'spark_application_name' in _dict:
            args['spark_application_name'] = _dict.get('spark_application_name')
        if 'start_time' in _dict:
            args['start_time'] = _dict.get('start_time')
        if 'state' in _dict:
            args['state'] = _dict.get('state')
        if 'submission_time' in _dict:
            args['submission_time'] = _dict.get('submission_time')
        if 'template_id' in _dict:
            args['template_id'] = _dict.get('template_id')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListSparkEngineApplication object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'application_id') and self.application_id is not None:
            _dict['application_id'] = self.application_id
        if hasattr(self, 'auto_termination_time') and self.auto_termination_time is not None:
            _dict['auto_termination_time'] = self.auto_termination_time
        if hasattr(self, 'creation_time') and self.creation_time is not None:
            _dict['creation_time'] = self.creation_time
        if hasattr(self, 'end_time') and self.end_time is not None:
            _dict['end_time'] = self.end_time
        if hasattr(self, 'failed_time') and self.failed_time is not None:
            _dict['failed_time'] = self.failed_time
        if hasattr(self, 'finish_time') and self.finish_time is not None:
            _dict['finish_time'] = self.finish_time
        if hasattr(self, 'id') and self.id is not None:
            _dict['id'] = self.id
        if hasattr(self, 'runtime') and self.runtime is not None:
            if isinstance(self.runtime, dict):
                _dict['runtime'] = self.runtime
            else:
                _dict['runtime'] = self.runtime.to_dict()
        if hasattr(self, 'spark_application_id') and self.spark_application_id is not None:
            _dict['spark_application_id'] = self.spark_application_id
        if hasattr(self, 'spark_application_name') and self.spark_application_name is not None:
            _dict['spark_application_name'] = self.spark_application_name
        if hasattr(self, 'start_time') and self.start_time is not None:
            _dict['start_time'] = self.start_time
        if hasattr(self, 'state') and self.state is not None:
            _dict['state'] = self.state
        if hasattr(self, 'submission_time') and self.submission_time is not None:
            _dict['submission_time'] = self.submission_time
        if hasattr(self, 'template_id') and self.template_id is not None:
            _dict['template_id'] = self.template_id
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ListSparkEngineApplication object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ListSparkEngineApplication') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ListSparkEngineApplication') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ListSparkEngineApplicationRuntime:
    """
    application run time.

    :param str spark_version: (optional) Spark Version.
    """

    def __init__(
        self,
        *,
        spark_version: Optional[str] = None,
    ) -> None:
        """
        Initialize a ListSparkEngineApplicationRuntime object.

        :param str spark_version: (optional) Spark Version.
        """
        self.spark_version = spark_version

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ListSparkEngineApplicationRuntime':
        """Initialize a ListSparkEngineApplicationRuntime object from a json dictionary."""
        args = {}
        if 'spark_version' in _dict:
            args['spark_version'] = _dict.get('spark_version')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListSparkEngineApplicationRuntime object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'spark_version') and self.spark_version is not None:
            _dict['spark_version'] = self.spark_version
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ListSparkEngineApplicationRuntime object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ListSparkEngineApplicationRuntime') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ListSparkEngineApplicationRuntime') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ListSparkEngineApplicationsOKBody:
    """
    list Applications.

    :param List[ListSparkEngineApplication] applications: list spark engines.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        applications: List['ListSparkEngineApplication'],
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a ListSparkEngineApplicationsOKBody object.

        :param List[ListSparkEngineApplication] applications: list spark engines.
        :param SuccessResponse response: Response of success.
        """
        self.applications = applications
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ListSparkEngineApplicationsOKBody':
        """Initialize a ListSparkEngineApplicationsOKBody object from a json dictionary."""
        args = {}
        if 'applications' in _dict:
            args['applications'] = [ListSparkEngineApplication.from_dict(v) for v in _dict.get('applications')]
        else:
            raise ValueError('Required property \'applications\' not present in ListSparkEngineApplicationsOKBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in ListSparkEngineApplicationsOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListSparkEngineApplicationsOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'applications') and self.applications is not None:
            applications_list = []
            for v in self.applications:
                if isinstance(v, dict):
                    applications_list.append(v)
                else:
                    applications_list.append(v.to_dict())
            _dict['applications'] = applications_list
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
        """Return a `str` version of this ListSparkEngineApplicationsOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ListSparkEngineApplicationsOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ListSparkEngineApplicationsOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ListSparkEnginesOKBody:
    """
    List spark engines.

    :param SuccessResponse response: Response of success.
    :param List[SparkEngine] spark_engines: List spark engines.
    """

    def __init__(
        self,
        response: 'SuccessResponse',
        spark_engines: List['SparkEngine'],
    ) -> None:
        """
        Initialize a ListSparkEnginesOKBody object.

        :param SuccessResponse response: Response of success.
        :param List[SparkEngine] spark_engines: List spark engines.
        """
        self.response = response
        self.spark_engines = spark_engines

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ListSparkEnginesOKBody':
        """Initialize a ListSparkEnginesOKBody object from a json dictionary."""
        args = {}
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in ListSparkEnginesOKBody JSON')
        if 'spark_engines' in _dict:
            args['spark_engines'] = [SparkEngine.from_dict(v) for v in _dict.get('spark_engines')]
        else:
            raise ValueError('Required property \'spark_engines\' not present in ListSparkEnginesOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListSparkEnginesOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'response') and self.response is not None:
            if isinstance(self.response, dict):
                _dict['response'] = self.response
            else:
                _dict['response'] = self.response.to_dict()
        if hasattr(self, 'spark_engines') and self.spark_engines is not None:
            spark_engines_list = []
            for v in self.spark_engines:
                if isinstance(v, dict):
                    spark_engines_list.append(v)
                else:
                    spark_engines_list.append(v.to_dict())
            _dict['spark_engines'] = spark_engines_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ListSparkEnginesOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ListSparkEnginesOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ListSparkEnginesOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ListTableSnapshotsOKBody:
    """
    TableSnapshot OK.

    :param SuccessResponse response: Response of success.
    :param List[TableSnapshot] snapshots: Snapshots.
    """

    def __init__(
        self,
        response: 'SuccessResponse',
        snapshots: List['TableSnapshot'],
    ) -> None:
        """
        Initialize a ListTableSnapshotsOKBody object.

        :param SuccessResponse response: Response of success.
        :param List[TableSnapshot] snapshots: Snapshots.
        """
        self.response = response
        self.snapshots = snapshots

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ListTableSnapshotsOKBody':
        """Initialize a ListTableSnapshotsOKBody object from a json dictionary."""
        args = {}
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in ListTableSnapshotsOKBody JSON')
        if 'snapshots' in _dict:
            args['snapshots'] = [TableSnapshot.from_dict(v) for v in _dict.get('snapshots')]
        else:
            raise ValueError('Required property \'snapshots\' not present in ListTableSnapshotsOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListTableSnapshotsOKBody object from a json dictionary."""
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
        """Return a `str` version of this ListTableSnapshotsOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ListTableSnapshotsOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ListTableSnapshotsOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ListTablesOKBody:
    """
    GetTables OK.

    :param SuccessResponse response: Response of success.
    :param List[str] tables: List of the tables present in the schema.
    """

    def __init__(
        self,
        response: 'SuccessResponse',
        tables: List[str],
    ) -> None:
        """
        Initialize a ListTablesOKBody object.

        :param SuccessResponse response: Response of success.
        :param List[str] tables: List of the tables present in the schema.
        """
        self.response = response
        self.tables = tables

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ListTablesOKBody':
        """Initialize a ListTablesOKBody object from a json dictionary."""
        args = {}
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in ListTablesOKBody JSON')
        if 'tables' in _dict:
            args['tables'] = _dict.get('tables')
        else:
            raise ValueError('Required property \'tables\' not present in ListTablesOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListTablesOKBody object from a json dictionary."""
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
        """Return a `str` version of this ListTablesOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ListTablesOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ListTablesOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class MilvusService:
    """
    milvus service details.

    :param List[str] actions: (optional) Actions.
    :param str created_by: (optional) Created user name.
    :param int created_on: (optional) Created time in epoch format.
    :param str description: (optional) Service description.
    :param int grpc_port: (optional) milvus port.
    :param str host_name: (optional) milvus display name.
    :param int https_port: (optional) milvus port.
    :param str origin: (optional) Origin - place holder.
    :param str service_display_name: (optional) Service display name.
    :param str service_id: (optional) Service programmatic name.
    :param str status: (optional) milvus status.
    :param int status_code: milvus status code.
    :param List[str] tags: (optional) Tags.
    :param str type: (optional) service type.
    """

    def __init__(
        self,
        status_code: int,
        *,
        actions: Optional[List[str]] = None,
        created_by: Optional[str] = None,
        created_on: Optional[int] = None,
        description: Optional[str] = None,
        grpc_port: Optional[int] = None,
        host_name: Optional[str] = None,
        https_port: Optional[int] = None,
        origin: Optional[str] = None,
        service_display_name: Optional[str] = None,
        service_id: Optional[str] = None,
        status: Optional[str] = None,
        tags: Optional[List[str]] = None,
        type: Optional[str] = None,
    ) -> None:
        """
        Initialize a MilvusService object.

        :param int status_code: milvus status code.
        :param List[str] actions: (optional) Actions.
        :param str created_by: (optional) Created user name.
        :param int created_on: (optional) Created time in epoch format.
        :param str description: (optional) Service description.
        :param int grpc_port: (optional) milvus port.
        :param str host_name: (optional) milvus display name.
        :param int https_port: (optional) milvus port.
        :param str origin: (optional) Origin - place holder.
        :param str service_display_name: (optional) Service display name.
        :param str service_id: (optional) Service programmatic name.
        :param str status: (optional) milvus status.
        :param List[str] tags: (optional) Tags.
        :param str type: (optional) service type.
        """
        self.actions = actions
        self.created_by = created_by
        self.created_on = created_on
        self.description = description
        self.grpc_port = grpc_port
        self.host_name = host_name
        self.https_port = https_port
        self.origin = origin
        self.service_display_name = service_display_name
        self.service_id = service_id
        self.status = status
        self.status_code = status_code
        self.tags = tags
        self.type = type

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'MilvusService':
        """Initialize a MilvusService object from a json dictionary."""
        args = {}
        if 'actions' in _dict:
            args['actions'] = _dict.get('actions')
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'created_on' in _dict:
            args['created_on'] = _dict.get('created_on')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'grpc_port' in _dict:
            args['grpc_port'] = _dict.get('grpc_port')
        if 'host_name' in _dict:
            args['host_name'] = _dict.get('host_name')
        if 'https_port' in _dict:
            args['https_port'] = _dict.get('https_port')
        if 'origin' in _dict:
            args['origin'] = _dict.get('origin')
        if 'service_display_name' in _dict:
            args['service_display_name'] = _dict.get('service_display_name')
        if 'service_id' in _dict:
            args['service_id'] = _dict.get('service_id')
        if 'status' in _dict:
            args['status'] = _dict.get('status')
        if 'status_code' in _dict:
            args['status_code'] = _dict.get('status_code')
        else:
            raise ValueError('Required property \'status_code\' not present in MilvusService JSON')
        if 'tags' in _dict:
            args['tags'] = _dict.get('tags')
        if 'type' in _dict:
            args['type'] = _dict.get('type')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a MilvusService object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'actions') and self.actions is not None:
            _dict['actions'] = self.actions
        if hasattr(self, 'created_by') and self.created_by is not None:
            _dict['created_by'] = self.created_by
        if hasattr(self, 'created_on') and self.created_on is not None:
            _dict['created_on'] = self.created_on
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'grpc_port') and self.grpc_port is not None:
            _dict['grpc_port'] = self.grpc_port
        if hasattr(self, 'host_name') and self.host_name is not None:
            _dict['host_name'] = self.host_name
        if hasattr(self, 'https_port') and self.https_port is not None:
            _dict['https_port'] = self.https_port
        if hasattr(self, 'origin') and self.origin is not None:
            _dict['origin'] = self.origin
        if hasattr(self, 'service_display_name') and self.service_display_name is not None:
            _dict['service_display_name'] = self.service_display_name
        if hasattr(self, 'service_id') and self.service_id is not None:
            _dict['service_id'] = self.service_id
        if hasattr(self, 'status') and self.status is not None:
            _dict['status'] = self.status
        if hasattr(self, 'status_code') and self.status_code is not None:
            _dict['status_code'] = self.status_code
        if hasattr(self, 'tags') and self.tags is not None:
            _dict['tags'] = self.tags
        if hasattr(self, 'type') and self.type is not None:
            _dict['type'] = self.type
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this MilvusService object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'MilvusService') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'MilvusService') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class StatusEnum(str, Enum):
        """
        milvus status.
        """

        RUNNING = 'running'
        PENDING = 'pending'
        STOPPED = 'stopped'


class NetezzaEngine:
    """
    Netezza engine details.

    :param List[str] actions: (optional) Actions.
    :param str build_version: (optional) watsonx.data build version.
    :param str created_by: (optional) Created user name.
    :param int created_on: (optional) Created time in epoch format.
    :param str description: (optional) Engine description.
    :param NetezzaEngineDetails engine_details: (optional) External engine details.
    :param str engine_display_name: (optional) Engine display name.
    :param str engine_id: (optional) Engine programmatic name.
    :param str host_name: (optional) Engine host name. In case of OCP based
          clusters, this is internal hostname.
    :param str origin: (optional) Origin - place holder.
    :param int port: (optional) Engine port.
    :param str status: (optional) Engine status.
    :param List[str] tags: (optional) Tags.
    :param str type: (optional) Engine type.
    """

    def __init__(
        self,
        *,
        actions: Optional[List[str]] = None,
        build_version: Optional[str] = None,
        created_by: Optional[str] = None,
        created_on: Optional[int] = None,
        description: Optional[str] = None,
        engine_details: Optional['NetezzaEngineDetails'] = None,
        engine_display_name: Optional[str] = None,
        engine_id: Optional[str] = None,
        host_name: Optional[str] = None,
        origin: Optional[str] = None,
        port: Optional[int] = None,
        status: Optional[str] = None,
        tags: Optional[List[str]] = None,
        type: Optional[str] = None,
    ) -> None:
        """
        Initialize a NetezzaEngine object.

        :param List[str] actions: (optional) Actions.
        :param str build_version: (optional) watsonx.data build version.
        :param str created_by: (optional) Created user name.
        :param int created_on: (optional) Created time in epoch format.
        :param str description: (optional) Engine description.
        :param NetezzaEngineDetails engine_details: (optional) External engine
               details.
        :param str engine_display_name: (optional) Engine display name.
        :param str engine_id: (optional) Engine programmatic name.
        :param str host_name: (optional) Engine host name. In case of OCP based
               clusters, this is internal hostname.
        :param str origin: (optional) Origin - place holder.
        :param int port: (optional) Engine port.
        :param str status: (optional) Engine status.
        :param List[str] tags: (optional) Tags.
        :param str type: (optional) Engine type.
        """
        self.actions = actions
        self.build_version = build_version
        self.created_by = created_by
        self.created_on = created_on
        self.description = description
        self.engine_details = engine_details
        self.engine_display_name = engine_display_name
        self.engine_id = engine_id
        self.host_name = host_name
        self.origin = origin
        self.port = port
        self.status = status
        self.tags = tags
        self.type = type

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'NetezzaEngine':
        """Initialize a NetezzaEngine object from a json dictionary."""
        args = {}
        if 'actions' in _dict:
            args['actions'] = _dict.get('actions')
        if 'build_version' in _dict:
            args['build_version'] = _dict.get('build_version')
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'created_on' in _dict:
            args['created_on'] = _dict.get('created_on')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'engine_details' in _dict:
            args['engine_details'] = NetezzaEngineDetails.from_dict(_dict.get('engine_details'))
        if 'engine_display_name' in _dict:
            args['engine_display_name'] = _dict.get('engine_display_name')
        if 'engine_id' in _dict:
            args['engine_id'] = _dict.get('engine_id')
        if 'host_name' in _dict:
            args['host_name'] = _dict.get('host_name')
        if 'origin' in _dict:
            args['origin'] = _dict.get('origin')
        if 'port' in _dict:
            args['port'] = _dict.get('port')
        if 'status' in _dict:
            args['status'] = _dict.get('status')
        if 'tags' in _dict:
            args['tags'] = _dict.get('tags')
        if 'type' in _dict:
            args['type'] = _dict.get('type')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a NetezzaEngine object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'actions') and self.actions is not None:
            _dict['actions'] = self.actions
        if hasattr(self, 'build_version') and self.build_version is not None:
            _dict['build_version'] = self.build_version
        if hasattr(self, 'created_by') and self.created_by is not None:
            _dict['created_by'] = self.created_by
        if hasattr(self, 'created_on') and self.created_on is not None:
            _dict['created_on'] = self.created_on
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'engine_details') and self.engine_details is not None:
            if isinstance(self.engine_details, dict):
                _dict['engine_details'] = self.engine_details
            else:
                _dict['engine_details'] = self.engine_details.to_dict()
        if hasattr(self, 'engine_display_name') and self.engine_display_name is not None:
            _dict['engine_display_name'] = self.engine_display_name
        if hasattr(self, 'engine_id') and self.engine_id is not None:
            _dict['engine_id'] = self.engine_id
        if hasattr(self, 'host_name') and self.host_name is not None:
            _dict['host_name'] = self.host_name
        if hasattr(self, 'origin') and self.origin is not None:
            _dict['origin'] = self.origin
        if hasattr(self, 'port') and self.port is not None:
            _dict['port'] = self.port
        if hasattr(self, 'status') and self.status is not None:
            _dict['status'] = self.status
        if hasattr(self, 'tags') and self.tags is not None:
            _dict['tags'] = self.tags
        if hasattr(self, 'type') and self.type is not None:
            _dict['type'] = self.type
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this NetezzaEngine object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'NetezzaEngine') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'NetezzaEngine') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class NetezzaEngineDetails:
    """
    External engine details.

    :param str connection_string: (optional) External engine connection string.
    :param str metastore_host: (optional) Metastore host.
    """

    def __init__(
        self,
        *,
        connection_string: Optional[str] = None,
        metastore_host: Optional[str] = None,
    ) -> None:
        """
        Initialize a NetezzaEngineDetails object.

        :param str connection_string: (optional) External engine connection string.
        :param str metastore_host: (optional) Metastore host.
        """
        self.connection_string = connection_string
        self.metastore_host = metastore_host

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'NetezzaEngineDetails':
        """Initialize a NetezzaEngineDetails object from a json dictionary."""
        args = {}
        if 'connection_string' in _dict:
            args['connection_string'] = _dict.get('connection_string')
        if 'metastore_host' in _dict:
            args['metastore_host'] = _dict.get('metastore_host')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a NetezzaEngineDetails object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'connection_string') and self.connection_string is not None:
            _dict['connection_string'] = self.connection_string
        if hasattr(self, 'metastore_host') and self.metastore_host is not None:
            _dict['metastore_host'] = self.metastore_host
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this NetezzaEngineDetails object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'NetezzaEngineDetails') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'NetezzaEngineDetails') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class NodeDescription:
    """
    NodeDescription.

    :param str node_type: (optional) Node type.
    :param int quantity: (optional) Quantity.
    """

    def __init__(
        self,
        *,
        node_type: Optional[str] = None,
        quantity: Optional[int] = None,
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

    :param str node_type: (optional) Node Type, r5, m, i..
    :param int quantity: (optional) Number of nodes.
    """

    def __init__(
        self,
        *,
        node_type: Optional[str] = None,
        quantity: Optional[int] = None,
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


class OtherEngine:
    """
    external engine details.

    :param str created_by: (optional) created user name.
    :param int created_on: (optional) created time in epoch format.
    :param str description: (optional) engine description.
    :param OtherEngineDetails engine_details: (optional) External engine details.
    :param str engine_display_name: (optional) Engine display name.
    :param str engine_id: (optional) engine programmatic name.
    :param str origin: (optional) origin.
    :param str status: (optional) engine status.
    :param int status_code: (optional) engine status code.
    :param List[str] tags: (optional) Tags.
    :param str type: (optional) Type like presto, netezza, external,..
    """

    def __init__(
        self,
        *,
        created_by: Optional[str] = None,
        created_on: Optional[int] = None,
        description: Optional[str] = None,
        engine_details: Optional['OtherEngineDetails'] = None,
        engine_display_name: Optional[str] = None,
        engine_id: Optional[str] = None,
        origin: Optional[str] = None,
        status: Optional[str] = None,
        status_code: Optional[int] = None,
        tags: Optional[List[str]] = None,
        type: Optional[str] = None,
    ) -> None:
        """
        Initialize a OtherEngine object.

        :param str created_by: (optional) created user name.
        :param int created_on: (optional) created time in epoch format.
        :param str description: (optional) engine description.
        :param OtherEngineDetails engine_details: (optional) External engine
               details.
        :param str engine_display_name: (optional) Engine display name.
        :param str engine_id: (optional) engine programmatic name.
        :param str origin: (optional) origin.
        :param str status: (optional) engine status.
        :param int status_code: (optional) engine status code.
        :param List[str] tags: (optional) Tags.
        :param str type: (optional) Type like presto, netezza, external,..
        """
        self.created_by = created_by
        self.created_on = created_on
        self.description = description
        self.engine_details = engine_details
        self.engine_display_name = engine_display_name
        self.engine_id = engine_id
        self.origin = origin
        self.status = status
        self.status_code = status_code
        self.tags = tags
        self.type = type

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'OtherEngine':
        """Initialize a OtherEngine object from a json dictionary."""
        args = {}
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'created_on' in _dict:
            args['created_on'] = _dict.get('created_on')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'engine_details' in _dict:
            args['engine_details'] = OtherEngineDetails.from_dict(_dict.get('engine_details'))
        if 'engine_display_name' in _dict:
            args['engine_display_name'] = _dict.get('engine_display_name')
        if 'engine_id' in _dict:
            args['engine_id'] = _dict.get('engine_id')
        if 'origin' in _dict:
            args['origin'] = _dict.get('origin')
        if 'status' in _dict:
            args['status'] = _dict.get('status')
        if 'status_code' in _dict:
            args['status_code'] = _dict.get('status_code')
        if 'tags' in _dict:
            args['tags'] = _dict.get('tags')
        if 'type' in _dict:
            args['type'] = _dict.get('type')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a OtherEngine object from a json dictionary."""
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
        if hasattr(self, 'engine_details') and self.engine_details is not None:
            if isinstance(self.engine_details, dict):
                _dict['engine_details'] = self.engine_details
            else:
                _dict['engine_details'] = self.engine_details.to_dict()
        if hasattr(self, 'engine_display_name') and self.engine_display_name is not None:
            _dict['engine_display_name'] = self.engine_display_name
        if hasattr(self, 'engine_id') and self.engine_id is not None:
            _dict['engine_id'] = self.engine_id
        if hasattr(self, 'origin') and self.origin is not None:
            _dict['origin'] = self.origin
        if hasattr(self, 'status') and self.status is not None:
            _dict['status'] = self.status
        if hasattr(self, 'status_code') and self.status_code is not None:
            _dict['status_code'] = self.status_code
        if hasattr(self, 'tags') and self.tags is not None:
            _dict['tags'] = self.tags
        if hasattr(self, 'type') and self.type is not None:
            _dict['type'] = self.type
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this OtherEngine object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'OtherEngine') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'OtherEngine') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class OtherEngineDetails:
    """
    External engine details.

    :param str connection_string: (optional) external engine connection string.
    :param str engine_type: (optional) Actual engine type.
    :param str metastore_host: (optional) metastore host.
    """

    def __init__(
        self,
        *,
        connection_string: Optional[str] = None,
        engine_type: Optional[str] = None,
        metastore_host: Optional[str] = None,
    ) -> None:
        """
        Initialize a OtherEngineDetails object.

        :param str connection_string: (optional) external engine connection string.
        :param str engine_type: (optional) Actual engine type.
        :param str metastore_host: (optional) metastore host.
        """
        self.connection_string = connection_string
        self.engine_type = engine_type
        self.metastore_host = metastore_host

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'OtherEngineDetails':
        """Initialize a OtherEngineDetails object from a json dictionary."""
        args = {}
        if 'connection_string' in _dict:
            args['connection_string'] = _dict.get('connection_string')
        if 'engine_type' in _dict:
            args['engine_type'] = _dict.get('engine_type')
        if 'metastore_host' in _dict:
            args['metastore_host'] = _dict.get('metastore_host')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a OtherEngineDetails object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'connection_string') and self.connection_string is not None:
            _dict['connection_string'] = self.connection_string
        if hasattr(self, 'engine_type') and self.engine_type is not None:
            _dict['engine_type'] = self.engine_type
        if hasattr(self, 'metastore_host') and self.metastore_host is not None:
            _dict['metastore_host'] = self.metastore_host
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this OtherEngineDetails object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'OtherEngineDetails') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'OtherEngineDetails') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class PrestissimoEndpoints:
    """
    Endpoints.

    :param str applications_api: (optional) Application API.
    :param str history_server_endpoint: (optional) History server endpoint.
    :param str spark_access_endpoint: (optional) Spark kernel endpoint.
    :param str spark_jobs_v4_endpoint: (optional) Spark jobs V4 endpoint.
    :param str spark_kernel_endpoint: (optional) Spark kernel endpoint.
    :param str view_history_server: (optional) View history server.
    :param str wxd_application_endpoint: (optional) Wxd application endpoint.
    """

    def __init__(
        self,
        *,
        applications_api: Optional[str] = None,
        history_server_endpoint: Optional[str] = None,
        spark_access_endpoint: Optional[str] = None,
        spark_jobs_v4_endpoint: Optional[str] = None,
        spark_kernel_endpoint: Optional[str] = None,
        view_history_server: Optional[str] = None,
        wxd_application_endpoint: Optional[str] = None,
    ) -> None:
        """
        Initialize a PrestissimoEndpoints object.

        :param str applications_api: (optional) Application API.
        :param str history_server_endpoint: (optional) History server endpoint.
        :param str spark_access_endpoint: (optional) Spark kernel endpoint.
        :param str spark_jobs_v4_endpoint: (optional) Spark jobs V4 endpoint.
        :param str spark_kernel_endpoint: (optional) Spark kernel endpoint.
        :param str view_history_server: (optional) View history server.
        :param str wxd_application_endpoint: (optional) Wxd application endpoint.
        """
        self.applications_api = applications_api
        self.history_server_endpoint = history_server_endpoint
        self.spark_access_endpoint = spark_access_endpoint
        self.spark_jobs_v4_endpoint = spark_jobs_v4_endpoint
        self.spark_kernel_endpoint = spark_kernel_endpoint
        self.view_history_server = view_history_server
        self.wxd_application_endpoint = wxd_application_endpoint

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrestissimoEndpoints':
        """Initialize a PrestissimoEndpoints object from a json dictionary."""
        args = {}
        if 'applications_api' in _dict:
            args['applications_api'] = _dict.get('applications_api')
        if 'history_server_endpoint' in _dict:
            args['history_server_endpoint'] = _dict.get('history_server_endpoint')
        if 'spark_access_endpoint' in _dict:
            args['spark_access_endpoint'] = _dict.get('spark_access_endpoint')
        if 'spark_jobs_v4_endpoint' in _dict:
            args['spark_jobs_v4_endpoint'] = _dict.get('spark_jobs_v4_endpoint')
        if 'spark_kernel_endpoint' in _dict:
            args['spark_kernel_endpoint'] = _dict.get('spark_kernel_endpoint')
        if 'view_history_server' in _dict:
            args['view_history_server'] = _dict.get('view_history_server')
        if 'wxd_application_endpoint' in _dict:
            args['wxd_application_endpoint'] = _dict.get('wxd_application_endpoint')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrestissimoEndpoints object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'applications_api') and self.applications_api is not None:
            _dict['applications_api'] = self.applications_api
        if hasattr(self, 'history_server_endpoint') and self.history_server_endpoint is not None:
            _dict['history_server_endpoint'] = self.history_server_endpoint
        if hasattr(self, 'spark_access_endpoint') and self.spark_access_endpoint is not None:
            _dict['spark_access_endpoint'] = self.spark_access_endpoint
        if hasattr(self, 'spark_jobs_v4_endpoint') and self.spark_jobs_v4_endpoint is not None:
            _dict['spark_jobs_v4_endpoint'] = self.spark_jobs_v4_endpoint
        if hasattr(self, 'spark_kernel_endpoint') and self.spark_kernel_endpoint is not None:
            _dict['spark_kernel_endpoint'] = self.spark_kernel_endpoint
        if hasattr(self, 'view_history_server') and self.view_history_server is not None:
            _dict['view_history_server'] = self.view_history_server
        if hasattr(self, 'wxd_application_endpoint') and self.wxd_application_endpoint is not None:
            _dict['wxd_application_endpoint'] = self.wxd_application_endpoint
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PrestissimoEndpoints object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PrestissimoEndpoints') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PrestissimoEndpoints') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class PrestissimoEngine:
    """
    EngineDetail.

    :param List[str] actions: (optional) Actions.
    :param List[str] associated_catalogs: (optional) Associated catalog.
    :param str build_version: (optional) watsonx.data build version.
    :param PrestissimoNodeDescriptionBody coordinator: (optional) Node details.
    :param str created_by: (optional) Created user name.
    :param int created_on: (optional) Created time in epoch format.
    :param str description: (optional) Engine description.
    :param PrestissimoEngineDetails engine_details: (optional) External engine
          details.
    :param str engine_display_name: (optional) Engine display name.
    :param str engine_id: (optional) Engine programmatic name.
    :param str external_host_name: Applicable only for OCP based clusters.  This is
          typically  servicename+route.
    :param str group_id: (optional) Group ID.
    :param str host_name: (optional) Engine host name. In case of OCP based
          clusters, this is internal hostname.
    :param str origin: (optional) Origin - place holder.
    :param int port: (optional) Engine port.
    :param str region: (optional) Region - place holder.
    :param str size_config: (optional) Size config.
    :param str status: (optional) Recipe status.
    :param int status_code: Engine status code.
    :param List[str] tags: (optional) Tags.
    :param str type: (optional) Type like prestissimo, netezza,..
    :param str version: (optional) Version of the engine.
    :param PrestissimoNodeDescriptionBody worker: (optional) Node details.
    """

    def __init__(
        self,
        external_host_name: str,
        status_code: int,
        *,
        actions: Optional[List[str]] = None,
        associated_catalogs: Optional[List[str]] = None,
        build_version: Optional[str] = None,
        coordinator: Optional['PrestissimoNodeDescriptionBody'] = None,
        created_by: Optional[str] = None,
        created_on: Optional[int] = None,
        description: Optional[str] = None,
        engine_details: Optional['PrestissimoEngineDetails'] = None,
        engine_display_name: Optional[str] = None,
        engine_id: Optional[str] = None,
        group_id: Optional[str] = None,
        host_name: Optional[str] = None,
        origin: Optional[str] = None,
        port: Optional[int] = None,
        region: Optional[str] = None,
        size_config: Optional[str] = None,
        status: Optional[str] = None,
        tags: Optional[List[str]] = None,
        type: Optional[str] = None,
        version: Optional[str] = None,
        worker: Optional['PrestissimoNodeDescriptionBody'] = None,
    ) -> None:
        """
        Initialize a PrestissimoEngine object.

        :param str external_host_name: Applicable only for OCP based clusters.
               This is typically  servicename+route.
        :param int status_code: Engine status code.
        :param List[str] actions: (optional) Actions.
        :param List[str] associated_catalogs: (optional) Associated catalog.
        :param str build_version: (optional) watsonx.data build version.
        :param PrestissimoNodeDescriptionBody coordinator: (optional) Node details.
        :param str created_by: (optional) Created user name.
        :param int created_on: (optional) Created time in epoch format.
        :param str description: (optional) Engine description.
        :param PrestissimoEngineDetails engine_details: (optional) External engine
               details.
        :param str engine_display_name: (optional) Engine display name.
        :param str engine_id: (optional) Engine programmatic name.
        :param str group_id: (optional) Group ID.
        :param str host_name: (optional) Engine host name. In case of OCP based
               clusters, this is internal hostname.
        :param str origin: (optional) Origin - place holder.
        :param int port: (optional) Engine port.
        :param str region: (optional) Region - place holder.
        :param str size_config: (optional) Size config.
        :param str status: (optional) Recipe status.
        :param List[str] tags: (optional) Tags.
        :param str type: (optional) Type like prestissimo, netezza,..
        :param str version: (optional) Version of the engine.
        :param PrestissimoNodeDescriptionBody worker: (optional) Node details.
        """
        self.actions = actions
        self.associated_catalogs = associated_catalogs
        self.build_version = build_version
        self.coordinator = coordinator
        self.created_by = created_by
        self.created_on = created_on
        self.description = description
        self.engine_details = engine_details
        self.engine_display_name = engine_display_name
        self.engine_id = engine_id
        self.external_host_name = external_host_name
        self.group_id = group_id
        self.host_name = host_name
        self.origin = origin
        self.port = port
        self.region = region
        self.size_config = size_config
        self.status = status
        self.status_code = status_code
        self.tags = tags
        self.type = type
        self.version = version
        self.worker = worker

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrestissimoEngine':
        """Initialize a PrestissimoEngine object from a json dictionary."""
        args = {}
        if 'actions' in _dict:
            args['actions'] = _dict.get('actions')
        if 'associated_catalogs' in _dict:
            args['associated_catalogs'] = _dict.get('associated_catalogs')
        if 'build_version' in _dict:
            args['build_version'] = _dict.get('build_version')
        if 'coordinator' in _dict:
            args['coordinator'] = PrestissimoNodeDescriptionBody.from_dict(_dict.get('coordinator'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'created_on' in _dict:
            args['created_on'] = _dict.get('created_on')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'engine_details' in _dict:
            args['engine_details'] = PrestissimoEngineDetails.from_dict(_dict.get('engine_details'))
        if 'engine_display_name' in _dict:
            args['engine_display_name'] = _dict.get('engine_display_name')
        if 'engine_id' in _dict:
            args['engine_id'] = _dict.get('engine_id')
        if 'external_host_name' in _dict:
            args['external_host_name'] = _dict.get('external_host_name')
        else:
            raise ValueError('Required property \'external_host_name\' not present in PrestissimoEngine JSON')
        if 'group_id' in _dict:
            args['group_id'] = _dict.get('group_id')
        if 'host_name' in _dict:
            args['host_name'] = _dict.get('host_name')
        if 'origin' in _dict:
            args['origin'] = _dict.get('origin')
        if 'port' in _dict:
            args['port'] = _dict.get('port')
        if 'region' in _dict:
            args['region'] = _dict.get('region')
        if 'size_config' in _dict:
            args['size_config'] = _dict.get('size_config')
        if 'status' in _dict:
            args['status'] = _dict.get('status')
        if 'status_code' in _dict:
            args['status_code'] = _dict.get('status_code')
        else:
            raise ValueError('Required property \'status_code\' not present in PrestissimoEngine JSON')
        if 'tags' in _dict:
            args['tags'] = _dict.get('tags')
        if 'type' in _dict:
            args['type'] = _dict.get('type')
        if 'version' in _dict:
            args['version'] = _dict.get('version')
        if 'worker' in _dict:
            args['worker'] = PrestissimoNodeDescriptionBody.from_dict(_dict.get('worker'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrestissimoEngine object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'actions') and self.actions is not None:
            _dict['actions'] = self.actions
        if hasattr(self, 'associated_catalogs') and self.associated_catalogs is not None:
            _dict['associated_catalogs'] = self.associated_catalogs
        if hasattr(self, 'build_version') and self.build_version is not None:
            _dict['build_version'] = self.build_version
        if hasattr(self, 'coordinator') and self.coordinator is not None:
            if isinstance(self.coordinator, dict):
                _dict['coordinator'] = self.coordinator
            else:
                _dict['coordinator'] = self.coordinator.to_dict()
        if hasattr(self, 'created_by') and self.created_by is not None:
            _dict['created_by'] = self.created_by
        if hasattr(self, 'created_on') and self.created_on is not None:
            _dict['created_on'] = self.created_on
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'engine_details') and self.engine_details is not None:
            if isinstance(self.engine_details, dict):
                _dict['engine_details'] = self.engine_details
            else:
                _dict['engine_details'] = self.engine_details.to_dict()
        if hasattr(self, 'engine_display_name') and self.engine_display_name is not None:
            _dict['engine_display_name'] = self.engine_display_name
        if hasattr(self, 'engine_id') and self.engine_id is not None:
            _dict['engine_id'] = self.engine_id
        if hasattr(self, 'external_host_name') and self.external_host_name is not None:
            _dict['external_host_name'] = self.external_host_name
        if hasattr(self, 'group_id') and self.group_id is not None:
            _dict['group_id'] = self.group_id
        if hasattr(self, 'host_name') and self.host_name is not None:
            _dict['host_name'] = self.host_name
        if hasattr(self, 'origin') and self.origin is not None:
            _dict['origin'] = self.origin
        if hasattr(self, 'port') and self.port is not None:
            _dict['port'] = self.port
        if hasattr(self, 'region') and self.region is not None:
            _dict['region'] = self.region
        if hasattr(self, 'size_config') and self.size_config is not None:
            _dict['size_config'] = self.size_config
        if hasattr(self, 'status') and self.status is not None:
            _dict['status'] = self.status
        if hasattr(self, 'status_code') and self.status_code is not None:
            _dict['status_code'] = self.status_code
        if hasattr(self, 'tags') and self.tags is not None:
            _dict['tags'] = self.tags
        if hasattr(self, 'type') and self.type is not None:
            _dict['type'] = self.type
        if hasattr(self, 'version') and self.version is not None:
            _dict['version'] = self.version
        if hasattr(self, 'worker') and self.worker is not None:
            if isinstance(self.worker, dict):
                _dict['worker'] = self.worker
            else:
                _dict['worker'] = self.worker.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PrestissimoEngine object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PrestissimoEngine') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PrestissimoEngine') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class StatusEnum(str, Enum):
        """
        Recipe status.
        """

        RUNNING = 'running'
        PENDING = 'pending'
        STOPPED = 'stopped'


class PrestissimoEngineDetails:
    """
    External engine details.

    :param str connection_string: (optional) External engine connection string.
    :param PrestissimoEndpoints endpoints: (optional) Endpoints.
    :param str metastore_host: (optional) Metastore host.
    """

    def __init__(
        self,
        *,
        connection_string: Optional[str] = None,
        endpoints: Optional['PrestissimoEndpoints'] = None,
        metastore_host: Optional[str] = None,
    ) -> None:
        """
        Initialize a PrestissimoEngineDetails object.

        :param str connection_string: (optional) External engine connection string.
        :param PrestissimoEndpoints endpoints: (optional) Endpoints.
        :param str metastore_host: (optional) Metastore host.
        """
        self.connection_string = connection_string
        self.endpoints = endpoints
        self.metastore_host = metastore_host

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrestissimoEngineDetails':
        """Initialize a PrestissimoEngineDetails object from a json dictionary."""
        args = {}
        if 'connection_string' in _dict:
            args['connection_string'] = _dict.get('connection_string')
        if 'endpoints' in _dict:
            args['endpoints'] = PrestissimoEndpoints.from_dict(_dict.get('endpoints'))
        if 'metastore_host' in _dict:
            args['metastore_host'] = _dict.get('metastore_host')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrestissimoEngineDetails object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'connection_string') and self.connection_string is not None:
            _dict['connection_string'] = self.connection_string
        if hasattr(self, 'endpoints') and self.endpoints is not None:
            if isinstance(self.endpoints, dict):
                _dict['endpoints'] = self.endpoints
            else:
                _dict['endpoints'] = self.endpoints.to_dict()
        if hasattr(self, 'metastore_host') and self.metastore_host is not None:
            _dict['metastore_host'] = self.metastore_host
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PrestissimoEngineDetails object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PrestissimoEngineDetails') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PrestissimoEngineDetails') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class PrestissimoNodeDescriptionBody:
    """
    Node details.

    :param str node_type: (optional) Node Type, r5, m, i..
    :param int quantity: (optional) Number of nodes.
    """

    def __init__(
        self,
        *,
        node_type: Optional[str] = None,
        quantity: Optional[int] = None,
    ) -> None:
        """
        Initialize a PrestissimoNodeDescriptionBody object.

        :param str node_type: (optional) Node Type, r5, m, i..
        :param int quantity: (optional) Number of nodes.
        """
        self.node_type = node_type
        self.quantity = quantity

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrestissimoNodeDescriptionBody':
        """Initialize a PrestissimoNodeDescriptionBody object from a json dictionary."""
        args = {}
        if 'node_type' in _dict:
            args['node_type'] = _dict.get('node_type')
        if 'quantity' in _dict:
            args['quantity'] = _dict.get('quantity')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrestissimoNodeDescriptionBody object from a json dictionary."""
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
        """Return a `str` version of this PrestissimoNodeDescriptionBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PrestissimoNodeDescriptionBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PrestissimoNodeDescriptionBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class PrestoEngine:
    """
    EngineDetail.

    :param List[str] actions: (optional) Actions.
    :param List[str] associated_catalogs: (optional) Associated catalog.
    :param str build_version: (optional) watsonx.data build version.
    :param NodeDescription coordinator: (optional) NodeDescription.
    :param str created_by: (optional) Created user name.
    :param int created_on: (optional) Created time in epoch format.
    :param str description: (optional) Engine description.
    :param EngineDetails engine_details: (optional) External engine details.
    :param str engine_display_name: (optional) Engine display name.
    :param str engine_id: (optional) Engine programmatic name.
    :param str external_host_name: Applicable only for OCP based clusters.  This is
          typically  servicename+route.
    :param str group_id: (optional) Group ID.
    :param str host_name: (optional) Engine host name. In case of OCP based
          clusters, this is internal hostname.
    :param str origin: (optional) Origin - place holder.
    :param int port: (optional) Engine port.
    :param str region: (optional) Region - place holder.
    :param str size_config: (optional) Size config.
    :param str status: (optional) Engine status.
    :param int status_code: Engine status code.
    :param List[str] tags: (optional) Tags.
    :param str type: (optional) Type like presto, netezza,..
    :param str version: (optional) Version of the engine.
    :param NodeDescription worker: (optional) NodeDescription.
    """

    def __init__(
        self,
        external_host_name: str,
        status_code: int,
        *,
        actions: Optional[List[str]] = None,
        associated_catalogs: Optional[List[str]] = None,
        build_version: Optional[str] = None,
        coordinator: Optional['NodeDescription'] = None,
        created_by: Optional[str] = None,
        created_on: Optional[int] = None,
        description: Optional[str] = None,
        engine_details: Optional['EngineDetails'] = None,
        engine_display_name: Optional[str] = None,
        engine_id: Optional[str] = None,
        group_id: Optional[str] = None,
        host_name: Optional[str] = None,
        origin: Optional[str] = None,
        port: Optional[int] = None,
        region: Optional[str] = None,
        size_config: Optional[str] = None,
        status: Optional[str] = None,
        tags: Optional[List[str]] = None,
        type: Optional[str] = None,
        version: Optional[str] = None,
        worker: Optional['NodeDescription'] = None,
    ) -> None:
        """
        Initialize a PrestoEngine object.

        :param str external_host_name: Applicable only for OCP based clusters.
               This is typically  servicename+route.
        :param int status_code: Engine status code.
        :param List[str] actions: (optional) Actions.
        :param List[str] associated_catalogs: (optional) Associated catalog.
        :param str build_version: (optional) watsonx.data build version.
        :param NodeDescription coordinator: (optional) NodeDescription.
        :param str created_by: (optional) Created user name.
        :param int created_on: (optional) Created time in epoch format.
        :param str description: (optional) Engine description.
        :param EngineDetails engine_details: (optional) External engine details.
        :param str engine_display_name: (optional) Engine display name.
        :param str engine_id: (optional) Engine programmatic name.
        :param str group_id: (optional) Group ID.
        :param str host_name: (optional) Engine host name. In case of OCP based
               clusters, this is internal hostname.
        :param str origin: (optional) Origin - place holder.
        :param int port: (optional) Engine port.
        :param str region: (optional) Region - place holder.
        :param str size_config: (optional) Size config.
        :param str status: (optional) Engine status.
        :param List[str] tags: (optional) Tags.
        :param str type: (optional) Type like presto, netezza,..
        :param str version: (optional) Version of the engine.
        :param NodeDescription worker: (optional) NodeDescription.
        """
        self.actions = actions
        self.associated_catalogs = associated_catalogs
        self.build_version = build_version
        self.coordinator = coordinator
        self.created_by = created_by
        self.created_on = created_on
        self.description = description
        self.engine_details = engine_details
        self.engine_display_name = engine_display_name
        self.engine_id = engine_id
        self.external_host_name = external_host_name
        self.group_id = group_id
        self.host_name = host_name
        self.origin = origin
        self.port = port
        self.region = region
        self.size_config = size_config
        self.status = status
        self.status_code = status_code
        self.tags = tags
        self.type = type
        self.version = version
        self.worker = worker

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrestoEngine':
        """Initialize a PrestoEngine object from a json dictionary."""
        args = {}
        if 'actions' in _dict:
            args['actions'] = _dict.get('actions')
        if 'associated_catalogs' in _dict:
            args['associated_catalogs'] = _dict.get('associated_catalogs')
        if 'build_version' in _dict:
            args['build_version'] = _dict.get('build_version')
        if 'coordinator' in _dict:
            args['coordinator'] = NodeDescription.from_dict(_dict.get('coordinator'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'created_on' in _dict:
            args['created_on'] = _dict.get('created_on')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'engine_details' in _dict:
            args['engine_details'] = EngineDetails.from_dict(_dict.get('engine_details'))
        if 'engine_display_name' in _dict:
            args['engine_display_name'] = _dict.get('engine_display_name')
        if 'engine_id' in _dict:
            args['engine_id'] = _dict.get('engine_id')
        if 'external_host_name' in _dict:
            args['external_host_name'] = _dict.get('external_host_name')
        else:
            raise ValueError('Required property \'external_host_name\' not present in PrestoEngine JSON')
        if 'group_id' in _dict:
            args['group_id'] = _dict.get('group_id')
        if 'host_name' in _dict:
            args['host_name'] = _dict.get('host_name')
        if 'origin' in _dict:
            args['origin'] = _dict.get('origin')
        if 'port' in _dict:
            args['port'] = _dict.get('port')
        if 'region' in _dict:
            args['region'] = _dict.get('region')
        if 'size_config' in _dict:
            args['size_config'] = _dict.get('size_config')
        if 'status' in _dict:
            args['status'] = _dict.get('status')
        if 'status_code' in _dict:
            args['status_code'] = _dict.get('status_code')
        else:
            raise ValueError('Required property \'status_code\' not present in PrestoEngine JSON')
        if 'tags' in _dict:
            args['tags'] = _dict.get('tags')
        if 'type' in _dict:
            args['type'] = _dict.get('type')
        if 'version' in _dict:
            args['version'] = _dict.get('version')
        if 'worker' in _dict:
            args['worker'] = NodeDescription.from_dict(_dict.get('worker'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrestoEngine object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'actions') and self.actions is not None:
            _dict['actions'] = self.actions
        if hasattr(self, 'associated_catalogs') and self.associated_catalogs is not None:
            _dict['associated_catalogs'] = self.associated_catalogs
        if hasattr(self, 'build_version') and self.build_version is not None:
            _dict['build_version'] = self.build_version
        if hasattr(self, 'coordinator') and self.coordinator is not None:
            if isinstance(self.coordinator, dict):
                _dict['coordinator'] = self.coordinator
            else:
                _dict['coordinator'] = self.coordinator.to_dict()
        if hasattr(self, 'created_by') and self.created_by is not None:
            _dict['created_by'] = self.created_by
        if hasattr(self, 'created_on') and self.created_on is not None:
            _dict['created_on'] = self.created_on
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'engine_details') and self.engine_details is not None:
            if isinstance(self.engine_details, dict):
                _dict['engine_details'] = self.engine_details
            else:
                _dict['engine_details'] = self.engine_details.to_dict()
        if hasattr(self, 'engine_display_name') and self.engine_display_name is not None:
            _dict['engine_display_name'] = self.engine_display_name
        if hasattr(self, 'engine_id') and self.engine_id is not None:
            _dict['engine_id'] = self.engine_id
        if hasattr(self, 'external_host_name') and self.external_host_name is not None:
            _dict['external_host_name'] = self.external_host_name
        if hasattr(self, 'group_id') and self.group_id is not None:
            _dict['group_id'] = self.group_id
        if hasattr(self, 'host_name') and self.host_name is not None:
            _dict['host_name'] = self.host_name
        if hasattr(self, 'origin') and self.origin is not None:
            _dict['origin'] = self.origin
        if hasattr(self, 'port') and self.port is not None:
            _dict['port'] = self.port
        if hasattr(self, 'region') and self.region is not None:
            _dict['region'] = self.region
        if hasattr(self, 'size_config') and self.size_config is not None:
            _dict['size_config'] = self.size_config
        if hasattr(self, 'status') and self.status is not None:
            _dict['status'] = self.status
        if hasattr(self, 'status_code') and self.status_code is not None:
            _dict['status_code'] = self.status_code
        if hasattr(self, 'tags') and self.tags is not None:
            _dict['tags'] = self.tags
        if hasattr(self, 'type') and self.type is not None:
            _dict['type'] = self.type
        if hasattr(self, 'version') and self.version is not None:
            _dict['version'] = self.version
        if hasattr(self, 'worker') and self.worker is not None:
            if isinstance(self.worker, dict):
                _dict['worker'] = self.worker
            else:
                _dict['worker'] = self.worker.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PrestoEngine object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PrestoEngine') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PrestoEngine') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class StatusEnum(str, Enum):
        """
        Engine status.
        """

        RUNNING = 'running'
        PENDING = 'pending'
        STOPPED = 'stopped'


class RegisterDatabaseCatalogBodyDatabaseDetails:
    """
    database details.

    :param str certificate: (optional) contents of a pem/crt file.
    :param str certificate_extension: (optional) extension of the certificate file.
    :param str database_name: (optional) Database name.
    :param str hostname: Host name.
    :param str hosts: (optional) String of hostname:port.
    :param str password: (optional) Psssword.
    :param int port: Port.
    :param bool sasl: (optional) SASL Mode.
    :param bool ssl: (optional) SSL Mode.
    :param str tables: (optional) Only for Kafka - Add kafka tables.
    :param str username: (optional) Username.
    """

    def __init__(
        self,
        hostname: str,
        port: int,
        *,
        certificate: Optional[str] = None,
        certificate_extension: Optional[str] = None,
        database_name: Optional[str] = None,
        hosts: Optional[str] = None,
        password: Optional[str] = None,
        sasl: Optional[bool] = None,
        ssl: Optional[bool] = None,
        tables: Optional[str] = None,
        username: Optional[str] = None,
    ) -> None:
        """
        Initialize a RegisterDatabaseCatalogBodyDatabaseDetails object.

        :param str hostname: Host name.
        :param int port: Port.
        :param str certificate: (optional) contents of a pem/crt file.
        :param str certificate_extension: (optional) extension of the certificate
               file.
        :param str database_name: (optional) Database name.
        :param str hosts: (optional) String of hostname:port.
        :param str password: (optional) Psssword.
        :param bool sasl: (optional) SASL Mode.
        :param bool ssl: (optional) SSL Mode.
        :param str tables: (optional) Only for Kafka - Add kafka tables.
        :param str username: (optional) Username.
        """
        self.certificate = certificate
        self.certificate_extension = certificate_extension
        self.database_name = database_name
        self.hostname = hostname
        self.hosts = hosts
        self.password = password
        self.port = port
        self.sasl = sasl
        self.ssl = ssl
        self.tables = tables
        self.username = username

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RegisterDatabaseCatalogBodyDatabaseDetails':
        """Initialize a RegisterDatabaseCatalogBodyDatabaseDetails object from a json dictionary."""
        args = {}
        if 'certificate' in _dict:
            args['certificate'] = _dict.get('certificate')
        if 'certificate_extension' in _dict:
            args['certificate_extension'] = _dict.get('certificate_extension')
        if 'database_name' in _dict:
            args['database_name'] = _dict.get('database_name')
        if 'hostname' in _dict:
            args['hostname'] = _dict.get('hostname')
        else:
            raise ValueError(
                'Required property \'hostname\' not present in RegisterDatabaseCatalogBodyDatabaseDetails JSON'
            )
        if 'hosts' in _dict:
            args['hosts'] = _dict.get('hosts')
        if 'password' in _dict:
            args['password'] = _dict.get('password')
        if 'port' in _dict:
            args['port'] = _dict.get('port')
        else:
            raise ValueError(
                'Required property \'port\' not present in RegisterDatabaseCatalogBodyDatabaseDetails JSON'
            )
        if 'sasl' in _dict:
            args['sasl'] = _dict.get('sasl')
        if 'ssl' in _dict:
            args['ssl'] = _dict.get('ssl')
        if 'tables' in _dict:
            args['tables'] = _dict.get('tables')
        if 'username' in _dict:
            args['username'] = _dict.get('username')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RegisterDatabaseCatalogBodyDatabaseDetails object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'certificate') and self.certificate is not None:
            _dict['certificate'] = self.certificate
        if hasattr(self, 'certificate_extension') and self.certificate_extension is not None:
            _dict['certificate_extension'] = self.certificate_extension
        if hasattr(self, 'database_name') and self.database_name is not None:
            _dict['database_name'] = self.database_name
        if hasattr(self, 'hostname') and self.hostname is not None:
            _dict['hostname'] = self.hostname
        if hasattr(self, 'hosts') and self.hosts is not None:
            _dict['hosts'] = self.hosts
        if hasattr(self, 'password') and self.password is not None:
            _dict['password'] = self.password
        if hasattr(self, 'port') and self.port is not None:
            _dict['port'] = self.port
        if hasattr(self, 'sasl') and self.sasl is not None:
            _dict['sasl'] = self.sasl
        if hasattr(self, 'ssl') and self.ssl is not None:
            _dict['ssl'] = self.ssl
        if hasattr(self, 'tables') and self.tables is not None:
            _dict['tables'] = self.tables
        if hasattr(self, 'username') and self.username is not None:
            _dict['username'] = self.username
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


class RegisterDatabaseCatalogBodyDatabasePropertiesItems:
    """
    Key value object.

    :param bool encrypt: Wether the value is to be encrypted before storing.
    :param str key: Key of the database property.
    :param str value: Value of the database property.
    """

    def __init__(
        self,
        encrypt: bool,
        key: str,
        value: str,
    ) -> None:
        """
        Initialize a RegisterDatabaseCatalogBodyDatabasePropertiesItems object.

        :param bool encrypt: Wether the value is to be encrypted before storing.
        :param str key: Key of the database property.
        :param str value: Value of the database property.
        """
        self.encrypt = encrypt
        self.key = key
        self.value = value

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RegisterDatabaseCatalogBodyDatabasePropertiesItems':
        """Initialize a RegisterDatabaseCatalogBodyDatabasePropertiesItems object from a json dictionary."""
        args = {}
        if 'encrypt' in _dict:
            args['encrypt'] = _dict.get('encrypt')
        else:
            raise ValueError(
                'Required property \'encrypt\' not present in RegisterDatabaseCatalogBodyDatabasePropertiesItems JSON'
            )
        if 'key' in _dict:
            args['key'] = _dict.get('key')
        else:
            raise ValueError(
                'Required property \'key\' not present in RegisterDatabaseCatalogBodyDatabasePropertiesItems JSON'
            )
        if 'value' in _dict:
            args['value'] = _dict.get('value')
        else:
            raise ValueError(
                'Required property \'value\' not present in RegisterDatabaseCatalogBodyDatabasePropertiesItems JSON'
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RegisterDatabaseCatalogBodyDatabasePropertiesItems object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'encrypt') and self.encrypt is not None:
            _dict['encrypt'] = self.encrypt
        if hasattr(self, 'key') and self.key is not None:
            _dict['key'] = self.key
        if hasattr(self, 'value') and self.value is not None:
            _dict['value'] = self.value
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RegisterDatabaseCatalogBodyDatabasePropertiesItems object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RegisterDatabaseCatalogBodyDatabasePropertiesItems') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RegisterDatabaseCatalogBodyDatabasePropertiesItems') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ReplacePrestoEngineCatalogsCreatedBody:
    """
    get engine catalogs.

    :param List[Catalog] catalogs: Engine Catalogs.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        catalogs: List['Catalog'],
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a ReplacePrestoEngineCatalogsCreatedBody object.

        :param List[Catalog] catalogs: Engine Catalogs.
        :param SuccessResponse response: Response of success.
        """
        self.catalogs = catalogs
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ReplacePrestoEngineCatalogsCreatedBody':
        """Initialize a ReplacePrestoEngineCatalogsCreatedBody object from a json dictionary."""
        args = {}
        if 'catalogs' in _dict:
            args['catalogs'] = [Catalog.from_dict(v) for v in _dict.get('catalogs')]
        else:
            raise ValueError(
                'Required property \'catalogs\' not present in ReplacePrestoEngineCatalogsCreatedBody JSON'
            )
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError(
                'Required property \'response\' not present in ReplacePrestoEngineCatalogsCreatedBody JSON'
            )
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ReplacePrestoEngineCatalogsCreatedBody object from a json dictionary."""
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
        """Return a `str` version of this ReplacePrestoEngineCatalogsCreatedBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ReplacePrestoEngineCatalogsCreatedBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ReplacePrestoEngineCatalogsCreatedBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ReplaceSnapshotCreatedBody:
    """
    success response.

    :param SuccessResponse response: (optional) Response of success.
    """

    def __init__(
        self,
        *,
        response: Optional['SuccessResponse'] = None,
    ) -> None:
        """
        Initialize a ReplaceSnapshotCreatedBody object.

        :param SuccessResponse response: (optional) Response of success.
        """
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ReplaceSnapshotCreatedBody':
        """Initialize a ReplaceSnapshotCreatedBody object from a json dictionary."""
        args = {}
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ReplaceSnapshotCreatedBody object from a json dictionary."""
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
        """Return a `str` version of this ReplaceSnapshotCreatedBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ReplaceSnapshotCreatedBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ReplaceSnapshotCreatedBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class RunExplainAnalyzeStatementOKBody:
    """
    explainAnalyzeStatement OK.

    :param SuccessResponse response: Response of success.
    :param str result: explainAnalyzeStatement result.
    """

    def __init__(
        self,
        response: 'SuccessResponse',
        result: str,
    ) -> None:
        """
        Initialize a RunExplainAnalyzeStatementOKBody object.

        :param SuccessResponse response: Response of success.
        :param str result: explainAnalyzeStatement result.
        """
        self.response = response
        self.result = result

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RunExplainAnalyzeStatementOKBody':
        """Initialize a RunExplainAnalyzeStatementOKBody object from a json dictionary."""
        args = {}
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in RunExplainAnalyzeStatementOKBody JSON')
        if 'result' in _dict:
            args['result'] = _dict.get('result')
        else:
            raise ValueError('Required property \'result\' not present in RunExplainAnalyzeStatementOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RunExplainAnalyzeStatementOKBody object from a json dictionary."""
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
        """Return a `str` version of this RunExplainAnalyzeStatementOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RunExplainAnalyzeStatementOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RunExplainAnalyzeStatementOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class RunExplainStatementOKBody:
    """
    ExplainStatement OK.

    :param SuccessResponse response: Response of success.
    :param str result: Result.
    """

    def __init__(
        self,
        response: 'SuccessResponse',
        result: str,
    ) -> None:
        """
        Initialize a RunExplainStatementOKBody object.

        :param SuccessResponse response: Response of success.
        :param str result: Result.
        """
        self.response = response
        self.result = result

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RunExplainStatementOKBody':
        """Initialize a RunExplainStatementOKBody object from a json dictionary."""
        args = {}
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in RunExplainStatementOKBody JSON')
        if 'result' in _dict:
            args['result'] = _dict.get('result')
        else:
            raise ValueError('Required property \'result\' not present in RunExplainStatementOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RunExplainStatementOKBody object from a json dictionary."""
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
        """Return a `str` version of this RunExplainStatementOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RunExplainStatementOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RunExplainStatementOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SparkApplicationDetails:
    """
    Application details.

    :param str application: Application.
    :param List[str] arguments: List of arguments.
    :param dict conf: Application.
    :param dict env: Application.
    :param str name: (optional) Display name of the spark application.
    """

    def __init__(
        self,
        application: str,
        arguments: List[str],
        conf: dict,
        env: dict,
        *,
        name: Optional[str] = None,
    ) -> None:
        """
        Initialize a SparkApplicationDetails object.

        :param str application: Application.
        :param List[str] arguments: List of arguments.
        :param dict conf: Application.
        :param dict env: Application.
        :param str name: (optional) Display name of the spark application.
        """
        self.application = application
        self.arguments = arguments
        self.conf = conf
        self.env = env
        self.name = name

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SparkApplicationDetails':
        """Initialize a SparkApplicationDetails object from a json dictionary."""
        args = {}
        if 'application' in _dict:
            args['application'] = _dict.get('application')
        else:
            raise ValueError('Required property \'application\' not present in SparkApplicationDetails JSON')
        if 'arguments' in _dict:
            args['arguments'] = _dict.get('arguments')
        else:
            raise ValueError('Required property \'arguments\' not present in SparkApplicationDetails JSON')
        if 'conf' in _dict:
            args['conf'] = _dict.get('conf')
        else:
            raise ValueError('Required property \'conf\' not present in SparkApplicationDetails JSON')
        if 'env' in _dict:
            args['env'] = _dict.get('env')
        else:
            raise ValueError('Required property \'env\' not present in SparkApplicationDetails JSON')
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SparkApplicationDetails object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'application') and self.application is not None:
            _dict['application'] = self.application
        if hasattr(self, 'arguments') and self.arguments is not None:
            _dict['arguments'] = self.arguments
        if hasattr(self, 'conf') and self.conf is not None:
            _dict['conf'] = self.conf
        if hasattr(self, 'env') and self.env is not None:
            _dict['env'] = self.env
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SparkApplicationDetails object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SparkApplicationDetails') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SparkApplicationDetails') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SparkEngine:
    """
    EngineDetail.

    :param List[str] actions: (optional) Actions.
    :param str build_version: (optional) watsonx.data build version.
    :param str created_by: (optional) Created user name.
    :param int created_on: (optional) Created time in epoch format.
    :param str description: (optional) Engine description.
    :param SparkEngineDetails engine_details: (optional) External engine details.
    :param str engine_display_name: (optional) Engine display name.
    :param str engine_id: (optional) Engine programmatic name.
    :param str origin: (optional) Origin - place holder.
    :param str status: (optional) Engine status.
    :param List[str] tags: (optional) Tags.
    :param str type: (optional) Type like spark, netezza,..
    """

    def __init__(
        self,
        *,
        actions: Optional[List[str]] = None,
        build_version: Optional[str] = None,
        created_by: Optional[str] = None,
        created_on: Optional[int] = None,
        description: Optional[str] = None,
        engine_details: Optional['SparkEngineDetails'] = None,
        engine_display_name: Optional[str] = None,
        engine_id: Optional[str] = None,
        origin: Optional[str] = None,
        status: Optional[str] = None,
        tags: Optional[List[str]] = None,
        type: Optional[str] = None,
    ) -> None:
        """
        Initialize a SparkEngine object.

        :param List[str] actions: (optional) Actions.
        :param str build_version: (optional) watsonx.data build version.
        :param str created_by: (optional) Created user name.
        :param int created_on: (optional) Created time in epoch format.
        :param str description: (optional) Engine description.
        :param SparkEngineDetails engine_details: (optional) External engine
               details.
        :param str engine_display_name: (optional) Engine display name.
        :param str engine_id: (optional) Engine programmatic name.
        :param str origin: (optional) Origin - place holder.
        :param str status: (optional) Engine status.
        :param List[str] tags: (optional) Tags.
        :param str type: (optional) Type like spark, netezza,..
        """
        self.actions = actions
        self.build_version = build_version
        self.created_by = created_by
        self.created_on = created_on
        self.description = description
        self.engine_details = engine_details
        self.engine_display_name = engine_display_name
        self.engine_id = engine_id
        self.origin = origin
        self.status = status
        self.tags = tags
        self.type = type

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SparkEngine':
        """Initialize a SparkEngine object from a json dictionary."""
        args = {}
        if 'actions' in _dict:
            args['actions'] = _dict.get('actions')
        if 'build_version' in _dict:
            args['build_version'] = _dict.get('build_version')
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'created_on' in _dict:
            args['created_on'] = _dict.get('created_on')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'engine_details' in _dict:
            args['engine_details'] = SparkEngineDetails.from_dict(_dict.get('engine_details'))
        if 'engine_display_name' in _dict:
            args['engine_display_name'] = _dict.get('engine_display_name')
        if 'engine_id' in _dict:
            args['engine_id'] = _dict.get('engine_id')
        if 'origin' in _dict:
            args['origin'] = _dict.get('origin')
        if 'status' in _dict:
            args['status'] = _dict.get('status')
        if 'tags' in _dict:
            args['tags'] = _dict.get('tags')
        if 'type' in _dict:
            args['type'] = _dict.get('type')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SparkEngine object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'actions') and self.actions is not None:
            _dict['actions'] = self.actions
        if hasattr(self, 'build_version') and self.build_version is not None:
            _dict['build_version'] = self.build_version
        if hasattr(self, 'created_by') and self.created_by is not None:
            _dict['created_by'] = self.created_by
        if hasattr(self, 'created_on') and self.created_on is not None:
            _dict['created_on'] = self.created_on
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'engine_details') and self.engine_details is not None:
            if isinstance(self.engine_details, dict):
                _dict['engine_details'] = self.engine_details
            else:
                _dict['engine_details'] = self.engine_details.to_dict()
        if hasattr(self, 'engine_display_name') and self.engine_display_name is not None:
            _dict['engine_display_name'] = self.engine_display_name
        if hasattr(self, 'engine_id') and self.engine_id is not None:
            _dict['engine_id'] = self.engine_id
        if hasattr(self, 'origin') and self.origin is not None:
            _dict['origin'] = self.origin
        if hasattr(self, 'status') and self.status is not None:
            _dict['status'] = self.status
        if hasattr(self, 'tags') and self.tags is not None:
            _dict['tags'] = self.tags
        if hasattr(self, 'type') and self.type is not None:
            _dict['type'] = self.type
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SparkEngine object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SparkEngine') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SparkEngine') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SparkEngineApplication:
    """
    EngineSubmitApplicationBody.

    :param str application_id: (optional) Application ID.
    :param str id: (optional) Application ID.
    :param str state: (optional) state.
    """

    def __init__(
        self,
        *,
        application_id: Optional[str] = None,
        id: Optional[str] = None,
        state: Optional[str] = None,
    ) -> None:
        """
        Initialize a SparkEngineApplication object.

        :param str application_id: (optional) Application ID.
        :param str id: (optional) Application ID.
        :param str state: (optional) state.
        """
        self.application_id = application_id
        self.id = id
        self.state = state

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SparkEngineApplication':
        """Initialize a SparkEngineApplication object from a json dictionary."""
        args = {}
        if 'application_id' in _dict:
            args['application_id'] = _dict.get('application_id')
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'state' in _dict:
            args['state'] = _dict.get('state')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SparkEngineApplication object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'application_id') and self.application_id is not None:
            _dict['application_id'] = self.application_id
        if hasattr(self, 'id') and self.id is not None:
            _dict['id'] = self.id
        if hasattr(self, 'state') and self.state is not None:
            _dict['state'] = self.state
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SparkEngineApplication object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SparkEngineApplication') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SparkEngineApplication') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SparkEngineApplicationStatus:
    """
    Engine Application Status.

    :param SparkEngineApplicationStatusApplicationDetails application_details:
          (optional) Application Details.
    :param str application_id: (optional) Application ID.
    :param str auto_termination_time: (optional) Auto Termination Time.
    :param str creation_time: (optional) Creation time.
    :param str deploy_mode: (optional) Deployment mode.
    :param str end_time: (optional) End Time.
    :param str failed_time: (optional) Failed time.
    :param str finish_time: (optional) Finish time.
    :param str id: (optional) Application ID.
    :param str return_code: (optional) Return code.
    :param str spark_application_id: (optional) Spark application ID.
    :param str spark_application_name: (optional) Spark application name.
    :param str start_time: (optional) Start time.
    :param str state: (optional) Application state.
    :param List[SparkEngineApplicationStatusStateDetailsItems] state_details:
          (optional) Application state details.
    :param str submission_time: (optional) Application submission time.
    :param str template_id: (optional) Template ID.
    """

    def __init__(
        self,
        *,
        application_details: Optional['SparkEngineApplicationStatusApplicationDetails'] = None,
        application_id: Optional[str] = None,
        auto_termination_time: Optional[str] = None,
        creation_time: Optional[str] = None,
        deploy_mode: Optional[str] = None,
        end_time: Optional[str] = None,
        failed_time: Optional[str] = None,
        finish_time: Optional[str] = None,
        id: Optional[str] = None,
        return_code: Optional[str] = None,
        spark_application_id: Optional[str] = None,
        spark_application_name: Optional[str] = None,
        start_time: Optional[str] = None,
        state: Optional[str] = None,
        state_details: Optional[List['SparkEngineApplicationStatusStateDetailsItems']] = None,
        submission_time: Optional[str] = None,
        template_id: Optional[str] = None,
    ) -> None:
        """
        Initialize a SparkEngineApplicationStatus object.

        :param SparkEngineApplicationStatusApplicationDetails application_details:
               (optional) Application Details.
        :param str application_id: (optional) Application ID.
        :param str auto_termination_time: (optional) Auto Termination Time.
        :param str creation_time: (optional) Creation time.
        :param str deploy_mode: (optional) Deployment mode.
        :param str end_time: (optional) End Time.
        :param str failed_time: (optional) Failed time.
        :param str finish_time: (optional) Finish time.
        :param str id: (optional) Application ID.
        :param str return_code: (optional) Return code.
        :param str spark_application_id: (optional) Spark application ID.
        :param str spark_application_name: (optional) Spark application name.
        :param str start_time: (optional) Start time.
        :param str state: (optional) Application state.
        :param List[SparkEngineApplicationStatusStateDetailsItems] state_details:
               (optional) Application state details.
        :param str submission_time: (optional) Application submission time.
        :param str template_id: (optional) Template ID.
        """
        self.application_details = application_details
        self.application_id = application_id
        self.auto_termination_time = auto_termination_time
        self.creation_time = creation_time
        self.deploy_mode = deploy_mode
        self.end_time = end_time
        self.failed_time = failed_time
        self.finish_time = finish_time
        self.id = id
        self.return_code = return_code
        self.spark_application_id = spark_application_id
        self.spark_application_name = spark_application_name
        self.start_time = start_time
        self.state = state
        self.state_details = state_details
        self.submission_time = submission_time
        self.template_id = template_id

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SparkEngineApplicationStatus':
        """Initialize a SparkEngineApplicationStatus object from a json dictionary."""
        args = {}
        if 'application_details' in _dict:
            args['application_details'] = SparkEngineApplicationStatusApplicationDetails.from_dict(
                _dict.get('application_details')
            )
        if 'application_id' in _dict:
            args['application_id'] = _dict.get('application_id')
        if 'auto_termination_time' in _dict:
            args['auto_termination_time'] = _dict.get('auto_termination_time')
        if 'creation_time' in _dict:
            args['creation_time'] = _dict.get('creation_time')
        if 'deploy_mode' in _dict:
            args['deploy_mode'] = _dict.get('deploy_mode')
        if 'end_time' in _dict:
            args['end_time'] = _dict.get('end_time')
        if 'failed_time' in _dict:
            args['failed_time'] = _dict.get('failed_time')
        if 'finish_time' in _dict:
            args['finish_time'] = _dict.get('finish_time')
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'return_code' in _dict:
            args['return_code'] = _dict.get('return_code')
        if 'spark_application_id' in _dict:
            args['spark_application_id'] = _dict.get('spark_application_id')
        if 'spark_application_name' in _dict:
            args['spark_application_name'] = _dict.get('spark_application_name')
        if 'start_time' in _dict:
            args['start_time'] = _dict.get('start_time')
        if 'state' in _dict:
            args['state'] = _dict.get('state')
        if 'state_details' in _dict:
            args['state_details'] = [
                SparkEngineApplicationStatusStateDetailsItems.from_dict(v) for v in _dict.get('state_details')
            ]
        if 'submission_time' in _dict:
            args['submission_time'] = _dict.get('submission_time')
        if 'template_id' in _dict:
            args['template_id'] = _dict.get('template_id')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SparkEngineApplicationStatus object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'application_details') and self.application_details is not None:
            if isinstance(self.application_details, dict):
                _dict['application_details'] = self.application_details
            else:
                _dict['application_details'] = self.application_details.to_dict()
        if hasattr(self, 'application_id') and self.application_id is not None:
            _dict['application_id'] = self.application_id
        if hasattr(self, 'auto_termination_time') and self.auto_termination_time is not None:
            _dict['auto_termination_time'] = self.auto_termination_time
        if hasattr(self, 'creation_time') and self.creation_time is not None:
            _dict['creation_time'] = self.creation_time
        if hasattr(self, 'deploy_mode') and self.deploy_mode is not None:
            _dict['deploy_mode'] = self.deploy_mode
        if hasattr(self, 'end_time') and self.end_time is not None:
            _dict['end_time'] = self.end_time
        if hasattr(self, 'failed_time') and self.failed_time is not None:
            _dict['failed_time'] = self.failed_time
        if hasattr(self, 'finish_time') and self.finish_time is not None:
            _dict['finish_time'] = self.finish_time
        if hasattr(self, 'id') and self.id is not None:
            _dict['id'] = self.id
        if hasattr(self, 'return_code') and self.return_code is not None:
            _dict['return_code'] = self.return_code
        if hasattr(self, 'spark_application_id') and self.spark_application_id is not None:
            _dict['spark_application_id'] = self.spark_application_id
        if hasattr(self, 'spark_application_name') and self.spark_application_name is not None:
            _dict['spark_application_name'] = self.spark_application_name
        if hasattr(self, 'start_time') and self.start_time is not None:
            _dict['start_time'] = self.start_time
        if hasattr(self, 'state') and self.state is not None:
            _dict['state'] = self.state
        if hasattr(self, 'state_details') and self.state_details is not None:
            state_details_list = []
            for v in self.state_details:
                if isinstance(v, dict):
                    state_details_list.append(v)
                else:
                    state_details_list.append(v.to_dict())
            _dict['state_details'] = state_details_list
        if hasattr(self, 'submission_time') and self.submission_time is not None:
            _dict['submission_time'] = self.submission_time
        if hasattr(self, 'template_id') and self.template_id is not None:
            _dict['template_id'] = self.template_id
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SparkEngineApplicationStatus object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SparkEngineApplicationStatus') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SparkEngineApplicationStatus') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SparkEngineApplicationStatusApplicationDetails:
    """
    Application Details.

    :param str application: (optional) Engine display name.
    :param List[str] arguments: (optional) List of arguments.
    :param SparkEngineApplicationStatusApplicationDetailsConf conf: (optional)
          Application.
    :param dict env: (optional) Environment variables.
    :param str name: (optional) Application name.
    """

    def __init__(
        self,
        *,
        application: Optional[str] = None,
        arguments: Optional[List[str]] = None,
        conf: Optional['SparkEngineApplicationStatusApplicationDetailsConf'] = None,
        env: Optional[dict] = None,
        name: Optional[str] = None,
    ) -> None:
        """
        Initialize a SparkEngineApplicationStatusApplicationDetails object.

        :param str application: (optional) Engine display name.
        :param List[str] arguments: (optional) List of arguments.
        :param SparkEngineApplicationStatusApplicationDetailsConf conf: (optional)
               Application.
        :param dict env: (optional) Environment variables.
        :param str name: (optional) Application name.
        """
        self.application = application
        self.arguments = arguments
        self.conf = conf
        self.env = env
        self.name = name

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SparkEngineApplicationStatusApplicationDetails':
        """Initialize a SparkEngineApplicationStatusApplicationDetails object from a json dictionary."""
        args = {}
        if 'application' in _dict:
            args['application'] = _dict.get('application')
        if 'arguments' in _dict:
            args['arguments'] = _dict.get('arguments')
        if 'conf' in _dict:
            args['conf'] = SparkEngineApplicationStatusApplicationDetailsConf.from_dict(_dict.get('conf'))
        if 'env' in _dict:
            args['env'] = _dict.get('env')
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SparkEngineApplicationStatusApplicationDetails object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'application') and self.application is not None:
            _dict['application'] = self.application
        if hasattr(self, 'arguments') and self.arguments is not None:
            _dict['arguments'] = self.arguments
        if hasattr(self, 'conf') and self.conf is not None:
            if isinstance(self.conf, dict):
                _dict['conf'] = self.conf
            else:
                _dict['conf'] = self.conf.to_dict()
        if hasattr(self, 'env') and self.env is not None:
            _dict['env'] = self.env
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SparkEngineApplicationStatusApplicationDetails object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SparkEngineApplicationStatusApplicationDetails') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SparkEngineApplicationStatusApplicationDetails') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SparkEngineApplicationStatusApplicationDetailsConf:
    """
    Application.

    :param str spark_app_name: (optional) Spark application name.
    :param str spark_hive_metastore_client_auth_mode: (optional) Hive Metastore
          authentication mode.
    :param str spark_hive_metastore_client_plain_password: (optional) Hive Metastore
          plain password.
    :param str spark_hive_metastore_client_plain_username: (optional) Hive Metastore
          plain username.
    :param str spark_hive_metastore_truststore_password: (optional) Truststore
          password.
    :param str spark_hive_metastore_truststore_path: (optional) Truststore path.
    :param str spark_hive_metastore_truststore_type: (optional) Truststore type.
    :param str spark_hive_metastore_use_ssl: (optional) Enable or disable SSL for
          Hive Metastore.
    :param str spark_sql_catalog_implementation: (optional) SQL catalog
          implementation.
    :param str spark_sql_catalog_lakehouse: (optional) Lakehouse catalog name.
    :param str spark_sql_catalog_lakehouse_type: (optional) Lakehouse catalog type.
    :param str spark_sql_catalog_lakehouse_uri: (optional) Lakehouse catalog URI.
    :param str spark_sql_extensions: (optional) SQL extensions.
    :param str spark_sql_iceberg_vectorization_enabled: (optional) Enable or disable
          Iceberg vectorization.
    """

    def __init__(
        self,
        *,
        spark_app_name: Optional[str] = None,
        spark_hive_metastore_client_auth_mode: Optional[str] = None,
        spark_hive_metastore_client_plain_password: Optional[str] = None,
        spark_hive_metastore_client_plain_username: Optional[str] = None,
        spark_hive_metastore_truststore_password: Optional[str] = None,
        spark_hive_metastore_truststore_path: Optional[str] = None,
        spark_hive_metastore_truststore_type: Optional[str] = None,
        spark_hive_metastore_use_ssl: Optional[str] = None,
        spark_sql_catalog_implementation: Optional[str] = None,
        spark_sql_catalog_lakehouse: Optional[str] = None,
        spark_sql_catalog_lakehouse_type: Optional[str] = None,
        spark_sql_catalog_lakehouse_uri: Optional[str] = None,
        spark_sql_extensions: Optional[str] = None,
        spark_sql_iceberg_vectorization_enabled: Optional[str] = None,
    ) -> None:
        """
        Initialize a SparkEngineApplicationStatusApplicationDetailsConf object.

        :param str spark_app_name: (optional) Spark application name.
        :param str spark_hive_metastore_client_auth_mode: (optional) Hive Metastore
               authentication mode.
        :param str spark_hive_metastore_client_plain_password: (optional) Hive
               Metastore plain password.
        :param str spark_hive_metastore_client_plain_username: (optional) Hive
               Metastore plain username.
        :param str spark_hive_metastore_truststore_password: (optional) Truststore
               password.
        :param str spark_hive_metastore_truststore_path: (optional) Truststore
               path.
        :param str spark_hive_metastore_truststore_type: (optional) Truststore
               type.
        :param str spark_hive_metastore_use_ssl: (optional) Enable or disable SSL
               for Hive Metastore.
        :param str spark_sql_catalog_implementation: (optional) SQL catalog
               implementation.
        :param str spark_sql_catalog_lakehouse: (optional) Lakehouse catalog name.
        :param str spark_sql_catalog_lakehouse_type: (optional) Lakehouse catalog
               type.
        :param str spark_sql_catalog_lakehouse_uri: (optional) Lakehouse catalog
               URI.
        :param str spark_sql_extensions: (optional) SQL extensions.
        :param str spark_sql_iceberg_vectorization_enabled: (optional) Enable or
               disable Iceberg vectorization.
        """
        self.spark_app_name = spark_app_name
        self.spark_hive_metastore_client_auth_mode = spark_hive_metastore_client_auth_mode
        self.spark_hive_metastore_client_plain_password = spark_hive_metastore_client_plain_password
        self.spark_hive_metastore_client_plain_username = spark_hive_metastore_client_plain_username
        self.spark_hive_metastore_truststore_password = spark_hive_metastore_truststore_password
        self.spark_hive_metastore_truststore_path = spark_hive_metastore_truststore_path
        self.spark_hive_metastore_truststore_type = spark_hive_metastore_truststore_type
        self.spark_hive_metastore_use_ssl = spark_hive_metastore_use_ssl
        self.spark_sql_catalog_implementation = spark_sql_catalog_implementation
        self.spark_sql_catalog_lakehouse = spark_sql_catalog_lakehouse
        self.spark_sql_catalog_lakehouse_type = spark_sql_catalog_lakehouse_type
        self.spark_sql_catalog_lakehouse_uri = spark_sql_catalog_lakehouse_uri
        self.spark_sql_extensions = spark_sql_extensions
        self.spark_sql_iceberg_vectorization_enabled = spark_sql_iceberg_vectorization_enabled

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SparkEngineApplicationStatusApplicationDetailsConf':
        """Initialize a SparkEngineApplicationStatusApplicationDetailsConf object from a json dictionary."""
        args = {}
        if 'spark_app_name' in _dict:
            args['spark_app_name'] = _dict.get('spark_app_name')
        if 'spark_hive_metastore_client_auth_mode' in _dict:
            args['spark_hive_metastore_client_auth_mode'] = _dict.get('spark_hive_metastore_client_auth_mode')
        if 'spark_hive_metastore_client_plain_password' in _dict:
            args['spark_hive_metastore_client_plain_password'] = _dict.get('spark_hive_metastore_client_plain_password')
        if 'spark_hive_metastore_client_plain_username' in _dict:
            args['spark_hive_metastore_client_plain_username'] = _dict.get('spark_hive_metastore_client_plain_username')
        if 'spark_hive_metastore_truststore_password' in _dict:
            args['spark_hive_metastore_truststore_password'] = _dict.get('spark_hive_metastore_truststore_password')
        if 'spark_hive_metastore_truststore_path' in _dict:
            args['spark_hive_metastore_truststore_path'] = _dict.get('spark_hive_metastore_truststore_path')
        if 'spark_hive_metastore_truststore_type' in _dict:
            args['spark_hive_metastore_truststore_type'] = _dict.get('spark_hive_metastore_truststore_type')
        if 'spark_hive_metastore_use_ssl' in _dict:
            args['spark_hive_metastore_use_ssl'] = _dict.get('spark_hive_metastore_use_ssl')
        if 'spark_sql_catalog_implementation' in _dict:
            args['spark_sql_catalog_implementation'] = _dict.get('spark_sql_catalog_implementation')
        if 'spark_sql_catalog_lakehouse' in _dict:
            args['spark_sql_catalog_lakehouse'] = _dict.get('spark_sql_catalog_lakehouse')
        if 'spark_sql_catalog_lakehouse_type' in _dict:
            args['spark_sql_catalog_lakehouse_type'] = _dict.get('spark_sql_catalog_lakehouse_type')
        if 'spark_sql_catalog_lakehouse_uri' in _dict:
            args['spark_sql_catalog_lakehouse_uri'] = _dict.get('spark_sql_catalog_lakehouse_uri')
        if 'spark_sql_extensions' in _dict:
            args['spark_sql_extensions'] = _dict.get('spark_sql_extensions')
        if 'spark_sql_iceberg_vectorization_enabled' in _dict:
            args['spark_sql_iceberg_vectorization_enabled'] = _dict.get('spark_sql_iceberg_vectorization_enabled')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SparkEngineApplicationStatusApplicationDetailsConf object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'spark_app_name') and self.spark_app_name is not None:
            _dict['spark_app_name'] = self.spark_app_name
        if (
            hasattr(self, 'spark_hive_metastore_client_auth_mode')
            and self.spark_hive_metastore_client_auth_mode is not None
        ):
            _dict['spark_hive_metastore_client_auth_mode'] = self.spark_hive_metastore_client_auth_mode
        if (
            hasattr(self, 'spark_hive_metastore_client_plain_password')
            and self.spark_hive_metastore_client_plain_password is not None
        ):
            _dict['spark_hive_metastore_client_plain_password'] = self.spark_hive_metastore_client_plain_password
        if (
            hasattr(self, 'spark_hive_metastore_client_plain_username')
            and self.spark_hive_metastore_client_plain_username is not None
        ):
            _dict['spark_hive_metastore_client_plain_username'] = self.spark_hive_metastore_client_plain_username
        if (
            hasattr(self, 'spark_hive_metastore_truststore_password')
            and self.spark_hive_metastore_truststore_password is not None
        ):
            _dict['spark_hive_metastore_truststore_password'] = self.spark_hive_metastore_truststore_password
        if (
            hasattr(self, 'spark_hive_metastore_truststore_path')
            and self.spark_hive_metastore_truststore_path is not None
        ):
            _dict['spark_hive_metastore_truststore_path'] = self.spark_hive_metastore_truststore_path
        if (
            hasattr(self, 'spark_hive_metastore_truststore_type')
            and self.spark_hive_metastore_truststore_type is not None
        ):
            _dict['spark_hive_metastore_truststore_type'] = self.spark_hive_metastore_truststore_type
        if hasattr(self, 'spark_hive_metastore_use_ssl') and self.spark_hive_metastore_use_ssl is not None:
            _dict['spark_hive_metastore_use_ssl'] = self.spark_hive_metastore_use_ssl
        if hasattr(self, 'spark_sql_catalog_implementation') and self.spark_sql_catalog_implementation is not None:
            _dict['spark_sql_catalog_implementation'] = self.spark_sql_catalog_implementation
        if hasattr(self, 'spark_sql_catalog_lakehouse') and self.spark_sql_catalog_lakehouse is not None:
            _dict['spark_sql_catalog_lakehouse'] = self.spark_sql_catalog_lakehouse
        if hasattr(self, 'spark_sql_catalog_lakehouse_type') and self.spark_sql_catalog_lakehouse_type is not None:
            _dict['spark_sql_catalog_lakehouse_type'] = self.spark_sql_catalog_lakehouse_type
        if hasattr(self, 'spark_sql_catalog_lakehouse_uri') and self.spark_sql_catalog_lakehouse_uri is not None:
            _dict['spark_sql_catalog_lakehouse_uri'] = self.spark_sql_catalog_lakehouse_uri
        if hasattr(self, 'spark_sql_extensions') and self.spark_sql_extensions is not None:
            _dict['spark_sql_extensions'] = self.spark_sql_extensions
        if (
            hasattr(self, 'spark_sql_iceberg_vectorization_enabled')
            and self.spark_sql_iceberg_vectorization_enabled is not None
        ):
            _dict['spark_sql_iceberg_vectorization_enabled'] = self.spark_sql_iceberg_vectorization_enabled
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SparkEngineApplicationStatusApplicationDetailsConf object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SparkEngineApplicationStatusApplicationDetailsConf') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SparkEngineApplicationStatusApplicationDetailsConf') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SparkEngineApplicationStatusStateDetailsItems:
    """
    State details.

    :param str code: (optional) State details code.
    :param str message: (optional) State details message.
    :param str type: (optional) State details type.
    """

    def __init__(
        self,
        *,
        code: Optional[str] = None,
        message: Optional[str] = None,
        type: Optional[str] = None,
    ) -> None:
        """
        Initialize a SparkEngineApplicationStatusStateDetailsItems object.

        :param str code: (optional) State details code.
        :param str message: (optional) State details message.
        :param str type: (optional) State details type.
        """
        self.code = code
        self.message = message
        self.type = type

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SparkEngineApplicationStatusStateDetailsItems':
        """Initialize a SparkEngineApplicationStatusStateDetailsItems object from a json dictionary."""
        args = {}
        if 'code' in _dict:
            args['code'] = _dict.get('code')
        if 'message' in _dict:
            args['message'] = _dict.get('message')
        if 'type' in _dict:
            args['type'] = _dict.get('type')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SparkEngineApplicationStatusStateDetailsItems object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'code') and self.code is not None:
            _dict['code'] = self.code
        if hasattr(self, 'message') and self.message is not None:
            _dict['message'] = self.message
        if hasattr(self, 'type') and self.type is not None:
            _dict['type'] = self.type
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SparkEngineApplicationStatusStateDetailsItems object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SparkEngineApplicationStatusStateDetailsItems') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SparkEngineApplicationStatusStateDetailsItems') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SparkEngineDetails:
    """
    External engine details.

    :param str connection_string: (optional) External engine connection string.
    :param SparkEngineDetailsEndpoints endpoints: (optional) Application Endpoints.
    """

    def __init__(
        self,
        *,
        connection_string: Optional[str] = None,
        endpoints: Optional['SparkEngineDetailsEndpoints'] = None,
    ) -> None:
        """
        Initialize a SparkEngineDetails object.

        :param str connection_string: (optional) External engine connection string.
        :param SparkEngineDetailsEndpoints endpoints: (optional) Application
               Endpoints.
        """
        self.connection_string = connection_string
        self.endpoints = endpoints

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SparkEngineDetails':
        """Initialize a SparkEngineDetails object from a json dictionary."""
        args = {}
        if 'connection_string' in _dict:
            args['connection_string'] = _dict.get('connection_string')
        if 'endpoints' in _dict:
            args['endpoints'] = SparkEngineDetailsEndpoints.from_dict(_dict.get('endpoints'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SparkEngineDetails object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'connection_string') and self.connection_string is not None:
            _dict['connection_string'] = self.connection_string
        if hasattr(self, 'endpoints') and self.endpoints is not None:
            if isinstance(self.endpoints, dict):
                _dict['endpoints'] = self.endpoints
            else:
                _dict['endpoints'] = self.endpoints.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SparkEngineDetails object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SparkEngineDetails') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SparkEngineDetails') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SparkEngineDetailsEndpoints:
    """
    Application Endpoints.

    :param str applications_api: (optional) Application API.
    :param str history_server_endpoint: (optional) History server endpoint.
    :param str spark_access_endpoint: (optional) Spark kernel endpoint.
    :param str spark_jobs_v4_endpoint: (optional) Spark jobs V4 endpoint.
    :param str spark_kernel_endpoint: (optional) Spark kernel endpoint.
    :param str view_history_server: (optional) View history server.
    :param str wxd_application_endpoint: (optional) Wxd application endpoint.
    """

    def __init__(
        self,
        *,
        applications_api: Optional[str] = None,
        history_server_endpoint: Optional[str] = None,
        spark_access_endpoint: Optional[str] = None,
        spark_jobs_v4_endpoint: Optional[str] = None,
        spark_kernel_endpoint: Optional[str] = None,
        view_history_server: Optional[str] = None,
        wxd_application_endpoint: Optional[str] = None,
    ) -> None:
        """
        Initialize a SparkEngineDetailsEndpoints object.

        :param str applications_api: (optional) Application API.
        :param str history_server_endpoint: (optional) History server endpoint.
        :param str spark_access_endpoint: (optional) Spark kernel endpoint.
        :param str spark_jobs_v4_endpoint: (optional) Spark jobs V4 endpoint.
        :param str spark_kernel_endpoint: (optional) Spark kernel endpoint.
        :param str view_history_server: (optional) View history server.
        :param str wxd_application_endpoint: (optional) Wxd application endpoint.
        """
        self.applications_api = applications_api
        self.history_server_endpoint = history_server_endpoint
        self.spark_access_endpoint = spark_access_endpoint
        self.spark_jobs_v4_endpoint = spark_jobs_v4_endpoint
        self.spark_kernel_endpoint = spark_kernel_endpoint
        self.view_history_server = view_history_server
        self.wxd_application_endpoint = wxd_application_endpoint

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SparkEngineDetailsEndpoints':
        """Initialize a SparkEngineDetailsEndpoints object from a json dictionary."""
        args = {}
        if 'applications_api' in _dict:
            args['applications_api'] = _dict.get('applications_api')
        if 'history_server_endpoint' in _dict:
            args['history_server_endpoint'] = _dict.get('history_server_endpoint')
        if 'spark_access_endpoint' in _dict:
            args['spark_access_endpoint'] = _dict.get('spark_access_endpoint')
        if 'spark_jobs_v4_endpoint' in _dict:
            args['spark_jobs_v4_endpoint'] = _dict.get('spark_jobs_v4_endpoint')
        if 'spark_kernel_endpoint' in _dict:
            args['spark_kernel_endpoint'] = _dict.get('spark_kernel_endpoint')
        if 'view_history_server' in _dict:
            args['view_history_server'] = _dict.get('view_history_server')
        if 'wxd_application_endpoint' in _dict:
            args['wxd_application_endpoint'] = _dict.get('wxd_application_endpoint')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SparkEngineDetailsEndpoints object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'applications_api') and self.applications_api is not None:
            _dict['applications_api'] = self.applications_api
        if hasattr(self, 'history_server_endpoint') and self.history_server_endpoint is not None:
            _dict['history_server_endpoint'] = self.history_server_endpoint
        if hasattr(self, 'spark_access_endpoint') and self.spark_access_endpoint is not None:
            _dict['spark_access_endpoint'] = self.spark_access_endpoint
        if hasattr(self, 'spark_jobs_v4_endpoint') and self.spark_jobs_v4_endpoint is not None:
            _dict['spark_jobs_v4_endpoint'] = self.spark_jobs_v4_endpoint
        if hasattr(self, 'spark_kernel_endpoint') and self.spark_kernel_endpoint is not None:
            _dict['spark_kernel_endpoint'] = self.spark_kernel_endpoint
        if hasattr(self, 'view_history_server') and self.view_history_server is not None:
            _dict['view_history_server'] = self.view_history_server
        if hasattr(self, 'wxd_application_endpoint') and self.wxd_application_endpoint is not None:
            _dict['wxd_application_endpoint'] = self.wxd_application_endpoint
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SparkEngineDetailsEndpoints object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SparkEngineDetailsEndpoints') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SparkEngineDetailsEndpoints') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SparkEngineDetailsPrototype:
    """
    Node details.

    :param str api_key: (optional) api key to work with the saas IAE instance.
    :param str connection_string: (optional) External engine connection string.
    :param str instance_id: (optional) Instance to access the instance.
    :param str managed_by: (optional) How is the spark instance managed.
    """

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        connection_string: Optional[str] = None,
        instance_id: Optional[str] = None,
        managed_by: Optional[str] = None,
    ) -> None:
        """
        Initialize a SparkEngineDetailsPrototype object.

        :param str api_key: (optional) api key to work with the saas IAE instance.
        :param str connection_string: (optional) External engine connection string.
        :param str instance_id: (optional) Instance to access the instance.
        :param str managed_by: (optional) How is the spark instance managed.
        """
        self.api_key = api_key
        self.connection_string = connection_string
        self.instance_id = instance_id
        self.managed_by = managed_by

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SparkEngineDetailsPrototype':
        """Initialize a SparkEngineDetailsPrototype object from a json dictionary."""
        args = {}
        if 'api_key' in _dict:
            args['api_key'] = _dict.get('api_key')
        if 'connection_string' in _dict:
            args['connection_string'] = _dict.get('connection_string')
        if 'instance_id' in _dict:
            args['instance_id'] = _dict.get('instance_id')
        if 'managed_by' in _dict:
            args['managed_by'] = _dict.get('managed_by')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SparkEngineDetailsPrototype object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'api_key') and self.api_key is not None:
            _dict['api_key'] = self.api_key
        if hasattr(self, 'connection_string') and self.connection_string is not None:
            _dict['connection_string'] = self.connection_string
        if hasattr(self, 'instance_id') and self.instance_id is not None:
            _dict['instance_id'] = self.instance_id
        if hasattr(self, 'managed_by') and self.managed_by is not None:
            _dict['managed_by'] = self.managed_by
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SparkEngineDetailsPrototype object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SparkEngineDetailsPrototype') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SparkEngineDetailsPrototype') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SuccessResponse:
    """
    Response of success.

    :param str message: (optional) Message.
    :param str message_code: (optional) Message code.
    """

    def __init__(
        self,
        *,
        message: Optional[str] = None,
        message_code: Optional[str] = None,
    ) -> None:
        """
        Initialize a SuccessResponse object.

        :param str message: (optional) Message.
        :param str message_code: (optional) Message code.
        """
        self.message = message
        self.message_code = message_code

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SuccessResponse':
        """Initialize a SuccessResponse object from a json dictionary."""
        args = {}
        if 'message' in _dict:
            args['message'] = _dict.get('message')
        if 'message_code' in _dict:
            args['message_code'] = _dict.get('message_code')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessResponse object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'message') and self.message is not None:
            _dict['message'] = self.message
        if hasattr(self, 'message_code') and self.message_code is not None:
            _dict['message_code'] = self.message_code
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

    :param str committed_at: (optional) Committed at.
    :param str operation: (optional) Operation.
    :param str snapshot_id: (optional) Snapshot id.
    :param dict summary: (optional) Summary.
    """

    def __init__(
        self,
        *,
        committed_at: Optional[str] = None,
        operation: Optional[str] = None,
        snapshot_id: Optional[str] = None,
        summary: Optional[dict] = None,
    ) -> None:
        """
        Initialize a TableSnapshot object.

        :param str committed_at: (optional) Committed at.
        :param str operation: (optional) Operation.
        :param str snapshot_id: (optional) Snapshot id.
        :param dict summary: (optional) Summary.
        """
        self.committed_at = committed_at
        self.operation = operation
        self.snapshot_id = snapshot_id
        self.summary = summary

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'TableSnapshot':
        """Initialize a TableSnapshot object from a json dictionary."""
        args = {}
        if 'committed_at' in _dict:
            args['committed_at'] = _dict.get('committed_at')
        if 'operation' in _dict:
            args['operation'] = _dict.get('operation')
        if 'snapshot_id' in _dict:
            args['snapshot_id'] = _dict.get('snapshot_id')
        if 'summary' in _dict:
            args['summary'] = _dict.get('summary')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a TableSnapshot object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'committed_at') and self.committed_at is not None:
            _dict['committed_at'] = self.committed_at
        if hasattr(self, 'operation') and self.operation is not None:
            _dict['operation'] = self.operation
        if hasattr(self, 'snapshot_id') and self.snapshot_id is not None:
            _dict['snapshot_id'] = self.snapshot_id
        if hasattr(self, 'summary') and self.summary is not None:
            _dict['summary'] = self.summary
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


class TestBucketConnectionOKBody:
    """
    ValidateBucketRegistrationCredentials OK.

    :param BucketStatusResponse bucket_status: object defining the response of
          checking if the credentials of a bucket are valid.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        bucket_status: 'BucketStatusResponse',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a TestBucketConnectionOKBody object.

        :param BucketStatusResponse bucket_status: object defining the response of
               checking if the credentials of a bucket are valid.
        :param SuccessResponse response: Response of success.
        """
        self.bucket_status = bucket_status
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'TestBucketConnectionOKBody':
        """Initialize a TestBucketConnectionOKBody object from a json dictionary."""
        args = {}
        if 'bucket_status' in _dict:
            args['bucket_status'] = BucketStatusResponse.from_dict(_dict.get('bucket_status'))
        else:
            raise ValueError('Required property \'bucket_status\' not present in TestBucketConnectionOKBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in TestBucketConnectionOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a TestBucketConnectionOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'bucket_status') and self.bucket_status is not None:
            if isinstance(self.bucket_status, dict):
                _dict['bucket_status'] = self.bucket_status
            else:
                _dict['bucket_status'] = self.bucket_status.to_dict()
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
        """Return a `str` version of this TestBucketConnectionOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'TestBucketConnectionOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'TestBucketConnectionOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class UpdateBucketRegistrationOKBody:
    """
    UpdateBucketRegistration OK.

    :param BucketRegistration bucket_registration: Bucket.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        bucket_registration: 'BucketRegistration',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a UpdateBucketRegistrationOKBody object.

        :param BucketRegistration bucket_registration: Bucket.
        :param SuccessResponse response: Response of success.
        """
        self.bucket_registration = bucket_registration
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'UpdateBucketRegistrationOKBody':
        """Initialize a UpdateBucketRegistrationOKBody object from a json dictionary."""
        args = {}
        if 'bucket_registration' in _dict:
            args['bucket_registration'] = BucketRegistration.from_dict(_dict.get('bucket_registration'))
        else:
            raise ValueError(
                'Required property \'bucket_registration\' not present in UpdateBucketRegistrationOKBody JSON'
            )
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in UpdateBucketRegistrationOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a UpdateBucketRegistrationOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'bucket_registration') and self.bucket_registration is not None:
            if isinstance(self.bucket_registration, dict):
                _dict['bucket_registration'] = self.bucket_registration
            else:
                _dict['bucket_registration'] = self.bucket_registration.to_dict()
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
        """Return a `str` version of this UpdateBucketRegistrationOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'UpdateBucketRegistrationOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'UpdateBucketRegistrationOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class UpdateDatabaseOKBody:
    """
    get databases success response body.

    :param DatabaseRegistration database: database registration object.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        database: 'DatabaseRegistration',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a UpdateDatabaseOKBody object.

        :param DatabaseRegistration database: database registration object.
        :param SuccessResponse response: Response of success.
        """
        self.database = database
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'UpdateDatabaseOKBody':
        """Initialize a UpdateDatabaseOKBody object from a json dictionary."""
        args = {}
        if 'database' in _dict:
            args['database'] = DatabaseRegistration.from_dict(_dict.get('database'))
        else:
            raise ValueError('Required property \'database\' not present in UpdateDatabaseOKBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in UpdateDatabaseOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a UpdateDatabaseOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'database') and self.database is not None:
            if isinstance(self.database, dict):
                _dict['database'] = self.database
            else:
                _dict['database'] = self.database.to_dict()
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
        """Return a `str` version of this UpdateDatabaseOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'UpdateDatabaseOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'UpdateDatabaseOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class UpdateDb2EngineOKBody:
    """
    update engine response.

    :param Db2Engine db2_engine: Db2 engine details.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        db2_engine: 'Db2Engine',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a UpdateDb2EngineOKBody object.

        :param Db2Engine db2_engine: Db2 engine details.
        :param SuccessResponse response: Response of success.
        """
        self.db2_engine = db2_engine
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'UpdateDb2EngineOKBody':
        """Initialize a UpdateDb2EngineOKBody object from a json dictionary."""
        args = {}
        if 'db2_engine' in _dict:
            args['db2_engine'] = Db2Engine.from_dict(_dict.get('db2_engine'))
        else:
            raise ValueError('Required property \'db2_engine\' not present in UpdateDb2EngineOKBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in UpdateDb2EngineOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a UpdateDb2EngineOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'db2_engine') and self.db2_engine is not None:
            if isinstance(self.db2_engine, dict):
                _dict['db2_engine'] = self.db2_engine
            else:
                _dict['db2_engine'] = self.db2_engine.to_dict()
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
        """Return a `str` version of this UpdateDb2EngineOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'UpdateDb2EngineOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'UpdateDb2EngineOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class UpdateEngineOKBody:
    """
    update engine response.

    :param PrestoEngine engine: EngineDetail.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        engine: 'PrestoEngine',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a UpdateEngineOKBody object.

        :param PrestoEngine engine: EngineDetail.
        :param SuccessResponse response: Response of success.
        """
        self.engine = engine
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'UpdateEngineOKBody':
        """Initialize a UpdateEngineOKBody object from a json dictionary."""
        args = {}
        if 'engine' in _dict:
            args['engine'] = PrestoEngine.from_dict(_dict.get('engine'))
        else:
            raise ValueError('Required property \'engine\' not present in UpdateEngineOKBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in UpdateEngineOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a UpdateEngineOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'engine') and self.engine is not None:
            if isinstance(self.engine, dict):
                _dict['engine'] = self.engine
            else:
                _dict['engine'] = self.engine.to_dict()
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
        """Return a `str` version of this UpdateEngineOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'UpdateEngineOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'UpdateEngineOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class UpdateNetezzaEngineOKBody:
    """
    update engine response.

    :param NetezzaEngine netezza_engine: Netezza engine details.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        netezza_engine: 'NetezzaEngine',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a UpdateNetezzaEngineOKBody object.

        :param NetezzaEngine netezza_engine: Netezza engine details.
        :param SuccessResponse response: Response of success.
        """
        self.netezza_engine = netezza_engine
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'UpdateNetezzaEngineOKBody':
        """Initialize a UpdateNetezzaEngineOKBody object from a json dictionary."""
        args = {}
        if 'netezza_engine' in _dict:
            args['netezza_engine'] = NetezzaEngine.from_dict(_dict.get('netezza_engine'))
        else:
            raise ValueError('Required property \'netezza_engine\' not present in UpdateNetezzaEngineOKBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in UpdateNetezzaEngineOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a UpdateNetezzaEngineOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'netezza_engine') and self.netezza_engine is not None:
            if isinstance(self.netezza_engine, dict):
                _dict['netezza_engine'] = self.netezza_engine
            else:
                _dict['netezza_engine'] = self.netezza_engine.to_dict()
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
        """Return a `str` version of this UpdateNetezzaEngineOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'UpdateNetezzaEngineOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'UpdateNetezzaEngineOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class UpdateSparkEngineOKBody:
    """
    update engine response.

    :param SparkEngine engine: EngineDetail.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        engine: 'SparkEngine',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a UpdateSparkEngineOKBody object.

        :param SparkEngine engine: EngineDetail.
        :param SuccessResponse response: Response of success.
        """
        self.engine = engine
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'UpdateSparkEngineOKBody':
        """Initialize a UpdateSparkEngineOKBody object from a json dictionary."""
        args = {}
        if 'engine' in _dict:
            args['engine'] = SparkEngine.from_dict(_dict.get('engine'))
        else:
            raise ValueError('Required property \'engine\' not present in UpdateSparkEngineOKBody JSON')
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in UpdateSparkEngineOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a UpdateSparkEngineOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'engine') and self.engine is not None:
            if isinstance(self.engine, dict):
                _dict['engine'] = self.engine
            else:
                _dict['engine'] = self.engine.to_dict()
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
        """Return a `str` version of this UpdateSparkEngineOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'UpdateSparkEngineOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'UpdateSparkEngineOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class UpdateSyncCatalogOKBody:
    """
    success response.

    :param SuccessResponse response: (optional) Response of success.
    """

    def __init__(
        self,
        *,
        response: Optional['SuccessResponse'] = None,
    ) -> None:
        """
        Initialize a UpdateSyncCatalogOKBody object.

        :param SuccessResponse response: (optional) Response of success.
        """
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'UpdateSyncCatalogOKBody':
        """Initialize a UpdateSyncCatalogOKBody object from a json dictionary."""
        args = {}
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a UpdateSyncCatalogOKBody object from a json dictionary."""
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
        """Return a `str` version of this UpdateSyncCatalogOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'UpdateSyncCatalogOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'UpdateSyncCatalogOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class UpdateTableOKBody:
    """
    success response.

    :param SuccessResponse response: (optional) Response of success.
    """

    def __init__(
        self,
        *,
        response: Optional['SuccessResponse'] = None,
    ) -> None:
        """
        Initialize a UpdateTableOKBody object.

        :param SuccessResponse response: (optional) Response of success.
        """
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'UpdateTableOKBody':
        """Initialize a UpdateTableOKBody object from a json dictionary."""
        args = {}
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a UpdateTableOKBody object from a json dictionary."""
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
        """Return a `str` version of this UpdateTableOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'UpdateTableOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'UpdateTableOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ValidateDatabaseBodyDatabaseDetails:
    """
    database details.

    :param str database_name: (optional) db name.
    :param str hostname: Host name.
    :param str password: (optional) Psssword.
    :param int port: Port.
    :param bool sasl: (optional) SASL Mode.
    :param bool ssl: (optional) SSL Mode.
    :param str tables: (optional) Only for Kafka - Add kafka tables.
    :param str username: (optional) Username.
    """

    def __init__(
        self,
        hostname: str,
        port: int,
        *,
        database_name: Optional[str] = None,
        password: Optional[str] = None,
        sasl: Optional[bool] = None,
        ssl: Optional[bool] = None,
        tables: Optional[str] = None,
        username: Optional[str] = None,
    ) -> None:
        """
        Initialize a ValidateDatabaseBodyDatabaseDetails object.

        :param str hostname: Host name.
        :param int port: Port.
        :param str database_name: (optional) db name.
        :param str password: (optional) Psssword.
        :param bool sasl: (optional) SASL Mode.
        :param bool ssl: (optional) SSL Mode.
        :param str tables: (optional) Only for Kafka - Add kafka tables.
        :param str username: (optional) Username.
        """
        self.database_name = database_name
        self.hostname = hostname
        self.password = password
        self.port = port
        self.sasl = sasl
        self.ssl = ssl
        self.tables = tables
        self.username = username

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ValidateDatabaseBodyDatabaseDetails':
        """Initialize a ValidateDatabaseBodyDatabaseDetails object from a json dictionary."""
        args = {}
        if 'database_name' in _dict:
            args['database_name'] = _dict.get('database_name')
        if 'hostname' in _dict:
            args['hostname'] = _dict.get('hostname')
        else:
            raise ValueError('Required property \'hostname\' not present in ValidateDatabaseBodyDatabaseDetails JSON')
        if 'password' in _dict:
            args['password'] = _dict.get('password')
        if 'port' in _dict:
            args['port'] = _dict.get('port')
        else:
            raise ValueError('Required property \'port\' not present in ValidateDatabaseBodyDatabaseDetails JSON')
        if 'sasl' in _dict:
            args['sasl'] = _dict.get('sasl')
        if 'ssl' in _dict:
            args['ssl'] = _dict.get('ssl')
        if 'tables' in _dict:
            args['tables'] = _dict.get('tables')
        if 'username' in _dict:
            args['username'] = _dict.get('username')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ValidateDatabaseBodyDatabaseDetails object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'database_name') and self.database_name is not None:
            _dict['database_name'] = self.database_name
        if hasattr(self, 'hostname') and self.hostname is not None:
            _dict['hostname'] = self.hostname
        if hasattr(self, 'password') and self.password is not None:
            _dict['password'] = self.password
        if hasattr(self, 'port') and self.port is not None:
            _dict['port'] = self.port
        if hasattr(self, 'sasl') and self.sasl is not None:
            _dict['sasl'] = self.sasl
        if hasattr(self, 'ssl') and self.ssl is not None:
            _dict['ssl'] = self.ssl
        if hasattr(self, 'tables') and self.tables is not None:
            _dict['tables'] = self.tables
        if hasattr(self, 'username') and self.username is not None:
            _dict['username'] = self.username
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ValidateDatabaseBodyDatabaseDetails object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ValidateDatabaseBodyDatabaseDetails') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ValidateDatabaseBodyDatabaseDetails') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ValidateDatabaseConnectionOKBody:
    """
    success response.

    :param ValidateDatabaseConnectionOKBodyConnectionResponse connection_response:
          validate db response.
    :param SuccessResponse response: Response of success.
    """

    def __init__(
        self,
        connection_response: 'ValidateDatabaseConnectionOKBodyConnectionResponse',
        response: 'SuccessResponse',
    ) -> None:
        """
        Initialize a ValidateDatabaseConnectionOKBody object.

        :param ValidateDatabaseConnectionOKBodyConnectionResponse
               connection_response: validate db response.
        :param SuccessResponse response: Response of success.
        """
        self.connection_response = connection_response
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ValidateDatabaseConnectionOKBody':
        """Initialize a ValidateDatabaseConnectionOKBody object from a json dictionary."""
        args = {}
        if 'connection_response' in _dict:
            args['connection_response'] = ValidateDatabaseConnectionOKBodyConnectionResponse.from_dict(
                _dict.get('connection_response')
            )
        else:
            raise ValueError(
                'Required property \'connection_response\' not present in ValidateDatabaseConnectionOKBody JSON'
            )
        if 'response' in _dict:
            args['response'] = SuccessResponse.from_dict(_dict.get('response'))
        else:
            raise ValueError('Required property \'response\' not present in ValidateDatabaseConnectionOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ValidateDatabaseConnectionOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'connection_response') and self.connection_response is not None:
            if isinstance(self.connection_response, dict):
                _dict['connection_response'] = self.connection_response
            else:
                _dict['connection_response'] = self.connection_response.to_dict()
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
        """Return a `str` version of this ValidateDatabaseConnectionOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ValidateDatabaseConnectionOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ValidateDatabaseConnectionOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ValidateDatabaseConnectionOKBodyConnectionResponse:
    """
    validate db response.

    :param bool state: (optional) whether the connection details are valid or not.
    :param str state_message: (optional) Connection message received by connector
          libraries for failed connection.
    """

    def __init__(
        self,
        *,
        state: Optional[bool] = None,
        state_message: Optional[str] = None,
    ) -> None:
        """
        Initialize a ValidateDatabaseConnectionOKBodyConnectionResponse object.

        :param bool state: (optional) whether the connection details are valid or
               not.
        :param str state_message: (optional) Connection message received by
               connector libraries for failed connection.
        """
        self.state = state
        self.state_message = state_message

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ValidateDatabaseConnectionOKBodyConnectionResponse':
        """Initialize a ValidateDatabaseConnectionOKBodyConnectionResponse object from a json dictionary."""
        args = {}
        if 'state' in _dict:
            args['state'] = _dict.get('state')
        if 'state_message' in _dict:
            args['state_message'] = _dict.get('state_message')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ValidateDatabaseConnectionOKBodyConnectionResponse object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'state') and self.state is not None:
            _dict['state'] = self.state
        if hasattr(self, 'state_message') and self.state_message is not None:
            _dict['state_message'] = self.state_message
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ValidateDatabaseConnectionOKBodyConnectionResponse object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ValidateDatabaseConnectionOKBodyConnectionResponse') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ValidateDatabaseConnectionOKBodyConnectionResponse') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other
