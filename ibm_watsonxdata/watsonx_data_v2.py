# coding: utf-8

# (C) Copyright IBM Corp. 2024.
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

# IBM OpenAPI SDK Code Generator Version: 3.97.0-0e90eab1-20241120-170029

"""
This is the Public API for IBM watsonx.data

API Version: 2.0.0
"""

from enum import Enum
from typing import BinaryIO, Dict, List, Optional
import json

from ibm_cloud_sdk_core import BaseService, DetailedResponse, get_query_param
from ibm_cloud_sdk_core.authenticators.authenticator import Authenticator
from ibm_cloud_sdk_core.get_authenticator import get_authenticator_from_environment
from ibm_cloud_sdk_core.utils import convert_list, convert_model

from .common import get_sdk_headers

##############################################################################
# Service
##############################################################################


class WatsonxDataV2(BaseService):
    """The watsonx.data V2 service."""

    DEFAULT_SERVICE_URL = 'https://region.lakehouse.cloud.ibm.com/lakehouse/api/v2'
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
        service = cls(
            authenticator
            )
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
        :rtype: DetailedResponse with `dict` result representing a `BucketRegistrationCollection` object
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
        bucket_type: str,
        description: str,
        managed_by: str,
        *,
        associated_catalog: Optional['BucketCatalog'] = None,
        bucket_details: Optional['BucketDetails'] = None,
        bucket_display_name: Optional[str] = None,
        region: Optional[str] = None,
        storage_details: Optional['StorageDetails'] = None,
        tags: Optional[List[str]] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Register bucket.

        Register a new bucket.

        :param str bucket_type: bucket type.
        :param str description: bucket description.
        :param str managed_by: managed by.
        :param BucketCatalog associated_catalog: (optional) bucket catalog.
        :param BucketDetails bucket_details: (optional) bucket details.
        :param str bucket_display_name: (optional) bucket display name.
        :param str region: (optional) region where the bucket is located.
        :param StorageDetails storage_details: (optional) storage details.
        :param List[str] tags: (optional) tags.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `BucketRegistration` object
        """

        if bucket_type is None:
            raise ValueError('bucket_type must be provided')
        if description is None:
            raise ValueError('description must be provided')
        if managed_by is None:
            raise ValueError('managed_by must be provided')
        if associated_catalog is not None:
            associated_catalog = convert_model(associated_catalog)
        if bucket_details is not None:
            bucket_details = convert_model(bucket_details)
        if storage_details is not None:
            storage_details = convert_model(storage_details)
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
            'bucket_type': bucket_type,
            'description': description,
            'managed_by': managed_by,
            'associated_catalog': associated_catalog,
            'bucket_details': bucket_details,
            'bucket_display_name': bucket_display_name,
            'region': region,
            'storage_details': storage_details,
            'tags': tags,
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
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `BucketRegistration` object
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
        Deregister Bucket.

        Deregister a bucket.

        :param str bucket_id: bucket id.
        :param str auth_instance_id: (optional) CRN.
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
        body: 'BucketRegistrationPatch',
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Update bucket.

        Update bucket details & credentials.

        :param str bucket_id: bucket id.
        :param BucketRegistrationPatch body: Request body.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `BucketRegistration` object
        """

        if not bucket_id:
            raise ValueError('bucket_id must be provided')
        if body is None:
            raise ValueError('body must be provided')
        if isinstance(body, BucketRegistrationPatch):
            body = convert_model(body)
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
        headers['content-type'] = 'application/merge-patch+json'

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
        :param str auth_instance_id: (optional) CRN.
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
        :param str auth_instance_id: (optional) CRN.
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
        path: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        List bucket objects.

        Fetch all objects from a given bucket.

        :param str bucket_id: bucket id.
        :param str auth_instance_id: (optional) Instance ID.
        :param str path: (optional) path.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `BucketRegistrationObjectCollection` object
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

        params = {
            'path': path,
        }

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
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def get_bucket_object_properties(
        self,
        bucket_id: str,
        *,
        paths: Optional[List['Path']] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get bucket object properties.

        Get bucket object properties.

        :param str bucket_id: bucket id.
        :param List[Path] paths: (optional) bucket object size.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `BucketObjectProperties` object
        """

        if not bucket_id:
            raise ValueError('bucket_id must be provided')
        if paths is not None:
            paths = [convert_model(x) for x in paths]
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_bucket_object_properties',
        )
        headers.update(sdk_headers)

        data = {
            'paths': paths,
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
        url = '/bucket_registrations/{bucket_id}/object_properties'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def create_hdfs_storage(
        self,
        bucket_display_name: str,
        bucket_type: str,
        hms_thrift_uri: str,
        hms_thrift_port: int,
        core_site: str,
        hdfs_site: str,
        kerberos: str,
        catalog_name: str,
        catalog_type: str,
        *,
        krb5_config: Optional[str] = None,
        hive_keytab: Optional[BinaryIO] = None,
        hive_keytab_content_type: Optional[str] = None,
        hdfs_keytab: Optional[BinaryIO] = None,
        hdfs_keytab_content_type: Optional[str] = None,
        hive_server_principal: Optional[str] = None,
        hive_client_principal: Optional[str] = None,
        hdfs_principal: Optional[str] = None,
        description: Optional[str] = None,
        created_on: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Add/Create HDFS storage.

        Add or create a new HDFS database.

        :param str bucket_display_name: Bucket display name.
        :param str bucket_type: Bucket type.
        :param str hms_thrift_uri: HMS Thrift URI.
        :param int hms_thrift_port: HMS Thrift Port.
        :param str core_site: contents of core-site.xml file.
        :param str hdfs_site: contents of hdfs-site.xml file.
        :param str kerberos: Kerberos Flag.
        :param str catalog_name: Catalog name.
        :param str catalog_type: Catalog type.
        :param str krb5_config: (optional) Kerberos config file.
        :param BinaryIO hive_keytab: (optional) Hive keytab file.
        :param str hive_keytab_content_type: (optional) The content type of
               hive_keytab.
        :param BinaryIO hdfs_keytab: (optional) HDFS keytab file.
        :param str hdfs_keytab_content_type: (optional) The content type of
               hdfs_keytab.
        :param str hive_server_principal: (optional) Hive server principal.
        :param str hive_client_principal: (optional) Hive client principal.
        :param str hdfs_principal: (optional) HDFS principal.
        :param str description: (optional) Database description.
        :param str created_on: (optional) Created on.
        :param str auth_instance_id: (optional) Instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `HdfsStorageRegistration` object
        """

        if not bucket_display_name:
            raise ValueError('bucket_display_name must be provided')
        if not bucket_type:
            raise ValueError('bucket_type must be provided')
        if not hms_thrift_uri:
            raise ValueError('hms_thrift_uri must be provided')
        if hms_thrift_port is None:
            raise ValueError('hms_thrift_port must be provided')
        if not core_site:
            raise ValueError('core_site must be provided')
        if not hdfs_site:
            raise ValueError('hdfs_site must be provided')
        if not kerberos:
            raise ValueError('kerberos must be provided')
        if not catalog_name:
            raise ValueError('catalog_name must be provided')
        if not catalog_type:
            raise ValueError('catalog_type must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_hdfs_storage',
        )
        headers.update(sdk_headers)

        form_data = []
        form_data.append(('bucket_display_name', (None, bucket_display_name, 'text/plain')))
        form_data.append(('bucket_type', (None, bucket_type, 'text/plain')))
        form_data.append(('hms_thrift_uri', (None, hms_thrift_uri, 'text/plain')))
        form_data.append(('hms_thrift_port', (None, str(hms_thrift_port), 'text/plain')))
        form_data.append(('core_site', (None, core_site, 'text/plain')))
        form_data.append(('hdfs_site', (None, hdfs_site, 'text/plain')))
        form_data.append(('kerberos', (None, kerberos, 'text/plain')))
        form_data.append(('catalog_name', (None, catalog_name, 'text/plain')))
        form_data.append(('catalog_type', (None, catalog_type, 'text/plain')))
        if krb5_config:
            form_data.append(('krb5_config', (None, krb5_config, 'text/plain')))
        if hive_keytab:
            form_data.append(('hive_keytab', (None, hive_keytab, hive_keytab_content_type or 'application/octet-stream')))
        if hdfs_keytab:
            form_data.append(('hdfs_keytab', (None, hdfs_keytab, hdfs_keytab_content_type or 'application/octet-stream')))
        if hive_server_principal:
            form_data.append(('hive_server_principal', (None, hive_server_principal, 'text/plain')))
        if hive_client_principal:
            form_data.append(('hive_client_principal', (None, hive_client_principal, 'text/plain')))
        if hdfs_principal:
            form_data.append(('hdfs_principal', (None, hdfs_principal, 'text/plain')))
        if description:
            form_data.append(('description', (None, description, 'text/plain')))
        if created_on:
            form_data.append(('created_on', (None, created_on, 'text/plain')))

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/storage_hdfs_registrations'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            files=form_data,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # databases
    #########################

    def list_database_registrations(
        self,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get databases.

        Get list of databases.

        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `DatabaseRegistrationCollection` object
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
        database_display_name: str,
        database_type: str,
        *,
        associated_catalog: Optional['DatabaseCatalog'] = None,
        created_on: Optional[str] = None,
        database_details: Optional['DatabaseDetails'] = None,
        database_properties: Optional[List['DatabaseRegistrationPrototypeDatabasePropertiesItems']] = None,
        description: Optional[str] = None,
        tags: Optional[List[str]] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Add/Create database.

        Add or create a new database.

        :param str database_display_name: Database display name.
        :param str database_type: Connector type.
        :param DatabaseCatalog associated_catalog: (optional) database catalog.
        :param str created_on: (optional) Created on.
        :param DatabaseDetails database_details: (optional) database details.
        :param List[DatabaseRegistrationPrototypeDatabasePropertiesItems]
               database_properties: (optional) This will hold all the properties for a
               custom database.
        :param str description: (optional) Database description.
        :param List[str] tags: (optional) tags.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `DatabaseRegistration` object
        """

        if database_display_name is None:
            raise ValueError('database_display_name must be provided')
        if database_type is None:
            raise ValueError('database_type must be provided')
        if associated_catalog is not None:
            associated_catalog = convert_model(associated_catalog)
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
            'database_display_name': database_display_name,
            'database_type': database_type,
            'associated_catalog': associated_catalog,
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

        Get a registered databases.

        :param str database_id: database id.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `DatabaseRegistration` object
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
        :param str auth_instance_id: (optional) CRN.
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
        body: 'DatabaseRegistrationPatch',
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Update database.

        Update database details.

        :param str database_id: database id.
        :param DatabaseRegistrationPatch body: Request body.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `DatabaseRegistration` object
        """

        if not database_id:
            raise ValueError('database_id must be provided')
        if body is None:
            raise ValueError('body must be provided')
        if isinstance(body, DatabaseRegistrationPatch):
            body = convert_model(body)
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
        headers['content-type'] = 'application/merge-patch+json'

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

    #########################
    # other_engines
    #########################

    def list_other_engines(
        self,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        List other engines.

        list all other engine details.

        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `OtherEngineCollection` object
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
        engine_details: 'OtherEngineDetailsBody',
        engine_display_name: str,
        *,
        description: Optional[str] = None,
        origin: Optional[str] = None,
        tags: Optional[List[str]] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Create other engine.

        Create a new engine.

        :param OtherEngineDetailsBody engine_details: External engine details.
        :param str engine_display_name: engine display name.
        :param str description: (optional) engine description.
        :param str origin: (optional) Origin - created or registered.
        :param List[str] tags: (optional) other engine tags.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `OtherEngine` object
        """

        if engine_details is None:
            raise ValueError('engine_details must be provided')
        if engine_display_name is None:
            raise ValueError('engine_display_name must be provided')
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
            'engine_details': engine_details,
            'engine_display_name': engine_display_name,
            'description': description,
            'origin': origin,
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
        :param str auth_instance_id: (optional) CRN.
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

    #########################
    # integrations
    #########################

    def list_all_integrations(
        self,
        *,
        auth_instance_id: Optional[str] = None,
        secret: Optional[str] = None,
        service_type: Optional[str] = None,
        state: Optional[List[str]] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get all existing Integrations.

        Get all existing Integrations.

        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param str secret: (optional) API Authentication service token.
        :param str service_type: (optional) service_type.
        :param List[str] state: (optional) state.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `IntegrationCollection` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
            'Secret': secret,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='list_all_integrations',
        )
        headers.update(sdk_headers)

        params = {
            'service_type': service_type,
            'state': convert_list(state),
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/integrations'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def create_integration(
        self,
        *,
        apikey: Optional[str] = None,
        enable_data_policy_within_wxd: Optional[bool] = None,
        password: Optional[str] = None,
        resource: Optional[str] = None,
        service_type: Optional[str] = None,
        storage_catalogs: Optional[List[str]] = None,
        url: Optional[str] = None,
        username: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        To register an integration.

        To register an integration.

        :param str apikey: (optional) Integration APIKEY.
        :param bool enable_data_policy_within_wxd: (optional) data policy enabler
               with wxd for ranger.
        :param str password: (optional) Integration password.
        :param str resource: (optional) resouce for ranger.
        :param str service_type: (optional) Integration type.
        :param List[str] storage_catalogs: (optional) Comma separated list of
               bucket catalogs which have ikc enabled.
        :param str url: (optional) Integration Connection URL.
        :param str username: (optional) Integration username.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `Integration` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_integration',
        )
        headers.update(sdk_headers)

        data = {
            'apikey': apikey,
            'enable_data_policy_within_wxd': enable_data_policy_within_wxd,
            'password': password,
            'resource': resource,
            'service_type': service_type,
            'storage_catalogs': storage_catalogs,
            'url': url,
            'username': username,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/integrations'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_integrations(
        self,
        integration_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        secret: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get an Integration.

        Get an Integration.

        :param str integration_id: integration_id.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param str secret: (optional) API Authentication service token.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `Integration` object
        """

        if not integration_id:
            raise ValueError('integration_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
            'Secret': secret,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_integrations',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['integration_id']
        path_param_values = self.encode_path_vars(integration_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/integrations/{integration_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_integration(
        self,
        integration_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Remove an Integration.

        Remove an Integration.

        :param str integration_id: integration_id.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not integration_id:
            raise ValueError('integration_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='delete_integration',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['integration_id']
        path_param_values = self.encode_path_vars(integration_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/integrations/{integration_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def update_integration(
        self,
        integration_id: str,
        integration_patch: 'IntegrationPatch',
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Update an existing Integration.

        Update an existing Integration.

        :param str integration_id: integration_id.
        :param IntegrationPatch integration_patch: Integration update parameters.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `Integration` object
        """

        if not integration_id:
            raise ValueError('integration_id must be provided')
        if integration_patch is None:
            raise ValueError('integration_patch must be provided')
        if isinstance(integration_patch, IntegrationPatch):
            integration_patch = convert_model(integration_patch)
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='update_integration',
        )
        headers.update(sdk_headers)

        data = json.dumps(integration_patch)
        headers['content-type'] = 'application/merge-patch+json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['integration_id']
        path_param_values = self.encode_path_vars(integration_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/integrations/{integration_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='PATCH',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # db2_engines
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

        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `Db2EngineCollection` object
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
        *,
        description: Optional[str] = None,
        engine_details: Optional['Db2EngineDetailsBody'] = None,
        engine_display_name: Optional[str] = None,
        tags: Optional[List[str]] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Create db2 engine.

        Create a new db2 engine.

        :param str origin: Origin - created or registered.
        :param str description: (optional) Engine description.
        :param Db2EngineDetailsBody engine_details: (optional) External engine
               details.
        :param str engine_display_name: (optional) Engine display name.
        :param List[str] tags: (optional) Tags.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `Db2Engine` object
        """

        if origin is None:
            raise ValueError('origin must be provided')
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
        :param str auth_instance_id: (optional) CRN.
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
        body: 'Db2EnginePatch',
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Update db2 engine.

        Update details of db2 engine.

        :param str engine_id: engine id.
        :param Db2EnginePatch body: Update Engine Body.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `Db2Engine` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if body is None:
            raise ValueError('body must be provided')
        if isinstance(body, Db2EnginePatch):
            body = convert_model(body)
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
        headers['content-type'] = 'application/merge-patch+json'

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

    #########################
    # netezza_engines
    #########################

    def list_netezza_engines(
        self,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get list of netezza engines.

        Get list of all netezza engines.

        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `NetezzaEngineCollection` object
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
        *,
        description: Optional[str] = None,
        engine_details: Optional['NetezzaEngineDetailsBody'] = None,
        engine_display_name: Optional[str] = None,
        tags: Optional[List[str]] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Create netezza engine.

        Create a new netezza engine.

        :param str origin: Origin - created or registered.
        :param str description: (optional) Engine description.
        :param NetezzaEngineDetailsBody engine_details: (optional) External engine
               details.
        :param str engine_display_name: (optional) Engine display name.
        :param List[str] tags: (optional) Tags.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `NetezzaEngine` object
        """

        if origin is None:
            raise ValueError('origin must be provided')
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
        :param str auth_instance_id: (optional) CRN.
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
        body: 'NetezzaEnginePatch',
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Update netezza engine.

        Update details of netezza engine.

        :param str engine_id: engine id.
        :param NetezzaEnginePatch body: Update Engine Body.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `NetezzaEngine` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if body is None:
            raise ValueError('body must be provided')
        if isinstance(body, NetezzaEnginePatch):
            body = convert_model(body)
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
        headers['content-type'] = 'application/merge-patch+json'

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

    #########################
    # queries
    #########################

    def create_execute_query(
        self,
        engine_id: str,
        sql_string: str,
        *,
        catalog_name: Optional[str] = None,
        schema_name: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Execute a query.

        Execute a query.

        :param str engine_id: Engine name.
        :param str sql_string: query to be executed.
        :param str catalog_name: (optional) Name of the catalog.
        :param str schema_name: (optional) Schema name.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ExecuteQueryCreatedBody` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if sql_string is None:
            raise ValueError('sql_string must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_execute_query',
        )
        headers.update(sdk_headers)

        data = {
            'sql_string': sql_string,
            'catalog_name': catalog_name,
            'schema_name': schema_name,
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
        url = '/queries/execute/{engine_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # prestissimo_engines
    #########################

    def list_prestissimo_engines(
        self,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get list of prestissimo engines.

        Get list of all prestissimo engines.

        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `PrestissimoEngineCollection` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='list_prestissimo_engines',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/prestissimo_engines'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def create_prestissimo_engine(
        self,
        origin: str,
        *,
        associated_catalogs: Optional[List[str]] = None,
        description: Optional[str] = None,
        engine_details: Optional['PrestissimoEngineDetails'] = None,
        engine_display_name: Optional[str] = None,
        region: Optional[str] = None,
        tags: Optional[List[str]] = None,
        version: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Create prestissimo engine.

        Create a new prestissimo engine.

        :param str origin: Origin - created or registered.
        :param List[str] associated_catalogs: (optional) Associated catalogs.
        :param str description: (optional) Engine description.
        :param PrestissimoEngineDetails engine_details: (optional) External engine
               details.
        :param str engine_display_name: (optional) Engine display name.
        :param str region: (optional) Region (cloud).
        :param List[str] tags: (optional) Tags.
        :param str version: (optional) Version like 0.278 for prestissimo or else.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `PrestissimoEngine` object
        """

        if origin is None:
            raise ValueError('origin must be provided')
        if engine_details is not None:
            engine_details = convert_model(engine_details)
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_prestissimo_engine',
        )
        headers.update(sdk_headers)

        data = {
            'origin': origin,
            'associated_catalogs': associated_catalogs,
            'description': description,
            'engine_details': engine_details,
            'engine_display_name': engine_display_name,
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

        url = '/prestissimo_engines'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_prestissimo_engine(
        self,
        engine_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get prestissimo engine.

        Get details of one prestissimo engine.

        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `PrestissimoEngine` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_prestissimo_engine',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/prestissimo_engines/{engine_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_prestissimo_engine(
        self,
        engine_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Delete prestissimo engine.

        Delete a prestissimo engine.

        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) CRN.
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
            operation_id='delete_prestissimo_engine',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/prestissimo_engines/{engine_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def update_prestissimo_engine(
        self,
        engine_id: str,
        body: 'PrestissimoEnginePatch',
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Update prestissimo engine.

        Update details of prestissimo engine.

        :param str engine_id: engine id.
        :param PrestissimoEnginePatch body: Update prestissimo engine body.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `PrestissimoEngine` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if body is None:
            raise ValueError('body must be provided')
        if isinstance(body, PrestissimoEnginePatch):
            body = convert_model(body)
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='update_prestissimo_engine',
        )
        headers.update(sdk_headers)

        data = json.dumps(body)
        headers['content-type'] = 'application/merge-patch+json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/prestissimo_engines/{engine_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='PATCH',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def list_prestissimo_engine_catalogs(
        self,
        engine_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get prestissimo engine catalogs.

        Get list of all catalogs attached a prestissimo engine.

        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `CatalogCollection` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='list_prestissimo_engine_catalogs',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/prestissimo_engines/{engine_id}/catalogs'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def create_prestissimo_engine_catalogs(
        self,
        engine_id: str,
        *,
        catalog_names: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Associate catalogs to a prestissimo engine.

        Associate one or more catalogs to a prestissimo engine.

        :param str engine_id: engine id.
        :param str catalog_names: (optional) catalog names.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `Catalog` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_prestissimo_engine_catalogs',
        )
        headers.update(sdk_headers)

        data = {
            'catalog_names': catalog_names,
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
        url = '/prestissimo_engines/{engine_id}/catalogs'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_prestissimo_engine_catalogs(
        self,
        engine_id: str,
        catalog_names: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Disassociate catalogs from a prestissimo engine.

        Disassociate one or more catalogs from a prestissimo engine.

        :param str engine_id: engine id.
        :param str catalog_names: Catalog id(s) to be stopped, comma separated.
        :param str auth_instance_id: (optional) CRN.
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
            operation_id='delete_prestissimo_engine_catalogs',
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
        url = '/prestissimo_engines/{engine_id}/catalogs'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def get_prestissimo_engine_catalog(
        self,
        engine_id: str,
        catalog_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get prestissimo engine catalog.

        Get catalog attached to a prestissimo engine.

        :param str engine_id: engine id.
        :param str catalog_id: catalog id.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `Catalog` object
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
            operation_id='get_prestissimo_engine_catalog',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id', 'catalog_id']
        path_param_values = self.encode_path_vars(engine_id, catalog_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/prestissimo_engines/{engine_id}/catalogs/{catalog_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def pause_prestissimo_engine(
        self,
        engine_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Pause prestissimo engine.

        Pause a running prestissimo engine.

        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessResponse` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='pause_prestissimo_engine',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/prestissimo_engines/{engine_id}/pause'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def run_prestissimo_explain_statement(
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
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ResultPrestissimoExplainStatement` object
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
            operation_id='run_prestissimo_explain_statement',
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
        url = '/prestissimo_engines/{engine_id}/query_explain'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def run_prestissimo_explain_analyze_statement(
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
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ResultRunPrestissimoExplainAnalyzeStatement` object
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
            operation_id='run_prestissimo_explain_analyze_statement',
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
        url = '/prestissimo_engines/{engine_id}/query_explain_analyze'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def restart_prestissimo_engine(
        self,
        engine_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Restart a prestissimo engine.

        Restart an existing prestissimo engine.

        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessResponse` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='restart_prestissimo_engine',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/prestissimo_engines/{engine_id}/restart'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def resume_prestissimo_engine(
        self,
        engine_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Resume prestissimo engine.

        Resume a paused prestissimo engine.

        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessResponse` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='resume_prestissimo_engine',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/prestissimo_engines/{engine_id}/resume'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def scale_prestissimo_engine(
        self,
        engine_id: str,
        *,
        coordinator: Optional['PrestissimoNodeDescriptionBody'] = None,
        worker: Optional['PrestissimoNodeDescriptionBody'] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Scale a prestissimo engine.

        Scale an existing prestissimo engine.

        :param str engine_id: engine id.
        :param PrestissimoNodeDescriptionBody coordinator: (optional)
               coordinator/worker property settings.
        :param PrestissimoNodeDescriptionBody worker: (optional) coordinator/worker
               property settings.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessResponse` object
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
            operation_id='scale_prestissimo_engine',
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
        url = '/prestissimo_engines/{engine_id}/scale'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # presto_engines
    #########################

    def list_presto_engines(
        self,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get list of presto engines.

        Get list of all presto engines.

        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `PrestoEngineCollection` object
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

    def create_presto_engine(
        self,
        origin: str,
        *,
        associated_catalogs: Optional[List[str]] = None,
        description: Optional[str] = None,
        engine_details: Optional['EngineDetailsBody'] = None,
        engine_display_name: Optional[str] = None,
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
        :param List[str] associated_catalogs: (optional) Associated catalogs.
        :param str description: (optional) Engine description.
        :param EngineDetailsBody engine_details: (optional) Node details.
        :param str engine_display_name: (optional) Engine display name.
        :param str region: (optional) Region (cloud).
        :param List[str] tags: (optional) Tags.
        :param str version: (optional) Version like 0.278 for presto or else.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `PrestoEngine` object
        """

        if origin is None:
            raise ValueError('origin must be provided')
        if engine_details is not None:
            engine_details = convert_model(engine_details)
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_presto_engine',
        )
        headers.update(sdk_headers)

        data = {
            'origin': origin,
            'associated_catalogs': associated_catalogs,
            'description': description,
            'engine_details': engine_details,
            'engine_display_name': engine_display_name,
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
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `PrestoEngine` object
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
        :param str auth_instance_id: (optional) CRN.
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

    def update_presto_engine(
        self,
        engine_id: str,
        body: 'PrestoEnginePatch',
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Update presto engine.

        Update details of presto engine.

        :param str engine_id: engine id.
        :param PrestoEnginePatch body: Update Engine Body.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `PrestoEngine` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if body is None:
            raise ValueError('body must be provided')
        if isinstance(body, PrestoEnginePatch):
            body = convert_model(body)
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='update_presto_engine',
        )
        headers.update(sdk_headers)

        data = json.dumps(body)
        headers['content-type'] = 'application/merge-patch+json'

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
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `CatalogCollection` object
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

    def create_presto_engine_catalogs(
        self,
        engine_id: str,
        *,
        catalog_names: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Associate catalogs to presto engine.

        Associate one or more catalogs to a presto engine.

        :param str engine_id: engine id.
        :param str catalog_names: (optional) catalog names.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `Catalog` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_presto_engine_catalogs',
        )
        headers.update(sdk_headers)

        data = {
            'catalog_names': catalog_names,
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
        url = '/presto_engines/{engine_id}/catalogs'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
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
        :param str auth_instance_id: (optional) CRN.
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
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `Catalog` object
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

    def pause_presto_engine(
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
        :param str auth_instance_id: (optional) CRN.
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
            operation_id='pause_presto_engine',
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
        Explain presto query.

        Explain a query statement.

        :param str engine_id: Engine id.
        :param str statement: Presto query to determine explain plan.
        :param str format: (optional) Format.
        :param str type: (optional) Type.
        :param str auth_instance_id: (optional) CRN.
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
        Explain presto analyze.

        Return query metrics after query is complete.

        :param str engine_id: Engine id.
        :param str statement: Presto query to show explain analyze.
        :param bool verbose: (optional) Verbose.
        :param str auth_instance_id: (optional) CRN.
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

    def restart_presto_engine(
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
        :param str auth_instance_id: (optional) CRN.
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
            operation_id='restart_presto_engine',
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

    def resume_presto_engine(
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
        :param str auth_instance_id: (optional) CRN.
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
            operation_id='resume_presto_engine',
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

    def scale_presto_engine(
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
        :param str auth_instance_id: (optional) CRN.
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
            operation_id='scale_presto_engine',
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

    #########################
    # semantic_automation_layer
    #########################

    def get_sal_integration(
        self,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get SAL Integrations.

        Get SAL Integration.

        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SalIntegration` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_sal_integration',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/sal_integrations'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def create_sal_integration(
        self,
        apikey: str,
        engine_id: str,
        *,
        storage_resource_crn: Optional[str] = None,
        storage_type: Optional[str] = None,
        trial_plan: Optional[bool] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Create sal integration with wxd.

        Add or create a new sal integration.

        :param str apikey: IAM apikey.
        :param str engine_id: engine ID.
        :param str storage_resource_crn: (optional) COS storage resource crn.
        :param str storage_type: (optional) COS storage type.
        :param bool trial_plan: (optional) COS storage type.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SalIntegration` object
        """

        if apikey is None:
            raise ValueError('apikey must be provided')
        if engine_id is None:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_sal_integration',
        )
        headers.update(sdk_headers)

        data = {
            'apikey': apikey,
            'engine_id': engine_id,
            'storage_resource_crn': storage_resource_crn,
            'storage_type': storage_type,
            'trial_plan': trial_plan,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/sal_integrations'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_sal_integration(
        self,
        **kwargs,
    ) -> DetailedResponse:
        """
        Delete sal-wxd integration.

        Delete a sal-wxd integration.

        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        headers = {}
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='delete_sal_integration',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        url = '/sal_integrations'
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def update_sal_integration(
        self,
        body: 'SalIntegrationPatch',
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Update sal-wxd integration.

        Update sal-wxd integration details.

        :param SalIntegrationPatch body: Request body.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SalIntegration` object
        """

        if body is None:
            raise ValueError('body must be provided')
        if isinstance(body, SalIntegrationPatch):
            body = convert_model(body)
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='update_sal_integration',
        )
        headers.update(sdk_headers)

        data = json.dumps(body)
        headers['content-type'] = 'application/merge-patch+json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/sal_integrations'
        request = self.prepare_request(
            method='PATCH',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def create_sal_integration_enrichment(
        self,
        *,
        changes: Optional['EnrichmentObj'] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Trigger enrichment jobs on schemas and tables.

        Trigger enrichment jobs on schemas and tables.

        :param EnrichmentObj changes: (optional) Encrichment api object.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if changes is not None:
            changes = convert_model(changes)
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_sal_integration_enrichment',
        )
        headers.update(sdk_headers)

        data = {
            'changes': changes,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        url = '/sal_integrations/enrichment'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_sal_integration_enrichment_assets(
        self,
        *,
        project_id: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get semantic enrichment assets associated with the schema.

        Get semantic enrichment job runs associated with the schema.

        :param str project_id: (optional) enrichment project id.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SalIntegrationEnrichmentAssets` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_sal_integration_enrichment_assets',
        )
        headers.update(sdk_headers)

        params = {
            'project_id': project_id,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/sal_integrations/enrichment_assets'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def get_sal_integration_enrichment_data_asset(
        self,
        *,
        project_id: Optional[str] = None,
        asset_id: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get semantic enrichment data asset associated with the table.

        Get semantic enrichment data asset associated with the table.

        :param str project_id: (optional) enrichment project id.
        :param str asset_id: (optional) enrichment data asset id.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SalIntegrationEnrichmentDataAsset` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_sal_integration_enrichment_data_asset',
        )
        headers.update(sdk_headers)

        params = {
            'project_id': project_id,
            'asset_id': asset_id,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/sal_integrations/enrichment_data_asset'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def get_sal_integration_enrichment_job_run_logs(
        self,
        *,
        job_id: Optional[str] = None,
        job_run_id: Optional[str] = None,
        project_id: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get semantic enrichment job run logs associated with the job run.

        Get semantic enrichment job run logs associated with the job run.

        :param str job_id: (optional) enrichment job id.
        :param str job_run_id: (optional) enrichment job run id.
        :param str project_id: (optional) enrichment project id.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SalIntegrationEnrichmentJobRunLogs` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_sal_integration_enrichment_job_run_logs',
        )
        headers.update(sdk_headers)

        params = {
            'job_id': job_id,
            'job_run_id': job_run_id,
            'project_id': project_id,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/sal_integrations/enrichment_job_run_logs'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def get_sal_integration_enrichment_job_runs(
        self,
        *,
        job_id: Optional[str] = None,
        project_id: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get semantic enrichment job runs associated with the schema.

        Get semantic enrichment job runs associated with the schema.

        :param str job_id: (optional) enrichment job id.
        :param str project_id: (optional) enrichment project id.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SalIntegrationEnrichmentJobRun` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_sal_integration_enrichment_job_runs',
        )
        headers.update(sdk_headers)

        params = {
            'job_id': job_id,
            'project_id': project_id,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/sal_integrations/enrichment_job_runs'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def get_sal_integration_enrichment_jobs(
        self,
        *,
        wkc_project_id: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get semantic enrichment jobs associated with the schema.

        Get semantic enrichment jobs associated with the schema.

        :param str wkc_project_id: (optional) ikc project id.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SalIntegrationEnrichmentJobs` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_sal_integration_enrichment_jobs',
        )
        headers.update(sdk_headers)

        params = {
            'wkc_project_id': wkc_project_id,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/sal_integrations/enrichment_jobs'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def get_sal_integration_glossary_terms(
        self,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get list of uploaded glossary terms.

        Get list of uploaded glossary terms.

        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SalIntegrationGlossaryTerms` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_sal_integration_glossary_terms',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/sal_integrations/glossary_terms'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def get_sal_integration_mappings(
        self,
        catalog_name: str,
        schema_name: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get wkc catalog and project mapped to the schema.

        Get wkc catalog and project mapped to the schema.

        :param str catalog_name: catalog name.
        :param str schema_name: schema name.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SalIntegrationMappings` object
        """

        if not catalog_name:
            raise ValueError('catalog_name must be provided')
        if not schema_name:
            raise ValueError('schema_name must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_sal_integration_mappings',
        )
        headers.update(sdk_headers)

        params = {
            'catalog_name': catalog_name,
            'schema_name': schema_name,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/sal_integrations/mappings'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def get_sal_integration_enrichment_global_settings(
        self,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get metadata enrichment global settings.

        Get metadata enrichment global settings.

        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SalIntegrationEnrichmentSettings` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_sal_integration_enrichment_global_settings',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/sal_integrations/metadata_enrichment_global_settings'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def create_sal_integration_enrichment_global_settings(
        self,
        *,
        semantic_expansion: Optional['SalIntegrationEnrichmentSettingsSemanticExpansion'] = None,
        term_assignment: Optional['SalIntegrationEnrichmentSettingsTermAssignment'] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Add metadata enrichment global settings.

        Add metadata enrichment global settings.

        :param SalIntegrationEnrichmentSettingsSemanticExpansion
               semantic_expansion: (optional) semantic expansion.
        :param SalIntegrationEnrichmentSettingsTermAssignment term_assignment:
               (optional) semantic expansion.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SalIntegrationEnrichmentSettings` object
        """

        if semantic_expansion is not None:
            semantic_expansion = convert_model(semantic_expansion)
        if term_assignment is not None:
            term_assignment = convert_model(term_assignment)
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_sal_integration_enrichment_global_settings',
        )
        headers.update(sdk_headers)

        data = {
            'semantic_expansion': semantic_expansion,
            'term_assignment': term_assignment,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/sal_integrations/metadata_enrichment_global_settings'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_sal_integration_enrichment_settings(
        self,
        *,
        project_id: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        get metadata enrichment settings for a project.

        get metadata enrichment settings for a project.

        :param str project_id: (optional) wkc project id.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SalIntegrationEnrichmentSettings` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_sal_integration_enrichment_settings',
        )
        headers.update(sdk_headers)

        params = {
            'project_id': project_id,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/sal_integrations/metadata_enrichment_settings'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def create_sal_integration_enrichment_settings(
        self,
        *,
        semantic_expansion: Optional['SalIntegrationEnrichmentSettingsSemanticExpansion'] = None,
        term_assignment: Optional['SalIntegrationEnrichmentSettingsTermAssignment'] = None,
        project_id: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Add metadata enrichment settings for a project.

        Add metadata enrichment settings for a project.

        :param SalIntegrationEnrichmentSettingsSemanticExpansion
               semantic_expansion: (optional) semantic expansion.
        :param SalIntegrationEnrichmentSettingsTermAssignment term_assignment:
               (optional) semantic expansion.
        :param str project_id: (optional) wkc project id.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if semantic_expansion is not None:
            semantic_expansion = convert_model(semantic_expansion)
        if term_assignment is not None:
            term_assignment = convert_model(term_assignment)
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_sal_integration_enrichment_settings',
        )
        headers.update(sdk_headers)

        params = {
            'project_id': project_id,
        }

        data = {
            'semantic_expansion': semantic_expansion,
            'term_assignment': term_assignment,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        url = '/sal_integrations/metadata_enrichment_settings'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            params=params,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def create_sal_integration_upload_glossary(
        self,
        replace_option: str,
        *,
        glossary_csv: Optional[BinaryIO] = None,
        glossary_csv_content_type: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Upload semantic enrichment business terms glossary.

        Upload semantic enrichment business terms glossary.

        :param str replace_option: glossary upload replace option.
        :param BinaryIO glossary_csv: (optional) Glossary CSV file.
        :param str glossary_csv_content_type: (optional) The content type of
               glossary_csv.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SalIntegrationUploadGlossary` object
        """

        if not replace_option:
            raise ValueError('replace_option must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_sal_integration_upload_glossary',
        )
        headers.update(sdk_headers)

        form_data = []
        form_data.append(('replace_option', (None, replace_option, 'text/plain')))
        if glossary_csv:
            form_data.append(('glossary_csv', (None, glossary_csv, glossary_csv_content_type or 'application/octet-stream')))

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/sal_integrations/upload_glossary'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            files=form_data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_sal_integration_upload_glossary_status(
        self,
        *,
        process_id: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get status of upload glossary job.

        Get status of upload glossary job.

        :param str process_id: (optional) upload process id.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SalIntegrationUploadGlossaryStatus` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_sal_integration_upload_glossary_status',
        )
        headers.update(sdk_headers)

        params = {
            'process_id': process_id,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/sal_integrations/upload_glossary_status'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # spark_engines
    #########################

    def list_spark_engines(
        self,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        List all spark engines.

        List all spark engines.

        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SparkEngineCollection` object
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
        *,
        associated_catalogs: Optional[List[str]] = None,
        description: Optional[str] = None,
        engine_details: Optional['SparkEngineDetailsPrototype'] = None,
        engine_display_name: Optional[str] = None,
        status: Optional[str] = None,
        tags: Optional[List[str]] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Create spark engine.

        Create a new spark  engine.

        :param str origin: Origin - created or registered.
        :param List[str] associated_catalogs: (optional) Associated catalogs.
        :param str description: (optional) Engine description.
        :param SparkEngineDetailsPrototype engine_details: (optional) Node details.
        :param str engine_display_name: (optional) Engine display name.
        :param str status: (optional) Engine status.
        :param List[str] tags: (optional) Tags.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SparkEngine` object
        """

        if origin is None:
            raise ValueError('origin must be provided')
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
            'associated_catalogs': associated_catalogs,
            'description': description,
            'engine_details': engine_details,
            'engine_display_name': engine_display_name,
            'status': status,
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

    def get_spark_engine(
        self,
        engine_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get spark engine.

        Get spark engine by ID.

        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SparkEngine` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_spark_engine',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/spark_engines/{engine_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
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
        :param str auth_instance_id: (optional) CRN.
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
        body: 'UpdateSparkEngineBody',
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Update spark engine.

        Update details of spark engine.

        :param str engine_id: engine id.
        :param UpdateSparkEngineBody body: Update Engine Body.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SparkEngine` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if body is None:
            raise ValueError('body must be provided')
        if isinstance(body, UpdateSparkEngineBody):
            body = convert_model(body)
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
        headers['content-type'] = 'application/merge-patch+json'

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
        state: Optional[List[str]] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        List all applications in a spark engine.

        List all applications in a spark engine.

        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) CRN.
        :param List[str] state: (optional) state.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SparkEngineApplicationStatusCollection` object
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

        params = {
            'state': convert_list(state),
        }

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
            params=params,
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
        volumes: Optional[List['SparkVolumeDetails']] = None,
        auth_instance_id: Optional[str] = None,
        state: Optional[List[str]] = None,
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
        :param List[SparkVolumeDetails] volumes: (optional) Spark application
               volumes to mount.
        :param str auth_instance_id: (optional) CRN.
        :param List[str] state: (optional) state.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SparkEngineApplicationStatus` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if application_details is None:
            raise ValueError('application_details must be provided')
        application_details = convert_model(application_details)
        if volumes is not None:
            volumes = [convert_model(x) for x in volumes]
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_spark_engine_application',
        )
        headers.update(sdk_headers)

        params = {
            'state': convert_list(state),
        }

        data = {
            'application_details': application_details,
            'job_endpoint': job_endpoint,
            'service_instance_id': service_instance_id,
            'type': type,
            'volumes': volumes,
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
            params=params,
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
        state: Optional[List[str]] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Stop Spark Applications.

        Stop a running spark application.

        :param str engine_id: engine id.
        :param str application_id: Application id(s) to be stopped, comma
               separated.
        :param str auth_instance_id: (optional) CRN.
        :param List[str] state: (optional) state.
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
            'state': convert_list(state),
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
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SparkEngineApplicationStatus` object
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

    def list_spark_engine_catalogs(
        self,
        engine_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get spark engine catalogs.

        Get list of all catalogs attached to a spark engine.

        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `CatalogCollection` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='list_spark_engine_catalogs',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/spark_engines/{engine_id}/catalogs'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def create_spark_engine_catalogs(
        self,
        engine_id: str,
        *,
        catalog_names: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Associate catalogs to spark engine.

        Associate one or more catalogs to a spark engine.

        :param str engine_id: engine id.
        :param str catalog_names: (optional) catalog names.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `Catalog` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_spark_engine_catalogs',
        )
        headers.update(sdk_headers)

        data = {
            'catalog_names': catalog_names,
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
        url = '/spark_engines/{engine_id}/catalogs'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_spark_engine_catalogs(
        self,
        engine_id: str,
        catalog_names: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Disassociate catalogs from a spark engine.

        Disassociate one or more catalogs from a spark engine.

        :param str engine_id: engine id.
        :param str catalog_names: Catalog id(s) to be stopped, comma separated.
        :param str auth_instance_id: (optional) CRN.
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
            operation_id='delete_spark_engine_catalogs',
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
        url = '/spark_engines/{engine_id}/catalogs'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def get_spark_engine_catalog(
        self,
        engine_id: str,
        catalog_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get spark engine catalog.

        Get catalog attached to spark engine.

        :param str engine_id: engine id.
        :param str catalog_id: catalog id.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `Catalog` object
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
            operation_id='get_spark_engine_catalog',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id', 'catalog_id']
        path_param_values = self.encode_path_vars(engine_id, catalog_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/spark_engines/{engine_id}/catalogs/{catalog_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def get_spark_engine_history_server(
        self,
        engine_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get spark history server.

        Get spark history server.

        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SparkHistoryServer` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_spark_engine_history_server',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/spark_engines/{engine_id}/history_server'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def start_spark_engine_history_server(
        self,
        engine_id: str,
        *,
        cores: Optional[str] = None,
        memory: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Start spark history server.

        Start spark history server.

        :param str engine_id: engine id.
        :param str cores: (optional) CPU count.
        :param str memory: (optional) Memory in GiB.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SparkHistoryServer` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='start_spark_engine_history_server',
        )
        headers.update(sdk_headers)

        data = {
            'cores': cores,
            'memory': memory,
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
        url = '/spark_engines/{engine_id}/history_server'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_spark_engine_history_server(
        self,
        engine_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Stop spark history server.

        Stop spark history server.

        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) CRN.
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
            operation_id='delete_spark_engine_history_server',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/spark_engines/{engine_id}/history_server'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def pause_spark_engine(
        self,
        engine_id: str,
        *,
        force: Optional[bool] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Pause engine.

        Pause engine.

        :param str engine_id: engine id.
        :param bool force: (optional) force spark engine pause.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessResponse` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='pause_spark_engine',
        )
        headers.update(sdk_headers)

        data = {
            'force': force,
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
        url = '/spark_engines/{engine_id}/pause'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def resume_spark_engine(
        self,
        engine_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Resume engine.

        Resume engine.

        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessResponse` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='resume_spark_engine',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['engine_id']
        path_param_values = self.encode_path_vars(engine_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/spark_engines/{engine_id}/resume'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def scale_spark_engine(
        self,
        engine_id: str,
        *,
        number_of_nodes: Optional[int] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Scale Spark engine.

        Scale Saprk engine.

        :param str engine_id: engine id.
        :param int number_of_nodes: (optional) Node count.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessResponse` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='scale_spark_engine',
        )
        headers.update(sdk_headers)

        data = {
            'number_of_nodes': number_of_nodes,
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
        url = '/spark_engines/{engine_id}/scale'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def list_spark_versions(
        self,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        List spark version.

        List spark version.

        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListSparkVersionsOKBody` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='list_spark_versions',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/spark_versions'
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

        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `CatalogCollection` object
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
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `Catalog` object
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
        :param str auth_instance_id: (optional) CRN.
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
        hostname: Optional[str] = None,
        port: Optional[int] = None,
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
        :param str hostname: (optional) Host name.
        :param int port: (optional) Port.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
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
            'hostname': hostname,
            'port': port,
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
        :param str auth_instance_id: (optional) CRN.
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
        List all tables.

        List all tables in a schema in a catalog for a given engine.

        :param str catalog_id: catalog id.
        :param str schema_id: URL encoded schema name.
        :param str engine_id: engine id.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `TableCollection` object
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
        type: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get table details.

        Get details of a given table in a catalog and schema.

        :param str catalog_id: catalog id.
        :param str schema_id: URL encoded schema name.
        :param str table_id: URL encoded table name.
        :param str engine_id: engine id.
        :param str type: (optional) URL encoded table type.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `Table` object
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
            'type': type,
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
        type: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Delete table.

        Delete table for a given schema and catalog.

        :param str catalog_id: catalog id.
        :param str schema_id: URL encoded schema name.
        :param str table_id: URL encoded table name.
        :param str engine_id: engine id.
        :param str type: (optional) URL encoded table type.
        :param str auth_instance_id: (optional) CRN.
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
            'type': type,
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
        body: 'TablePatch',
        *,
        type: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Rename table.

        Rename table.

        :param str catalog_id: catalog id.
        :param str schema_id: URL encoded schema name.
        :param str table_id: URL encoded table name.
        :param str engine_id: engine id.
        :param TablePatch body: Request body.
        :param str type: (optional) URL encoded table type.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `Table` object
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
        if isinstance(body, TablePatch):
            body = convert_model(body)
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
            'type': type,
        }

        data = json.dumps(body)
        headers['content-type'] = 'application/merge-patch+json'

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

    def list_columns(
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
        List all columns of a table.

        List all columns of a table in a given a schema for a given catalog.

        :param str engine_id: engine id.
        :param str catalog_id: catalog id.
        :param str schema_id: URL encoded schema name.
        :param str table_id: URL encoded schema name.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ColumnCollection` object
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
            operation_id='list_columns',
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
        url = '/catalogs/{catalog_id}/schemas/{schema_id}/tables/{table_id}/columns'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def create_columns(
        self,
        engine_id: str,
        catalog_id: str,
        schema_id: str,
        table_id: str,
        *,
        columns: Optional[List['Column']] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Add column(s).

        Add one or multiple columns to a table in a schema for a given catalog.

        :param str engine_id: engine id.
        :param str catalog_id: catalog id.
        :param str schema_id: URL encoded schema name.
        :param str table_id: URL encoded schema name.
        :param List[Column] columns: (optional) List of the tables present in the
               schema.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ColumnCollection` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if not catalog_id:
            raise ValueError('catalog_id must be provided')
        if not schema_id:
            raise ValueError('schema_id must be provided')
        if not table_id:
            raise ValueError('table_id must be provided')
        if columns is not None:
            columns = [convert_model(x) for x in columns]
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_columns',
        )
        headers.update(sdk_headers)

        params = {
            'engine_id': engine_id,
        }

        data = {
            'columns': columns,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['catalog_id', 'schema_id', 'table_id']
        path_param_values = self.encode_path_vars(catalog_id, schema_id, table_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/catalogs/{catalog_id}/schemas/{schema_id}/tables/{table_id}/columns'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            params=params,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_column(
        self,
        engine_id: str,
        catalog_id: str,
        schema_id: str,
        table_id: str,
        column_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Delete column.

        Delete column in a table for a given schema and catalog.

        :param str engine_id: engine id.
        :param str catalog_id: catalog id.
        :param str schema_id: URL encoded schema name.
        :param str table_id: URL encoded schema name.
        :param str column_id: URL encoded schema name.
        :param str auth_instance_id: (optional) CRN.
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
        if not table_id:
            raise ValueError('table_id must be provided')
        if not column_id:
            raise ValueError('column_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='delete_column',
        )
        headers.update(sdk_headers)

        params = {
            'engine_id': engine_id,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['catalog_id', 'schema_id', 'table_id', 'column_id']
        path_param_values = self.encode_path_vars(catalog_id, schema_id, table_id, column_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/catalogs/{catalog_id}/schemas/{schema_id}/tables/{table_id}/columns/{column_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def update_column(
        self,
        engine_id: str,
        catalog_id: str,
        schema_id: str,
        table_id: str,
        column_id: str,
        body: 'ColumnPatch',
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Alter column.

        Update the given column - rename column.

        :param str engine_id: engine id.
        :param str catalog_id: catalog id.
        :param str schema_id: URL encoded schema name.
        :param str table_id: URL encoded schema name.
        :param str column_id: URL encoded schema name.
        :param ColumnPatch body: Request body.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `Column` object
        """

        if not engine_id:
            raise ValueError('engine_id must be provided')
        if not catalog_id:
            raise ValueError('catalog_id must be provided')
        if not schema_id:
            raise ValueError('schema_id must be provided')
        if not table_id:
            raise ValueError('table_id must be provided')
        if not column_id:
            raise ValueError('column_id must be provided')
        if body is None:
            raise ValueError('body must be provided')
        if isinstance(body, ColumnPatch):
            body = convert_model(body)
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='update_column',
        )
        headers.update(sdk_headers)

        params = {
            'engine_id': engine_id,
        }

        data = json.dumps(body)
        headers['content-type'] = 'application/merge-patch+json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['catalog_id', 'schema_id', 'table_id', 'column_id']
        path_param_values = self.encode_path_vars(catalog_id, schema_id, table_id, column_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/catalogs/{catalog_id}/schemas/{schema_id}/tables/{table_id}/columns/{column_id}'.format(**path_param_dict)
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
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `TableSnapshotCollection` object
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

    def rollback_table(
        self,
        engine_id: str,
        catalog_id: str,
        schema_id: str,
        table_id: str,
        *,
        snapshot_id: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Rollback table to snapshot.

        Rollback table to a snapshot.

        :param str engine_id: Engine name.
        :param str catalog_id: Catalog ID.
        :param str schema_id: Schema ID.
        :param str table_id: Table ID.
        :param str snapshot_id: (optional) Snapshot Id.
        :param str auth_instance_id: (optional) CRN.
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
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='rollback_table',
        )
        headers.update(sdk_headers)

        params = {
            'engine_id': engine_id,
        }

        data = {
            'snapshot_id': snapshot_id,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['catalog_id', 'schema_id', 'table_id']
        path_param_values = self.encode_path_vars(catalog_id, schema_id, table_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/catalogs/{catalog_id}/schemas/{schema_id}/tables/{table_id}/rollback'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            params=params,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def update_sync_catalog(
        self,
        catalog_id: str,
        body: 'SyncCatalogs',
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        External Iceberg table registration.

        Synchronize the external Iceberg table registration for a catalog identified by
        catalog_id.

        :param str catalog_id: catalog ID.
        :param SyncCatalogs body: Request body.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `UpdateSyncCatalogOKBody` object
        """

        if not catalog_id:
            raise ValueError('catalog_id must be provided')
        if body is None:
            raise ValueError('body must be provided')
        if isinstance(body, SyncCatalogs):
            body = convert_model(body)
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
        headers['content-type'] = 'application/merge-patch+json'

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

    #########################
    # services
    #########################

    def list_milvus_services(
        self,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get list of milvus services.

        Get list milvus services.

        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `MilvusServiceCollection` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='list_milvus_services',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/milvus_services'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def create_milvus_service(
        self,
        bucket_name: str,
        origin: str,
        root_path: str,
        service_display_name: str,
        *,
        bucket_type: Optional[str] = None,
        description: Optional[str] = None,
        tags: Optional[List[str]] = None,
        tshirt_size: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Create milvus service.

        Create milvus service.

        :param str bucket_name: bucket name.
        :param str origin: Origin - place holder.
        :param str root_path: root path.
        :param str service_display_name: Service display name.
        :param str bucket_type: (optional) bucket type.
        :param str description: (optional) Service description.
        :param List[str] tags: (optional) Tags.
        :param str tshirt_size: (optional) tshirt size.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `MilvusService` object
        """

        if bucket_name is None:
            raise ValueError('bucket_name must be provided')
        if origin is None:
            raise ValueError('origin must be provided')
        if root_path is None:
            raise ValueError('root_path must be provided')
        if service_display_name is None:
            raise ValueError('service_display_name must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_milvus_service',
        )
        headers.update(sdk_headers)

        data = {
            'bucket_name': bucket_name,
            'origin': origin,
            'root_path': root_path,
            'service_display_name': service_display_name,
            'bucket_type': bucket_type,
            'description': description,
            'tags': tags,
            'tshirt_size': tshirt_size,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/milvus_services'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_milvus_service(
        self,
        service_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get milvus service.

        Get milvus service.

        :param str service_id: service id.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `MilvusService` object
        """

        if not service_id:
            raise ValueError('service_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_milvus_service',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['service_id']
        path_param_values = self.encode_path_vars(service_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/milvus_services/{service_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_milvus_service(
        self,
        service_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Delete milvus service.

        Delete milvus service.

        :param str service_id: service id.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not service_id:
            raise ValueError('service_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='delete_milvus_service',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['service_id']
        path_param_values = self.encode_path_vars(service_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/milvus_services/{service_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def update_milvus_service(
        self,
        service_id: str,
        body: 'MilvusServicePatch',
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Update milvus service.

        Update details of milvus service.

        :param str service_id: service id.
        :param MilvusServicePatch body: Update milvus service.
        :param str auth_instance_id: (optional) CRN.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `MilvusService` object
        """

        if not service_id:
            raise ValueError('service_id must be provided')
        if body is None:
            raise ValueError('body must be provided')
        if isinstance(body, MilvusServicePatch):
            body = convert_model(body)
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='update_milvus_service',
        )
        headers.update(sdk_headers)

        data = json.dumps(body)
        headers['content-type'] = 'application/merge-patch+json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['service_id']
        path_param_values = self.encode_path_vars(service_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/milvus_services/{service_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='PATCH',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def list_milvus_service_databases(
        self,
        service_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get milvus service databases.

        Get milvus service databases.

        :param str service_id: service id.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `MilvusServiceDatabases` object
        """

        if not service_id:
            raise ValueError('service_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='list_milvus_service_databases',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['service_id']
        path_param_values = self.encode_path_vars(service_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/milvus_services/{service_id}/databases'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def list_milvus_database_collections(
        self,
        service_id: str,
        database_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get milvus database collections.

        Get milvus database collections.

        :param str service_id: service id.
        :param str database_id: database id.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `MilvusDatabaseCollections` object
        """

        if not service_id:
            raise ValueError('service_id must be provided')
        if not database_id:
            raise ValueError('database_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='list_milvus_database_collections',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['service_id', 'database_id']
        path_param_values = self.encode_path_vars(service_id, database_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/milvus_services/{service_id}/databases/{database_id}/collections'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def create_milvus_service_pause(
        self,
        service_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Pause milvus service.

        Pause a running milvus service.

        :param str service_id: service id.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessResponse` object
        """

        if not service_id:
            raise ValueError('service_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_milvus_service_pause',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['service_id']
        path_param_values = self.encode_path_vars(service_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/milvus_services/{service_id}/pause'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def create_milvus_service_resume(
        self,
        service_id: str,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Resume milvus service.

        Resume a paused milvus service.

        :param str service_id: service id.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessResponse` object
        """

        if not service_id:
            raise ValueError('service_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_milvus_service_resume',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['service_id']
        path_param_values = self.encode_path_vars(service_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/milvus_services/{service_id}/resume'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def create_milvus_service_scale(
        self,
        service_id: str,
        *,
        tshirt_size: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Scale a milvus service.

        Scale an existing milvus service.

        :param str service_id: service id.
        :param str tshirt_size: (optional) tshirt size.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SuccessResponse` object
        """

        if not service_id:
            raise ValueError('service_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_milvus_service_scale',
        )
        headers.update(sdk_headers)

        data = {
            'tshirt_size': tshirt_size,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['service_id']
        path_param_values = self.encode_path_vars(service_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/milvus_services/{service_id}/scale'.format(**path_param_dict)
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # ingestion
    #########################

    def list_ingestion_jobs(
        self,
        auth_instance_id: str,
        *,
        start: Optional[str] = None,
        jobs_per_page: Optional[int] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get ingestion jobs.

        Get list of ingestion jobs.

        :param str auth_instance_id: watsonx.data instance ID.
        :param str start: (optional) Page number of requested ingestion jobs.
        :param int jobs_per_page: (optional) Number of requested ingestion jobs.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `IngestionJobCollection` object
        """

        if not auth_instance_id:
            raise ValueError('auth_instance_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='list_ingestion_jobs',
        )
        headers.update(sdk_headers)

        params = {
            'start': start,
            'jobs_per_page': jobs_per_page,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/ingestion_jobs'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def create_ingestion_jobs(
        self,
        auth_instance_id: str,
        job_id: str,
        source_data_files: str,
        target_table: str,
        username: str,
        *,
        create_if_not_exist: Optional[bool] = None,
        csv_property: Optional['IngestionJobPrototypeCsvProperty'] = None,
        engine_id: Optional[str] = None,
        execute_config: Optional['IngestionJobPrototypeExecuteConfig'] = None,
        partition_by: Optional[str] = None,
        schema: Optional[str] = None,
        source_file_type: Optional[str] = None,
        validate_csv_header: Optional[bool] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Create an ingestion job.

        Create an ingestion job.

        :param str auth_instance_id: watsonx.data instance ID.
        :param str job_id: Job ID of the job.
        :param str source_data_files: Comma separated source file or directory
               path.
        :param str target_table: Target table name in format catalog.schema.table.
        :param str username: User submitting ingestion job.
        :param bool create_if_not_exist: (optional) Create new target table (if
               True); Insert into pre-existing target table (if False).
        :param IngestionJobPrototypeCsvProperty csv_property: (optional) Ingestion
               CSV properties.
        :param str engine_id: (optional) ID of the spark engine to be used for
               ingestion.
        :param IngestionJobPrototypeExecuteConfig execute_config: (optional)
               Ingestion engine configuration.
        :param str partition_by: (optional) Partition by expression of the target
               table.
        :param str schema: (optional) Schema definition of the source table.
        :param str source_file_type: (optional) Source file types (parquet or csv
               or json).
        :param bool validate_csv_header: (optional) Validate CSV header if the
               target table exist.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `IngestionJob` object
        """

        if not auth_instance_id:
            raise ValueError('auth_instance_id must be provided')
        if job_id is None:
            raise ValueError('job_id must be provided')
        if source_data_files is None:
            raise ValueError('source_data_files must be provided')
        if target_table is None:
            raise ValueError('target_table must be provided')
        if username is None:
            raise ValueError('username must be provided')
        if csv_property is not None:
            csv_property = convert_model(csv_property)
        if execute_config is not None:
            execute_config = convert_model(execute_config)
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_ingestion_jobs',
        )
        headers.update(sdk_headers)

        data = {
            'job_id': job_id,
            'source_data_files': source_data_files,
            'target_table': target_table,
            'username': username,
            'create_if_not_exist': create_if_not_exist,
            'csv_property': csv_property,
            'engine_id': engine_id,
            'execute_config': execute_config,
            'partition_by': partition_by,
            'schema': schema,
            'source_file_type': source_file_type,
            'validate_csv_header': validate_csv_header,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/ingestion_jobs'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    def create_ingestion_jobs_local_files(
        self,
        auth_instance_id: str,
        source_data_file: BinaryIO,
        target_table: str,
        job_id: str,
        username: str,
        *,
        source_data_file_content_type: Optional[str] = None,
        source_file_type: Optional[str] = None,
        csv_property: Optional[str] = None,
        create_if_not_exist: Optional[bool] = None,
        validate_csv_header: Optional[bool] = None,
        execute_config: Optional[str] = None,
        engine_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Create an ingestion job for user local files.

        Create an ingestion job for user local files.

        :param str auth_instance_id: watsonx.data instance ID.
        :param BinaryIO source_data_file: The user local file submitted for
               ingestion.
        :param str target_table: Target table name in format catalog.schema.table.
        :param str job_id: Job ID of the job.
        :param str username: User submitting ingestion job.
        :param str source_data_file_content_type: (optional) The content type of
               source_data_file.
        :param str source_file_type: (optional) File format of source file.
        :param str csv_property: (optional) Ingestion CSV properties (base64
               encoding of a stringifed json).
        :param bool create_if_not_exist: (optional) Create new target table (if
               true); Insert into pre-existing target table (if false).
        :param bool validate_csv_header: (optional) Validate CSV header if the
               target table exist.
        :param str execute_config: (optional) Ingestion engine configuration
               (base64 encoding of a stringifed json).
        :param str engine_id: (optional) ID of the spark engine to be used for
               ingestion.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `IngestionJob` object
        """

        if not auth_instance_id:
            raise ValueError('auth_instance_id must be provided')
        if source_data_file is None:
            raise ValueError('source_data_file must be provided')
        if not target_table:
            raise ValueError('target_table must be provided')
        if not job_id:
            raise ValueError('job_id must be provided')
        if not username:
            raise ValueError('username must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_ingestion_jobs_local_files',
        )
        headers.update(sdk_headers)

        form_data = []
        form_data.append(('source_data_file', (None, source_data_file, source_data_file_content_type or 'application/octet-stream')))
        form_data.append(('target_table', (None, target_table, 'text/plain')))
        form_data.append(('job_id', (None, job_id, 'text/plain')))
        form_data.append(('username', (None, username, 'text/plain')))
        if source_file_type:
            form_data.append(('source_file_type', (None, source_file_type, 'text/plain')))
        if csv_property:
            form_data.append(('csv_property', (None, csv_property, 'text/plain')))
        if create_if_not_exist:
            form_data.append(('create_if_not_exist', (None, str(create_if_not_exist), 'text/plain')))
        if validate_csv_header:
            form_data.append(('validate_csv_header', (None, str(validate_csv_header), 'text/plain')))
        if execute_config:
            form_data.append(('execute_config', (None, execute_config, 'text/plain')))
        if engine_id:
            form_data.append(('engine_id', (None, engine_id, 'text/plain')))

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/ingestion_jobs_local_files'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            files=form_data,
        )

        response = self.send(request, **kwargs)
        return response

    def get_ingestion_job(
        self,
        job_id: str,
        auth_instance_id: str,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get ingestion job.

        Get a submitted ingestion job.

        :param str job_id: ingestion job id.
        :param str auth_instance_id: watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `IngestionJob` object
        """

        if not job_id:
            raise ValueError('job_id must be provided')
        if not auth_instance_id:
            raise ValueError('auth_instance_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_ingestion_job',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['job_id']
        path_param_values = self.encode_path_vars(job_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/ingestion_jobs/{job_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def delete_ingestion_jobs(
        self,
        job_id: str,
        auth_instance_id: str,
        **kwargs,
    ) -> DetailedResponse:
        """
        Delete an ingestion job.

        Delete an ingestion job.

        :param str job_id: ingestion job id.
        :param str auth_instance_id: watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not job_id:
            raise ValueError('job_id must be provided')
        if not auth_instance_id:
            raise ValueError('auth_instance_id must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='delete_ingestion_jobs',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['job_id']
        path_param_values = self.encode_path_vars(job_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/ingestion_jobs/{job_id}'.format(**path_param_dict)
        request = self.prepare_request(
            method='DELETE',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    def create_preview_ingestion_file(
        self,
        auth_instance_id: str,
        source_data_files: str,
        *,
        csv_property: Optional['PreviewIngestionFilePrototypeCsvProperty'] = None,
        source_file_type: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Generate a preview of source file(s).

        Generate a preview of source file(s).

        :param str auth_instance_id: watsonx.data instance ID.
        :param str source_data_files: Comma separated source file or directory
               path.
        :param PreviewIngestionFilePrototypeCsvProperty csv_property: (optional)
               CSV properties of source file(s).
        :param str source_file_type: (optional) File format of source file(s).
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `PreviewIngestionFile` object
        """

        if not auth_instance_id:
            raise ValueError('auth_instance_id must be provided')
        if source_data_files is None:
            raise ValueError('source_data_files must be provided')
        if csv_property is not None:
            csv_property = convert_model(csv_property)
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='create_preview_ingestion_file',
        )
        headers.update(sdk_headers)

        data = {
            'source_data_files': source_data_files,
            'csv_property': csv_property,
            'source_file_type': source_file_type,
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/preview_ingestion_file'
        request = self.prepare_request(
            method='POST',
            url=url,
            headers=headers,
            data=data,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # endpoints
    #########################

    def get_endpoints(
        self,
        *,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get CPG and CAS endpoints.

        Get Common policy gateway (CPG) and  Data Access Service(CAS) endpoints.

        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `EndpointCollection` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_endpoints',
        )
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/endpoints'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
        )

        response = self.send(request, **kwargs)
        return response

    #########################
    # metadata
    #########################

    def get_all_columns(
        self,
        *,
        table_name: Optional[str] = None,
        catalog_name: Optional[str] = None,
        schema_name: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get all columns.

        Get all columns.

        :param str table_name: (optional) Table name.
        :param str catalog_name: (optional) Catalog name.
        :param str schema_name: (optional) Schema name.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ColumnsResponse` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_all_columns',
        )
        headers.update(sdk_headers)

        params = {
            'table_name': table_name,
            'catalog_name': catalog_name,
            'schema_name': schema_name,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/columns'
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def list_all_schemas(
        self,
        *,
        catalog_name: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get all schemas for a given catalog.

        List Schemas for a catalog with the given catalog_name.

        :param str catalog_name: (optional) Catalog name.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SchemaResponseCollection` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='list_all_schemas',
        )
        headers.update(sdk_headers)

        params = {
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

    def get_schema_details(
        self,
        schema_name: str,
        *,
        catalog_name: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get schema details.

        Get schema details.

        :param str schema_name: Schema name.
        :param str catalog_name: (optional) Catalog name.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SchemaResponse` object
        """

        if not schema_name:
            raise ValueError('schema_name must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_schema_details',
        )
        headers.update(sdk_headers)

        params = {
            'catalog_name': catalog_name,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['schema_name']
        path_param_values = self.encode_path_vars(schema_name)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/schemas/{schema_name}'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response

    def list_all_tables(
        self,
        *,
        catalog_name: Optional[str] = None,
        schema_name: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get all tables.

        Get all tables.

        :param str catalog_name: (optional) Catalog name.
        :param str schema_name: (optional) Schema name.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `TableResponseCollection` object
        """

        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='list_all_tables',
        )
        headers.update(sdk_headers)

        params = {
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

    def get_table_details(
        self,
        table_name: str,
        *,
        catalog_name: Optional[str] = None,
        schema_name: Optional[str] = None,
        auth_instance_id: Optional[str] = None,
        **kwargs,
    ) -> DetailedResponse:
        """
        Get table details.

        Get table details.

        :param str table_name: Table name.
        :param str catalog_name: (optional) Catalog name.
        :param str schema_name: (optional) Schema name.
        :param str auth_instance_id: (optional) watsonx.data instance ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `TableResponse` object
        """

        if not table_name:
            raise ValueError('table_name must be provided')
        headers = {
            'AuthInstanceId': auth_instance_id,
        }
        sdk_headers = get_sdk_headers(
            service_name=self.DEFAULT_SERVICE_NAME,
            service_version='V2',
            operation_id='get_table_details',
        )
        headers.update(sdk_headers)

        params = {
            'catalog_name': catalog_name,
            'schema_name': schema_name,
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['table_name']
        path_param_values = self.encode_path_vars(table_name)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/tables/{table_name}'.format(**path_param_dict)
        request = self.prepare_request(
            method='GET',
            url=url,
            headers=headers,
            params=params,
        )

        response = self.send(request, **kwargs)
        return response


class CreateSalIntegrationUploadGlossaryEnums:
    """
    Enums for create_sal_integration_upload_glossary parameters.
    """

    class ReplaceOption(str, Enum):
        """
        glossary upload replace option.
        """

        ALL = 'all'
        SPECIFIED = 'specified'
        EMPTY = 'empty'


class CreateIngestionJobsLocalFilesEnums:
    """
    Enums for create_ingestion_jobs_local_files parameters.
    """

    class SourceFileType(str, Enum):
        """
        File format of source file.
        """

        CSV = 'csv'
        PARQUET = 'parquet'
        JSON = 'json'


##############################################################################
# Models
##############################################################################


class BucketCatalog:
    """
    bucket catalog.

    :param str catalog_name: (optional) catalog name.
    :param List[str] catalog_tags: (optional) catalog tags.
    :param str catalog_type: (optional) catalog type.
    """

    def __init__(
        self,
        *,
        catalog_name: Optional[str] = None,
        catalog_tags: Optional[List[str]] = None,
        catalog_type: Optional[str] = None,
    ) -> None:
        """
        Initialize a BucketCatalog object.

        :param str catalog_name: (optional) catalog name.
        :param List[str] catalog_tags: (optional) catalog tags.
        :param str catalog_type: (optional) catalog type.
        """
        self.catalog_name = catalog_name
        self.catalog_tags = catalog_tags
        self.catalog_type = catalog_type

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'BucketCatalog':
        """Initialize a BucketCatalog object from a json dictionary."""
        args = {}
        if (catalog_name := _dict.get('catalog_name')) is not None:
            args['catalog_name'] = catalog_name
        if (catalog_tags := _dict.get('catalog_tags')) is not None:
            args['catalog_tags'] = catalog_tags
        if (catalog_type := _dict.get('catalog_type')) is not None:
            args['catalog_type'] = catalog_type
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a BucketCatalog object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'catalog_name') and self.catalog_name is not None:
            _dict['catalog_name'] = self.catalog_name
        if hasattr(self, 'catalog_tags') and self.catalog_tags is not None:
            _dict['catalog_tags'] = self.catalog_tags
        if hasattr(self, 'catalog_type') and self.catalog_type is not None:
            _dict['catalog_type'] = self.catalog_type
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this BucketCatalog object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'BucketCatalog') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'BucketCatalog') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class BucketDetails:
    """
    bucket details.

    :param str access_key: (optional) Access key ID, encrypted during bucket
          registration.
    :param str bucket_name: actual bucket name.
    :param str endpoint: (optional) Cos endpoint.
    :param str key_file: (optional) Key file, encrypted during bucket registration.
    :param str provider: (optional) bucket provider.
    :param str region: (optional) Region where the bucket is located.
    :param str secret_key: (optional) Secret access key, encrypted during bucket
          registration.
    """

    def __init__(
        self,
        bucket_name: str,
        *,
        access_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        key_file: Optional[str] = None,
        provider: Optional[str] = None,
        region: Optional[str] = None,
        secret_key: Optional[str] = None,
    ) -> None:
        """
        Initialize a BucketDetails object.

        :param str bucket_name: actual bucket name.
        :param str access_key: (optional) Access key ID, encrypted during bucket
               registration.
        :param str endpoint: (optional) Cos endpoint.
        :param str key_file: (optional) Key file, encrypted during bucket
               registration.
        :param str provider: (optional) bucket provider.
        :param str region: (optional) Region where the bucket is located.
        :param str secret_key: (optional) Secret access key, encrypted during
               bucket registration.
        """
        self.access_key = access_key
        self.bucket_name = bucket_name
        self.endpoint = endpoint
        self.key_file = key_file
        self.provider = provider
        self.region = region
        self.secret_key = secret_key

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'BucketDetails':
        """Initialize a BucketDetails object from a json dictionary."""
        args = {}
        if (access_key := _dict.get('access_key')) is not None:
            args['access_key'] = access_key
        if (bucket_name := _dict.get('bucket_name')) is not None:
            args['bucket_name'] = bucket_name
        else:
            raise ValueError('Required property \'bucket_name\' not present in BucketDetails JSON')
        if (endpoint := _dict.get('endpoint')) is not None:
            args['endpoint'] = endpoint
        if (key_file := _dict.get('key_file')) is not None:
            args['key_file'] = key_file
        if (provider := _dict.get('provider')) is not None:
            args['provider'] = provider
        if (region := _dict.get('region')) is not None:
            args['region'] = region
        if (secret_key := _dict.get('secret_key')) is not None:
            args['secret_key'] = secret_key
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
        if hasattr(self, 'key_file') and self.key_file is not None:
            _dict['key_file'] = self.key_file
        if hasattr(self, 'provider') and self.provider is not None:
            _dict['provider'] = self.provider
        if hasattr(self, 'region') and self.region is not None:
            _dict['region'] = self.region
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


class BucketObjectProperties:
    """
    muliple bucket object properties.

    :param List[BucketRegistrationObjectSizeCollection] object_properties:
          (optional) muliple bucket object properties.
    """

    def __init__(
        self,
        *,
        object_properties: Optional[List['BucketRegistrationObjectSizeCollection']] = None,
    ) -> None:
        """
        Initialize a BucketObjectProperties object.

        :param List[BucketRegistrationObjectSizeCollection] object_properties:
               (optional) muliple bucket object properties.
        """
        self.object_properties = object_properties

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'BucketObjectProperties':
        """Initialize a BucketObjectProperties object from a json dictionary."""
        args = {}
        if (object_properties := _dict.get('object_properties')) is not None:
            args['object_properties'] = [BucketRegistrationObjectSizeCollection.from_dict(v) for v in object_properties]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a BucketObjectProperties object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'object_properties') and self.object_properties is not None:
            object_properties_list = []
            for v in self.object_properties:
                if isinstance(v, dict):
                    object_properties_list.append(v)
                else:
                    object_properties_list.append(v.to_dict())
            _dict['object_properties'] = object_properties_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this BucketObjectProperties object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'BucketObjectProperties') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'BucketObjectProperties') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class BucketRegistration:
    """
    Bucket.

    :param List[str] actions: (optional) Actions.
    :param BucketCatalog associated_catalog: bucket catalog.
    :param BucketDetails bucket_details: (optional) bucket details.
    :param str bucket_display_name: (optional) bucket display name.
    :param str bucket_id: (optional) bucket ID auto generated during bucket
          registration.
    :param str bucket_type: bucket type.
    :param str created_by: Username who created the bucket.
    :param str created_on: Creation date.
    :param str description: bucket description.
    :param str managed_by: managed by.
    :param str region: (optional) Region where the bucket is located.
    :param str state: mark bucket active or inactive.
    :param StorageDetails storage_details: (optional) storage details.
    :param List[str] tags: (optional) tags.
    """

    def __init__(
        self,
        associated_catalog: 'BucketCatalog',
        bucket_type: str,
        created_by: str,
        created_on: str,
        description: str,
        managed_by: str,
        state: str,
        *,
        actions: Optional[List[str]] = None,
        bucket_details: Optional['BucketDetails'] = None,
        bucket_display_name: Optional[str] = None,
        bucket_id: Optional[str] = None,
        region: Optional[str] = None,
        storage_details: Optional['StorageDetails'] = None,
        tags: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a BucketRegistration object.

        :param BucketCatalog associated_catalog: bucket catalog.
        :param str bucket_type: bucket type.
        :param str created_by: Username who created the bucket.
        :param str created_on: Creation date.
        :param str description: bucket description.
        :param str managed_by: managed by.
        :param str state: mark bucket active or inactive.
        :param List[str] actions: (optional) Actions.
        :param BucketDetails bucket_details: (optional) bucket details.
        :param str bucket_display_name: (optional) bucket display name.
        :param str bucket_id: (optional) bucket ID auto generated during bucket
               registration.
        :param str region: (optional) Region where the bucket is located.
        :param StorageDetails storage_details: (optional) storage details.
        :param List[str] tags: (optional) tags.
        """
        self.actions = actions
        self.associated_catalog = associated_catalog
        self.bucket_details = bucket_details
        self.bucket_display_name = bucket_display_name
        self.bucket_id = bucket_id
        self.bucket_type = bucket_type
        self.created_by = created_by
        self.created_on = created_on
        self.description = description
        self.managed_by = managed_by
        self.region = region
        self.state = state
        self.storage_details = storage_details
        self.tags = tags

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'BucketRegistration':
        """Initialize a BucketRegistration object from a json dictionary."""
        args = {}
        if (actions := _dict.get('actions')) is not None:
            args['actions'] = actions
        if (associated_catalog := _dict.get('associated_catalog')) is not None:
            args['associated_catalog'] = BucketCatalog.from_dict(associated_catalog)
        else:
            raise ValueError('Required property \'associated_catalog\' not present in BucketRegistration JSON')
        if (bucket_details := _dict.get('bucket_details')) is not None:
            args['bucket_details'] = BucketDetails.from_dict(bucket_details)
        if (bucket_display_name := _dict.get('bucket_display_name')) is not None:
            args['bucket_display_name'] = bucket_display_name
        if (bucket_id := _dict.get('bucket_id')) is not None:
            args['bucket_id'] = bucket_id
        if (bucket_type := _dict.get('bucket_type')) is not None:
            args['bucket_type'] = bucket_type
        else:
            raise ValueError('Required property \'bucket_type\' not present in BucketRegistration JSON')
        if (created_by := _dict.get('created_by')) is not None:
            args['created_by'] = created_by
        else:
            raise ValueError('Required property \'created_by\' not present in BucketRegistration JSON')
        if (created_on := _dict.get('created_on')) is not None:
            args['created_on'] = created_on
        else:
            raise ValueError('Required property \'created_on\' not present in BucketRegistration JSON')
        if (description := _dict.get('description')) is not None:
            args['description'] = description
        else:
            raise ValueError('Required property \'description\' not present in BucketRegistration JSON')
        if (managed_by := _dict.get('managed_by')) is not None:
            args['managed_by'] = managed_by
        else:
            raise ValueError('Required property \'managed_by\' not present in BucketRegistration JSON')
        if (region := _dict.get('region')) is not None:
            args['region'] = region
        if (state := _dict.get('state')) is not None:
            args['state'] = state
        else:
            raise ValueError('Required property \'state\' not present in BucketRegistration JSON')
        if (storage_details := _dict.get('storage_details')) is not None:
            args['storage_details'] = StorageDetails.from_dict(storage_details)
        if (tags := _dict.get('tags')) is not None:
            args['tags'] = tags
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a BucketRegistration object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'actions') and self.actions is not None:
            _dict['actions'] = self.actions
        if hasattr(self, 'associated_catalog') and self.associated_catalog is not None:
            if isinstance(self.associated_catalog, dict):
                _dict['associated_catalog'] = self.associated_catalog
            else:
                _dict['associated_catalog'] = self.associated_catalog.to_dict()
        if hasattr(self, 'bucket_details') and self.bucket_details is not None:
            if isinstance(self.bucket_details, dict):
                _dict['bucket_details'] = self.bucket_details
            else:
                _dict['bucket_details'] = self.bucket_details.to_dict()
        if hasattr(self, 'bucket_display_name') and self.bucket_display_name is not None:
            _dict['bucket_display_name'] = self.bucket_display_name
        if hasattr(self, 'bucket_id') and self.bucket_id is not None:
            _dict['bucket_id'] = self.bucket_id
        if hasattr(self, 'bucket_type') and self.bucket_type is not None:
            _dict['bucket_type'] = self.bucket_type
        if hasattr(self, 'created_by') and self.created_by is not None:
            _dict['created_by'] = self.created_by
        if hasattr(self, 'created_on') and self.created_on is not None:
            _dict['created_on'] = self.created_on
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'managed_by') and self.managed_by is not None:
            _dict['managed_by'] = self.managed_by
        if hasattr(self, 'region') and self.region is not None:
            _dict['region'] = self.region
        if hasattr(self, 'state') and self.state is not None:
            _dict['state'] = self.state
        if hasattr(self, 'storage_details') and self.storage_details is not None:
            if isinstance(self.storage_details, dict):
                _dict['storage_details'] = self.storage_details
            else:
                _dict['storage_details'] = self.storage_details.to_dict()
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
        bucket type.
        """

        AMAZON_S3 = 'amazon_s3'
        AWS_S3 = 'aws_s3'
        MINIO = 'minio'
        IBM_COS = 'ibm_cos'
        IBM_CEPH = 'ibm_ceph'
        ADLS_GEN1 = 'adls_gen1'
        ADLS_GEN2 = 'adls_gen2'
        GOOGLE_CS = 'google_cs'


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



class BucketRegistrationCollection:
    """
    List bucket registrations.

    :param List[BucketRegistration] bucket_registrations: (optional) Buckets.
    """

    def __init__(
        self,
        *,
        bucket_registrations: Optional[List['BucketRegistration']] = None,
    ) -> None:
        """
        Initialize a BucketRegistrationCollection object.

        :param List[BucketRegistration] bucket_registrations: (optional) Buckets.
        """
        self.bucket_registrations = bucket_registrations

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'BucketRegistrationCollection':
        """Initialize a BucketRegistrationCollection object from a json dictionary."""
        args = {}
        if (bucket_registrations := _dict.get('bucket_registrations')) is not None:
            args['bucket_registrations'] = [BucketRegistration.from_dict(v) for v in bucket_registrations]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a BucketRegistrationCollection object from a json dictionary."""
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
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this BucketRegistrationCollection object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'BucketRegistrationCollection') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'BucketRegistrationCollection') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class BucketRegistrationObjectCollection:
    """
    List bucket objects.

    :param List[str] objects: (optional) bucket object.
    """

    def __init__(
        self,
        *,
        objects: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a BucketRegistrationObjectCollection object.

        :param List[str] objects: (optional) bucket object.
        """
        self.objects = objects

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'BucketRegistrationObjectCollection':
        """Initialize a BucketRegistrationObjectCollection object from a json dictionary."""
        args = {}
        if (objects := _dict.get('objects')) is not None:
            args['objects'] = objects
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a BucketRegistrationObjectCollection object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'objects') and self.objects is not None:
            _dict['objects'] = self.objects
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this BucketRegistrationObjectCollection object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'BucketRegistrationObjectCollection') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'BucketRegistrationObjectCollection') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class BucketRegistrationObjectSizeCollection:
    """
    Bucket object size.

    :param str content_type: (optional) content type.
    :param str file_type: (optional) file type.
    :param str last_modified: (optional) bucket last modified.
    :param dict metadata: (optional) Additional metadata associated with the object.
    :param str path: (optional) bucket last modified.
    :param str size: (optional) size of the bucket objects.
    """

    def __init__(
        self,
        *,
        content_type: Optional[str] = None,
        file_type: Optional[str] = None,
        last_modified: Optional[str] = None,
        metadata: Optional[dict] = None,
        path: Optional[str] = None,
        size: Optional[str] = None,
    ) -> None:
        """
        Initialize a BucketRegistrationObjectSizeCollection object.

        :param str content_type: (optional) content type.
        :param str file_type: (optional) file type.
        :param str last_modified: (optional) bucket last modified.
        :param dict metadata: (optional) Additional metadata associated with the
               object.
        :param str path: (optional) bucket last modified.
        :param str size: (optional) size of the bucket objects.
        """
        self.content_type = content_type
        self.file_type = file_type
        self.last_modified = last_modified
        self.metadata = metadata
        self.path = path
        self.size = size

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'BucketRegistrationObjectSizeCollection':
        """Initialize a BucketRegistrationObjectSizeCollection object from a json dictionary."""
        args = {}
        if (content_type := _dict.get('content_type')) is not None:
            args['content_type'] = content_type
        if (file_type := _dict.get('file_type')) is not None:
            args['file_type'] = file_type
        if (last_modified := _dict.get('last_modified')) is not None:
            args['last_modified'] = last_modified
        if (metadata := _dict.get('metadata')) is not None:
            args['metadata'] = metadata
        if (path := _dict.get('path')) is not None:
            args['path'] = path
        if (size := _dict.get('size')) is not None:
            args['size'] = size
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a BucketRegistrationObjectSizeCollection object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'content_type') and self.content_type is not None:
            _dict['content_type'] = self.content_type
        if hasattr(self, 'file_type') and self.file_type is not None:
            _dict['file_type'] = self.file_type
        if hasattr(self, 'last_modified') and self.last_modified is not None:
            _dict['last_modified'] = self.last_modified
        if hasattr(self, 'metadata') and self.metadata is not None:
            _dict['metadata'] = self.metadata
        if hasattr(self, 'path') and self.path is not None:
            _dict['path'] = self.path
        if hasattr(self, 'size') and self.size is not None:
            _dict['size'] = self.size
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this BucketRegistrationObjectSizeCollection object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'BucketRegistrationObjectSizeCollection') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'BucketRegistrationObjectSizeCollection') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class BucketRegistrationPatch:
    """
    Update bucket parameters.

    :param BucketDetails bucket_details: (optional) bucket details.
    :param str bucket_display_name: (optional) bucket display name.
    :param str description: (optional) modified description.
    :param List[str] tags: (optional) Tags.
    """

    def __init__(
        self,
        *,
        bucket_details: Optional['BucketDetails'] = None,
        bucket_display_name: Optional[str] = None,
        description: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a BucketRegistrationPatch object.

        :param BucketDetails bucket_details: (optional) bucket details.
        :param str bucket_display_name: (optional) bucket display name.
        :param str description: (optional) modified description.
        :param List[str] tags: (optional) Tags.
        """
        self.bucket_details = bucket_details
        self.bucket_display_name = bucket_display_name
        self.description = description
        self.tags = tags

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'BucketRegistrationPatch':
        """Initialize a BucketRegistrationPatch object from a json dictionary."""
        args = {}
        if (bucket_details := _dict.get('bucket_details')) is not None:
            args['bucket_details'] = BucketDetails.from_dict(bucket_details)
        if (bucket_display_name := _dict.get('bucket_display_name')) is not None:
            args['bucket_display_name'] = bucket_display_name
        if (description := _dict.get('description')) is not None:
            args['description'] = description
        if (tags := _dict.get('tags')) is not None:
            args['tags'] = tags
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a BucketRegistrationPatch object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'bucket_details') and self.bucket_details is not None:
            if isinstance(self.bucket_details, dict):
                _dict['bucket_details'] = self.bucket_details
            else:
                _dict['bucket_details'] = self.bucket_details.to_dict()
        if hasattr(self, 'bucket_display_name') and self.bucket_display_name is not None:
            _dict['bucket_display_name'] = self.bucket_display_name
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'tags') and self.tags is not None:
            _dict['tags'] = self.tags
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this BucketRegistrationPatch object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'BucketRegistrationPatch') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'BucketRegistrationPatch') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class Catalog:
    """
    Define the catalog details.

    :param List[str] actions: (optional) list of allowed actions.
    :param List[str] associated_buckets: (optional) Associated buckets items.
    :param List[str] associated_databases: (optional) Associated databases items.
    :param List[str] associated_engines: (optional) Associated engines items.
    :param str catalog_name: (optional) Name for the catalog.
    :param str catalog_names: (optional) catalog names.
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
        catalog_names: Optional[str] = None,
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
        Initialize a Catalog object.

        :param List[str] actions: (optional) list of allowed actions.
        :param List[str] associated_buckets: (optional) Associated buckets items.
        :param List[str] associated_databases: (optional) Associated databases
               items.
        :param List[str] associated_engines: (optional) Associated engines items.
        :param str catalog_name: (optional) Name for the catalog.
        :param str catalog_names: (optional) catalog names.
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
        self.catalog_names = catalog_names
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
    def from_dict(cls, _dict: Dict) -> 'Catalog':
        """Initialize a Catalog object from a json dictionary."""
        args = {}
        if (actions := _dict.get('actions')) is not None:
            args['actions'] = actions
        if (associated_buckets := _dict.get('associated_buckets')) is not None:
            args['associated_buckets'] = associated_buckets
        if (associated_databases := _dict.get('associated_databases')) is not None:
            args['associated_databases'] = associated_databases
        if (associated_engines := _dict.get('associated_engines')) is not None:
            args['associated_engines'] = associated_engines
        if (catalog_name := _dict.get('catalog_name')) is not None:
            args['catalog_name'] = catalog_name
        if (catalog_names := _dict.get('catalog_names')) is not None:
            args['catalog_names'] = catalog_names
        if (created_by := _dict.get('created_by')) is not None:
            args['created_by'] = created_by
        if (created_on := _dict.get('created_on')) is not None:
            args['created_on'] = created_on
        if (description := _dict.get('description')) is not None:
            args['description'] = description
        if (hostname := _dict.get('hostname')) is not None:
            args['hostname'] = hostname
        if (last_sync_at := _dict.get('last_sync_at')) is not None:
            args['last_sync_at'] = last_sync_at
        if (managed_by := _dict.get('managed_by')) is not None:
            args['managed_by'] = managed_by
        if (metastore := _dict.get('metastore')) is not None:
            args['metastore'] = metastore
        if (port := _dict.get('port')) is not None:
            args['port'] = port
        if (status := _dict.get('status')) is not None:
            args['status'] = status
        if (sync_description := _dict.get('sync_description')) is not None:
            args['sync_description'] = sync_description
        if (sync_exception := _dict.get('sync_exception')) is not None:
            args['sync_exception'] = sync_exception
        if (sync_status := _dict.get('sync_status')) is not None:
            args['sync_status'] = sync_status
        if (tags := _dict.get('tags')) is not None:
            args['tags'] = tags
        if (thrift_uri := _dict.get('thrift_uri')) is not None:
            args['thrift_uri'] = thrift_uri
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a Catalog object from a json dictionary."""
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
        if hasattr(self, 'catalog_names') and self.catalog_names is not None:
            _dict['catalog_names'] = self.catalog_names
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

    class ManagedByEnum(str, Enum):
        """
        Managed by.
        """

        IBM = 'ibm'
        CUSTOMER = 'customer'



class CatalogCollection:
    """
    GetCatalogs OK.

    :param List[Catalog] catalogs: (optional) Catalogs.
    """

    def __init__(
        self,
        *,
        catalogs: Optional[List['Catalog']] = None,
    ) -> None:
        """
        Initialize a CatalogCollection object.

        :param List[Catalog] catalogs: (optional) Catalogs.
        """
        self.catalogs = catalogs

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CatalogCollection':
        """Initialize a CatalogCollection object from a json dictionary."""
        args = {}
        if (catalogs := _dict.get('catalogs')) is not None:
            args['catalogs'] = [Catalog.from_dict(v) for v in catalogs]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CatalogCollection object from a json dictionary."""
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
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CatalogCollection object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CatalogCollection') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CatalogCollection') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class Column:
    """
    Column.

    :param str column_name: (optional) Column name.
    :param str comment: (optional) Comment.
    :param str extra: (optional) Extra.
    :param str length: (optional) length.
    :param str scale: (optional) scale.
    :param str precision: (optional) precision.
    :param str type: (optional) Data type.
    """

    def __init__(
        self,
        *,
        column_name: Optional[str] = None,
        comment: Optional[str] = None,
        extra: Optional[str] = None,
        length: Optional[str] = None,
        scale: Optional[str] = None,
        precision: Optional[str] = None,
        type: Optional[str] = None,
    ) -> None:
        """
        Initialize a Column object.

        :param str column_name: (optional) Column name.
        :param str comment: (optional) Comment.
        :param str extra: (optional) Extra.
        :param str length: (optional) length.
        :param str scale: (optional) scale.
        :param str precision: (optional) precision.
        :param str type: (optional) Data type.
        """
        self.column_name = column_name
        self.comment = comment
        self.extra = extra
        self.length = length
        self.scale = scale
        self.precision = precision
        self.type = type

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'Column':
        """Initialize a Column object from a json dictionary."""
        args = {}
        if (column_name := _dict.get('column_name')) is not None:
            args['column_name'] = column_name
        if (comment := _dict.get('comment')) is not None:
            args['comment'] = comment
        if (extra := _dict.get('extra')) is not None:
            args['extra'] = extra
        if (length := _dict.get('length')) is not None:
            args['length'] = length
        if (scale := _dict.get('scale')) is not None:
            args['scale'] = scale
        if (precision := _dict.get('precision')) is not None:
            args['precision'] = precision
        if (type := _dict.get('type')) is not None:
            args['type'] = type
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
        if hasattr(self, 'length') and self.length is not None:
            _dict['length'] = self.length
        if hasattr(self, 'scale') and self.scale is not None:
            _dict['scale'] = self.scale
        if hasattr(self, 'precision') and self.precision is not None:
            _dict['precision'] = self.precision
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


class ColumnCollection:
    """
    list of columns in a table.

    :param List[Column] columns: (optional) List of the columns present in the
          table.
    """

    def __init__(
        self,
        *,
        columns: Optional[List['Column']] = None,
    ) -> None:
        """
        Initialize a ColumnCollection object.

        :param List[Column] columns: (optional) List of the columns present in the
               table.
        """
        self.columns = columns

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ColumnCollection':
        """Initialize a ColumnCollection object from a json dictionary."""
        args = {}
        if (columns := _dict.get('columns')) is not None:
            args['columns'] = [Column.from_dict(v) for v in columns]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ColumnCollection object from a json dictionary."""
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
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ColumnCollection object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ColumnCollection') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ColumnCollection') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ColumnPatch:
    """
    list of columns to be added to a table.

    :param str column_name: (optional) Column name.
    """

    def __init__(
        self,
        *,
        column_name: Optional[str] = None,
    ) -> None:
        """
        Initialize a ColumnPatch object.

        :param str column_name: (optional) Column name.
        """
        self.column_name = column_name

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ColumnPatch':
        """Initialize a ColumnPatch object from a json dictionary."""
        args = {}
        if (column_name := _dict.get('column_name')) is not None:
            args['column_name'] = column_name
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ColumnPatch object from a json dictionary."""
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
        """Return a `str` version of this ColumnPatch object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ColumnPatch') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ColumnPatch') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ColumnsResponse:
    """
    Column details.

    :param List[TableColumDetail] columns: (optional) A list of all tables with
          columns.
    :param str message: (optional) Response message string.
    :param str message_code: (optional) Message code string.
    """

    def __init__(
        self,
        *,
        columns: Optional[List['TableColumDetail']] = None,
        message: Optional[str] = None,
        message_code: Optional[str] = None,
    ) -> None:
        """
        Initialize a ColumnsResponse object.

        :param List[TableColumDetail] columns: (optional) A list of all tables with
               columns.
        :param str message: (optional) Response message string.
        :param str message_code: (optional) Message code string.
        """
        self.columns = columns
        self.message = message
        self.message_code = message_code

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ColumnsResponse':
        """Initialize a ColumnsResponse object from a json dictionary."""
        args = {}
        if (columns := _dict.get('columns')) is not None:
            args['columns'] = [TableColumDetail.from_dict(v) for v in columns]
        if (message := _dict.get('message')) is not None:
            args['message'] = message
        if (message_code := _dict.get('message_code')) is not None:
            args['message_code'] = message_code
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ColumnsResponse object from a json dictionary."""
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
        if hasattr(self, 'message') and self.message is not None:
            _dict['message'] = self.message
        if hasattr(self, 'message_code') and self.message_code is not None:
            _dict['message_code'] = self.message_code
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ColumnsResponse object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ColumnsResponse') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ColumnsResponse') -> bool:
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
        if (response := _dict.get('response')) is not None:
            args['response'] = SuccessResponse.from_dict(response)
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
        if (response := _dict.get('response')) is not None:
            args['response'] = SuccessResponse.from_dict(response)
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
        if (response := _dict.get('response')) is not None:
            args['response'] = SuccessResponse.from_dict(response)
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
        if (response := _dict.get('response')) is not None:
            args['response'] = SuccessResponse.from_dict(response)
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
        if (response := _dict.get('response')) is not None:
            args['response'] = SuccessResponse.from_dict(response)
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
        if (response := _dict.get('response')) is not None:
            args['response'] = SuccessResponse.from_dict(response)
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


class DatabaseCatalog:
    """
    database catalog.

    :param str catalog_name: (optional) catalog name.
    :param List[str] catalog_tags: (optional) catalog tags.
    :param str catalog_type: (optional) catalog type.
    """

    def __init__(
        self,
        *,
        catalog_name: Optional[str] = None,
        catalog_tags: Optional[List[str]] = None,
        catalog_type: Optional[str] = None,
    ) -> None:
        """
        Initialize a DatabaseCatalog object.

        :param str catalog_name: (optional) catalog name.
        :param List[str] catalog_tags: (optional) catalog tags.
        :param str catalog_type: (optional) catalog type.
        """
        self.catalog_name = catalog_name
        self.catalog_tags = catalog_tags
        self.catalog_type = catalog_type

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'DatabaseCatalog':
        """Initialize a DatabaseCatalog object from a json dictionary."""
        args = {}
        if (catalog_name := _dict.get('catalog_name')) is not None:
            args['catalog_name'] = catalog_name
        if (catalog_tags := _dict.get('catalog_tags')) is not None:
            args['catalog_tags'] = catalog_tags
        if (catalog_type := _dict.get('catalog_type')) is not None:
            args['catalog_type'] = catalog_type
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a DatabaseCatalog object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'catalog_name') and self.catalog_name is not None:
            _dict['catalog_name'] = self.catalog_name
        if hasattr(self, 'catalog_tags') and self.catalog_tags is not None:
            _dict['catalog_tags'] = self.catalog_tags
        if hasattr(self, 'catalog_type') and self.catalog_type is not None:
            _dict['catalog_type'] = self.catalog_type
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this DatabaseCatalog object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'DatabaseCatalog') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'DatabaseCatalog') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class DatabaseDetails:
    """
    database details.

    :param str authentication_type: (optional) Authentication method.
    :param str authentication_value: (optional) Authentication method.
    :param str broker_authentication_password: (optional) Broker authentication
          password.
    :param str broker_authentication_type: (optional) Broker authentication type.
    :param str broker_authentication_user: (optional) Broker authentication user.
    :param str broker_host: (optional) Broker host.
    :param int broker_port: (optional) Broker port.
    :param str certificate: (optional) contents of a pem/crt file.
    :param str certificate_extension: (optional) extension of the certificate file.
    :param str connection_method: (optional) connection mode.
    :param str connection_mode: (optional) connection mode.
    :param str connection_mode_value: (optional) connection mode value.
    :param str connection_type: (optional) Connection type.
    :param str controller_authentication_password: (optional) Controller
          authentication password.
    :param str controller_authentication_type: (optional) Controller authentication
          type.
    :param str controller_authentication_user: (optional) Controller authentication
          user.
    :param str coordinator_host: (optional) Coordinator host.
    :param int coordinator_port: (optional) Coordinator port.
    :param str cpd_hostname: (optional) CPD Hostname.
    :param str credentials_key: (optional) Base 64 encoded json file.
    :param str database_name: (optional) Database name.
    :param List[DatabaseRegistrationPatchDatabaseDetailsDatabasePropertiesItems]
          database_properties: (optional) This will hold all the properties for a custom
          database.
    :param str hostname: (optional) Host name.
    :param str hostname_in_certificate: (optional) Hostname in certificate.
    :param str hosts: (optional) String of hostname:port.
    :param str informix_server: (optional) informix server value.
    :param str password: (optional) Psssword.
    :param int port: (optional) Port.
    :param str project_id: (optional) Project ID.
    :param bool sasl: (optional) SASL Mode.
    :param str sasl_mechanism: (optional) sasl mechanism for kafka.
    :param str schema_name: (optional) Schema name.
    :param str schemas: (optional) Add tables.
    :param str service_api_key: (optional) service api key.
    :param str service_hostname: (optional) service hostname.
    :param str service_password: (optional) service password.
    :param int service_port: (optional) Service Port.
    :param bool service_ssl: (optional) Service SSL Mode.
    :param str service_token_url: (optional) service token url.
    :param str service_username: (optional) service username.
    :param bool ssl: (optional) SSL Mode.
    :param str tables: (optional) Add tables.
    :param str username: (optional) Username.
    :param bool validate_server_certificate: (optional) Verify certificate.
    :param bool verify_host_name: (optional) Verify host name.
    :param str warehouse_name: (optional) Warehouse name.
    """

    def __init__(
        self,
        *,
        authentication_type: Optional[str] = None,
        authentication_value: Optional[str] = None,
        broker_authentication_password: Optional[str] = None,
        broker_authentication_type: Optional[str] = None,
        broker_authentication_user: Optional[str] = None,
        broker_host: Optional[str] = None,
        broker_port: Optional[int] = None,
        certificate: Optional[str] = None,
        certificate_extension: Optional[str] = None,
        connection_method: Optional[str] = None,
        connection_mode: Optional[str] = None,
        connection_mode_value: Optional[str] = None,
        connection_type: Optional[str] = None,
        controller_authentication_password: Optional[str] = None,
        controller_authentication_type: Optional[str] = None,
        controller_authentication_user: Optional[str] = None,
        coordinator_host: Optional[str] = None,
        coordinator_port: Optional[int] = None,
        cpd_hostname: Optional[str] = None,
        credentials_key: Optional[str] = None,
        database_name: Optional[str] = None,
        database_properties: Optional[List['DatabaseRegistrationPatchDatabaseDetailsDatabasePropertiesItems']] = None,
        hostname: Optional[str] = None,
        hostname_in_certificate: Optional[str] = None,
        hosts: Optional[str] = None,
        informix_server: Optional[str] = None,
        password: Optional[str] = None,
        port: Optional[int] = None,
        project_id: Optional[str] = None,
        sasl: Optional[bool] = None,
        sasl_mechanism: Optional[str] = None,
        schema_name: Optional[str] = None,
        schemas: Optional[str] = None,
        service_api_key: Optional[str] = None,
        service_hostname: Optional[str] = None,
        service_password: Optional[str] = None,
        service_port: Optional[int] = None,
        service_ssl: Optional[bool] = None,
        service_token_url: Optional[str] = None,
        service_username: Optional[str] = None,
        ssl: Optional[bool] = None,
        tables: Optional[str] = None,
        username: Optional[str] = None,
        validate_server_certificate: Optional[bool] = None,
        verify_host_name: Optional[bool] = None,
        warehouse_name: Optional[str] = None,
    ) -> None:
        """
        Initialize a DatabaseDetails object.

        :param str authentication_type: (optional) Authentication method.
        :param str authentication_value: (optional) Authentication method.
        :param str broker_authentication_password: (optional) Broker authentication
               password.
        :param str broker_authentication_type: (optional) Broker authentication
               type.
        :param str broker_authentication_user: (optional) Broker authentication
               user.
        :param str broker_host: (optional) Broker host.
        :param int broker_port: (optional) Broker port.
        :param str certificate: (optional) contents of a pem/crt file.
        :param str certificate_extension: (optional) extension of the certificate
               file.
        :param str connection_method: (optional) connection mode.
        :param str connection_mode: (optional) connection mode.
        :param str connection_mode_value: (optional) connection mode value.
        :param str connection_type: (optional) Connection type.
        :param str controller_authentication_password: (optional) Controller
               authentication password.
        :param str controller_authentication_type: (optional) Controller
               authentication type.
        :param str controller_authentication_user: (optional) Controller
               authentication user.
        :param str coordinator_host: (optional) Coordinator host.
        :param int coordinator_port: (optional) Coordinator port.
        :param str cpd_hostname: (optional) CPD Hostname.
        :param str credentials_key: (optional) Base 64 encoded json file.
        :param str database_name: (optional) Database name.
        :param
               List[DatabaseRegistrationPatchDatabaseDetailsDatabasePropertiesItems]
               database_properties: (optional) This will hold all the properties for a
               custom database.
        :param str hostname: (optional) Host name.
        :param str hostname_in_certificate: (optional) Hostname in certificate.
        :param str hosts: (optional) String of hostname:port.
        :param str informix_server: (optional) informix server value.
        :param str password: (optional) Psssword.
        :param int port: (optional) Port.
        :param str project_id: (optional) Project ID.
        :param bool sasl: (optional) SASL Mode.
        :param str sasl_mechanism: (optional) sasl mechanism for kafka.
        :param str schema_name: (optional) Schema name.
        :param str schemas: (optional) Add tables.
        :param str service_api_key: (optional) service api key.
        :param str service_hostname: (optional) service hostname.
        :param str service_password: (optional) service password.
        :param int service_port: (optional) Service Port.
        :param bool service_ssl: (optional) Service SSL Mode.
        :param str service_token_url: (optional) service token url.
        :param str service_username: (optional) service username.
        :param bool ssl: (optional) SSL Mode.
        :param str tables: (optional) Add tables.
        :param str username: (optional) Username.
        :param bool validate_server_certificate: (optional) Verify certificate.
        :param bool verify_host_name: (optional) Verify host name.
        :param str warehouse_name: (optional) Warehouse name.
        """
        self.authentication_type = authentication_type
        self.authentication_value = authentication_value
        self.broker_authentication_password = broker_authentication_password
        self.broker_authentication_type = broker_authentication_type
        self.broker_authentication_user = broker_authentication_user
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.certificate = certificate
        self.certificate_extension = certificate_extension
        self.connection_method = connection_method
        self.connection_mode = connection_mode
        self.connection_mode_value = connection_mode_value
        self.connection_type = connection_type
        self.controller_authentication_password = controller_authentication_password
        self.controller_authentication_type = controller_authentication_type
        self.controller_authentication_user = controller_authentication_user
        self.coordinator_host = coordinator_host
        self.coordinator_port = coordinator_port
        self.cpd_hostname = cpd_hostname
        self.credentials_key = credentials_key
        self.database_name = database_name
        self.database_properties = database_properties
        self.hostname = hostname
        self.hostname_in_certificate = hostname_in_certificate
        self.hosts = hosts
        self.informix_server = informix_server
        self.password = password
        self.port = port
        self.project_id = project_id
        self.sasl = sasl
        self.sasl_mechanism = sasl_mechanism
        self.schema_name = schema_name
        self.schemas = schemas
        self.service_api_key = service_api_key
        self.service_hostname = service_hostname
        self.service_password = service_password
        self.service_port = service_port
        self.service_ssl = service_ssl
        self.service_token_url = service_token_url
        self.service_username = service_username
        self.ssl = ssl
        self.tables = tables
        self.username = username
        self.validate_server_certificate = validate_server_certificate
        self.verify_host_name = verify_host_name
        self.warehouse_name = warehouse_name

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'DatabaseDetails':
        """Initialize a DatabaseDetails object from a json dictionary."""
        args = {}
        if (authentication_type := _dict.get('authentication_type')) is not None:
            args['authentication_type'] = authentication_type
        if (authentication_value := _dict.get('authentication_value')) is not None:
            args['authentication_value'] = authentication_value
        if (broker_authentication_password := _dict.get('broker_authentication_password')) is not None:
            args['broker_authentication_password'] = broker_authentication_password
        if (broker_authentication_type := _dict.get('broker_authentication_type')) is not None:
            args['broker_authentication_type'] = broker_authentication_type
        if (broker_authentication_user := _dict.get('broker_authentication_user')) is not None:
            args['broker_authentication_user'] = broker_authentication_user
        if (broker_host := _dict.get('broker_host')) is not None:
            args['broker_host'] = broker_host
        if (broker_port := _dict.get('broker_port')) is not None:
            args['broker_port'] = broker_port
        if (certificate := _dict.get('certificate')) is not None:
            args['certificate'] = certificate
        if (certificate_extension := _dict.get('certificate_extension')) is not None:
            args['certificate_extension'] = certificate_extension
        if (connection_method := _dict.get('connection_method')) is not None:
            args['connection_method'] = connection_method
        if (connection_mode := _dict.get('connection_mode')) is not None:
            args['connection_mode'] = connection_mode
        if (connection_mode_value := _dict.get('connection_mode_value')) is not None:
            args['connection_mode_value'] = connection_mode_value
        if (connection_type := _dict.get('connection_type')) is not None:
            args['connection_type'] = connection_type
        if (controller_authentication_password := _dict.get('controller_authentication_password')) is not None:
            args['controller_authentication_password'] = controller_authentication_password
        if (controller_authentication_type := _dict.get('controller_authentication_type')) is not None:
            args['controller_authentication_type'] = controller_authentication_type
        if (controller_authentication_user := _dict.get('controller_authentication_user')) is not None:
            args['controller_authentication_user'] = controller_authentication_user
        if (coordinator_host := _dict.get('coordinator_host')) is not None:
            args['coordinator_host'] = coordinator_host
        if (coordinator_port := _dict.get('coordinator_port')) is not None:
            args['coordinator_port'] = coordinator_port
        if (cpd_hostname := _dict.get('cpd_hostname')) is not None:
            args['cpd_hostname'] = cpd_hostname
        if (credentials_key := _dict.get('credentials_key')) is not None:
            args['credentials_key'] = credentials_key
        if (database_name := _dict.get('database_name')) is not None:
            args['database_name'] = database_name
        if (database_properties := _dict.get('database_properties')) is not None:
            args['database_properties'] = [DatabaseRegistrationPatchDatabaseDetailsDatabasePropertiesItems.from_dict(v) for v in database_properties]
        if (hostname := _dict.get('hostname')) is not None:
            args['hostname'] = hostname
        if (hostname_in_certificate := _dict.get('hostname_in_certificate')) is not None:
            args['hostname_in_certificate'] = hostname_in_certificate
        if (hosts := _dict.get('hosts')) is not None:
            args['hosts'] = hosts
        if (informix_server := _dict.get('informix_server')) is not None:
            args['informix_server'] = informix_server
        if (password := _dict.get('password')) is not None:
            args['password'] = password
        if (port := _dict.get('port')) is not None:
            args['port'] = port
        if (project_id := _dict.get('project_id')) is not None:
            args['project_id'] = project_id
        if (sasl := _dict.get('sasl')) is not None:
            args['sasl'] = sasl
        if (sasl_mechanism := _dict.get('sasl_mechanism')) is not None:
            args['sasl_mechanism'] = sasl_mechanism
        if (schema_name := _dict.get('schema_name')) is not None:
            args['schema_name'] = schema_name
        if (schemas := _dict.get('schemas')) is not None:
            args['schemas'] = schemas
        if (service_api_key := _dict.get('service_api_key')) is not None:
            args['service_api_key'] = service_api_key
        if (service_hostname := _dict.get('service_hostname')) is not None:
            args['service_hostname'] = service_hostname
        if (service_password := _dict.get('service_password')) is not None:
            args['service_password'] = service_password
        if (service_port := _dict.get('service_port')) is not None:
            args['service_port'] = service_port
        if (service_ssl := _dict.get('service_ssl')) is not None:
            args['service_ssl'] = service_ssl
        if (service_token_url := _dict.get('service_token_url')) is not None:
            args['service_token_url'] = service_token_url
        if (service_username := _dict.get('service_username')) is not None:
            args['service_username'] = service_username
        if (ssl := _dict.get('ssl')) is not None:
            args['ssl'] = ssl
        if (tables := _dict.get('tables')) is not None:
            args['tables'] = tables
        if (username := _dict.get('username')) is not None:
            args['username'] = username
        if (validate_server_certificate := _dict.get('validate_server_certificate')) is not None:
            args['validate_server_certificate'] = validate_server_certificate
        if (verify_host_name := _dict.get('verify_host_name')) is not None:
            args['verify_host_name'] = verify_host_name
        if (warehouse_name := _dict.get('warehouse_name')) is not None:
            args['warehouse_name'] = warehouse_name
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a DatabaseDetails object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'authentication_type') and self.authentication_type is not None:
            _dict['authentication_type'] = self.authentication_type
        if hasattr(self, 'authentication_value') and self.authentication_value is not None:
            _dict['authentication_value'] = self.authentication_value
        if hasattr(self, 'broker_authentication_password') and self.broker_authentication_password is not None:
            _dict['broker_authentication_password'] = self.broker_authentication_password
        if hasattr(self, 'broker_authentication_type') and self.broker_authentication_type is not None:
            _dict['broker_authentication_type'] = self.broker_authentication_type
        if hasattr(self, 'broker_authentication_user') and self.broker_authentication_user is not None:
            _dict['broker_authentication_user'] = self.broker_authentication_user
        if hasattr(self, 'broker_host') and self.broker_host is not None:
            _dict['broker_host'] = self.broker_host
        if hasattr(self, 'broker_port') and self.broker_port is not None:
            _dict['broker_port'] = self.broker_port
        if hasattr(self, 'certificate') and self.certificate is not None:
            _dict['certificate'] = self.certificate
        if hasattr(self, 'certificate_extension') and self.certificate_extension is not None:
            _dict['certificate_extension'] = self.certificate_extension
        if hasattr(self, 'connection_method') and self.connection_method is not None:
            _dict['connection_method'] = self.connection_method
        if hasattr(self, 'connection_mode') and self.connection_mode is not None:
            _dict['connection_mode'] = self.connection_mode
        if hasattr(self, 'connection_mode_value') and self.connection_mode_value is not None:
            _dict['connection_mode_value'] = self.connection_mode_value
        if hasattr(self, 'connection_type') and self.connection_type is not None:
            _dict['connection_type'] = self.connection_type
        if hasattr(self, 'controller_authentication_password') and self.controller_authentication_password is not None:
            _dict['controller_authentication_password'] = self.controller_authentication_password
        if hasattr(self, 'controller_authentication_type') and self.controller_authentication_type is not None:
            _dict['controller_authentication_type'] = self.controller_authentication_type
        if hasattr(self, 'controller_authentication_user') and self.controller_authentication_user is not None:
            _dict['controller_authentication_user'] = self.controller_authentication_user
        if hasattr(self, 'coordinator_host') and self.coordinator_host is not None:
            _dict['coordinator_host'] = self.coordinator_host
        if hasattr(self, 'coordinator_port') and self.coordinator_port is not None:
            _dict['coordinator_port'] = self.coordinator_port
        if hasattr(self, 'cpd_hostname') and self.cpd_hostname is not None:
            _dict['cpd_hostname'] = self.cpd_hostname
        if hasattr(self, 'credentials_key') and self.credentials_key is not None:
            _dict['credentials_key'] = self.credentials_key
        if hasattr(self, 'database_name') and self.database_name is not None:
            _dict['database_name'] = self.database_name
        if hasattr(self, 'database_properties') and self.database_properties is not None:
            database_properties_list = []
            for v in self.database_properties:
                if isinstance(v, dict):
                    database_properties_list.append(v)
                else:
                    database_properties_list.append(v.to_dict())
            _dict['database_properties'] = database_properties_list
        if hasattr(self, 'hostname') and self.hostname is not None:
            _dict['hostname'] = self.hostname
        if hasattr(self, 'hostname_in_certificate') and self.hostname_in_certificate is not None:
            _dict['hostname_in_certificate'] = self.hostname_in_certificate
        if hasattr(self, 'hosts') and self.hosts is not None:
            _dict['hosts'] = self.hosts
        if hasattr(self, 'informix_server') and self.informix_server is not None:
            _dict['informix_server'] = self.informix_server
        if hasattr(self, 'password') and self.password is not None:
            _dict['password'] = self.password
        if hasattr(self, 'port') and self.port is not None:
            _dict['port'] = self.port
        if hasattr(self, 'project_id') and self.project_id is not None:
            _dict['project_id'] = self.project_id
        if hasattr(self, 'sasl') and self.sasl is not None:
            _dict['sasl'] = self.sasl
        if hasattr(self, 'sasl_mechanism') and self.sasl_mechanism is not None:
            _dict['sasl_mechanism'] = self.sasl_mechanism
        if hasattr(self, 'schema_name') and self.schema_name is not None:
            _dict['schema_name'] = self.schema_name
        if hasattr(self, 'schemas') and self.schemas is not None:
            _dict['schemas'] = self.schemas
        if hasattr(self, 'service_api_key') and self.service_api_key is not None:
            _dict['service_api_key'] = self.service_api_key
        if hasattr(self, 'service_hostname') and self.service_hostname is not None:
            _dict['service_hostname'] = self.service_hostname
        if hasattr(self, 'service_password') and self.service_password is not None:
            _dict['service_password'] = self.service_password
        if hasattr(self, 'service_port') and self.service_port is not None:
            _dict['service_port'] = self.service_port
        if hasattr(self, 'service_ssl') and self.service_ssl is not None:
            _dict['service_ssl'] = self.service_ssl
        if hasattr(self, 'service_token_url') and self.service_token_url is not None:
            _dict['service_token_url'] = self.service_token_url
        if hasattr(self, 'service_username') and self.service_username is not None:
            _dict['service_username'] = self.service_username
        if hasattr(self, 'ssl') and self.ssl is not None:
            _dict['ssl'] = self.ssl
        if hasattr(self, 'tables') and self.tables is not None:
            _dict['tables'] = self.tables
        if hasattr(self, 'username') and self.username is not None:
            _dict['username'] = self.username
        if hasattr(self, 'validate_server_certificate') and self.validate_server_certificate is not None:
            _dict['validate_server_certificate'] = self.validate_server_certificate
        if hasattr(self, 'verify_host_name') and self.verify_host_name is not None:
            _dict['verify_host_name'] = self.verify_host_name
        if hasattr(self, 'warehouse_name') and self.warehouse_name is not None:
            _dict['warehouse_name'] = self.warehouse_name
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this DatabaseDetails object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'DatabaseDetails') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'DatabaseDetails') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class SaslMechanismEnum(str, Enum):
        """
        sasl mechanism for kafka.
        """

        PLAIN = 'plain'
        SCRAM_SHA_256 = 'scram_sha_256'
        SCRAM_SHA_512 = 'scram_sha_512'



class DatabaseRegistration:
    """
    database registration object.

    :param List[str] actions: (optional) actions.
    :param DatabaseCatalog associated_catalog: (optional) database catalog.
    :param str catalog_name: (optional) Catalog name.
    :param str created_by: (optional) Created by.
    :param str created_on: (optional) Created on.
    :param DatabaseDetails database_details: database details.
    :param str database_display_name: Database display name.
    :param str database_id: (optional) Database ID.
    :param List[DatabaseRegistrationDatabasePropertiesItems] database_properties:
          (optional) This will hold all the properties for a custom database.
    :param str database_type: Connector type.
    :param List[DatabaseRegistrationPatchTablesItems] tables: (optional) List of
          tables.
    :param str description: (optional) Database description.
    :param List[str] tags: (optional) tags.
    :param List[DatabaseRegistrationTopicsItems] topics: (optional) List of topics.
    """

    def __init__(
        self,
        database_details: 'DatabaseDetails',
        database_display_name: str,
        database_type: str,
        *,
        actions: Optional[List[str]] = None,
        associated_catalog: Optional['DatabaseCatalog'] = None,
        catalog_name: Optional[str] = None,
        created_by: Optional[str] = None,
        created_on: Optional[str] = None,
        database_id: Optional[str] = None,
        database_properties: Optional[List['DatabaseRegistrationDatabasePropertiesItems']] = None,
        tables: Optional[List['DatabaseRegistrationPatchTablesItems']] = None,
        description: Optional[str] = None,
        tags: Optional[List[str]] = None,
        topics: Optional[List['DatabaseRegistrationTopicsItems']] = None,
    ) -> None:
        """
        Initialize a DatabaseRegistration object.

        :param DatabaseDetails database_details: database details.
        :param str database_display_name: Database display name.
        :param str database_type: Connector type.
        :param List[str] actions: (optional) actions.
        :param DatabaseCatalog associated_catalog: (optional) database catalog.
        :param str catalog_name: (optional) Catalog name.
        :param str created_by: (optional) Created by.
        :param str created_on: (optional) Created on.
        :param str database_id: (optional) Database ID.
        :param List[DatabaseRegistrationDatabasePropertiesItems]
               database_properties: (optional) This will hold all the properties for a
               custom database.
        :param List[DatabaseRegistrationPatchTablesItems] tables: (optional) List
               of tables.
        :param str description: (optional) Database description.
        :param List[str] tags: (optional) tags.
        :param List[DatabaseRegistrationTopicsItems] topics: (optional) List of
               topics.
        """
        self.actions = actions
        self.associated_catalog = associated_catalog
        self.catalog_name = catalog_name
        self.created_by = created_by
        self.created_on = created_on
        self.database_details = database_details
        self.database_display_name = database_display_name
        self.database_id = database_id
        self.database_properties = database_properties
        self.database_type = database_type
        self.tables = tables
        self.description = description
        self.tags = tags
        self.topics = topics

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'DatabaseRegistration':
        """Initialize a DatabaseRegistration object from a json dictionary."""
        args = {}
        if (actions := _dict.get('actions')) is not None:
            args['actions'] = actions
        if (associated_catalog := _dict.get('associated_catalog')) is not None:
            args['associated_catalog'] = DatabaseCatalog.from_dict(associated_catalog)
        if (catalog_name := _dict.get('catalog_name')) is not None:
            args['catalog_name'] = catalog_name
        if (created_by := _dict.get('created_by')) is not None:
            args['created_by'] = created_by
        if (created_on := _dict.get('created_on')) is not None:
            args['created_on'] = created_on
        if (database_details := _dict.get('database_details')) is not None:
            args['database_details'] = DatabaseDetails.from_dict(database_details)
        else:
            raise ValueError('Required property \'database_details\' not present in DatabaseRegistration JSON')
        if (database_display_name := _dict.get('database_display_name')) is not None:
            args['database_display_name'] = database_display_name
        else:
            raise ValueError('Required property \'database_display_name\' not present in DatabaseRegistration JSON')
        if (database_id := _dict.get('database_id')) is not None:
            args['database_id'] = database_id
        if (database_properties := _dict.get('database_properties')) is not None:
            args['database_properties'] = [DatabaseRegistrationDatabasePropertiesItems.from_dict(v) for v in database_properties]
        if (database_type := _dict.get('database_type')) is not None:
            args['database_type'] = database_type
        else:
            raise ValueError('Required property \'database_type\' not present in DatabaseRegistration JSON')
        if (tables := _dict.get('tables')) is not None:
            args['tables'] = [DatabaseRegistrationPatchTablesItems.from_dict(v) for v in tables]
        if (description := _dict.get('description')) is not None:
            args['description'] = description
        if (tags := _dict.get('tags')) is not None:
            args['tags'] = tags
        if (topics := _dict.get('topics')) is not None:
            args['topics'] = [DatabaseRegistrationTopicsItems.from_dict(v) for v in topics]
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
        if hasattr(self, 'associated_catalog') and self.associated_catalog is not None:
            if isinstance(self.associated_catalog, dict):
                _dict['associated_catalog'] = self.associated_catalog
            else:
                _dict['associated_catalog'] = self.associated_catalog.to_dict()
        if hasattr(self, 'catalog_name') and self.catalog_name is not None:
            _dict['catalog_name'] = self.catalog_name
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
            database_properties_list = []
            for v in self.database_properties:
                if isinstance(v, dict):
                    database_properties_list.append(v)
                else:
                    database_properties_list.append(v.to_dict())
            _dict['database_properties'] = database_properties_list
        if hasattr(self, 'database_type') and self.database_type is not None:
            _dict['database_type'] = self.database_type
        if hasattr(self, 'tables') and self.tables is not None:
            tables_list = []
            for v in self.tables:
                if isinstance(v, dict):
                    tables_list.append(v)
                else:
                    tables_list.append(v.to_dict())
            _dict['tables'] = tables_list
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'tags') and self.tags is not None:
            _dict['tags'] = self.tags
        if hasattr(self, 'topics') and self.topics is not None:
            topics_list = []
            for v in self.topics:
                if isinstance(v, dict):
                    topics_list.append(v)
                else:
                    topics_list.append(v.to_dict())
            _dict['topics'] = topics_list
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


class DatabaseRegistrationCollection:
    """
    list database registrations.

    :param List[DatabaseRegistration] database_registrations: (optional) Database
          body.
    """

    def __init__(
        self,
        *,
        database_registrations: Optional[List['DatabaseRegistration']] = None,
    ) -> None:
        """
        Initialize a DatabaseRegistrationCollection object.

        :param List[DatabaseRegistration] database_registrations: (optional)
               Database body.
        """
        self.database_registrations = database_registrations

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'DatabaseRegistrationCollection':
        """Initialize a DatabaseRegistrationCollection object from a json dictionary."""
        args = {}
        if (database_registrations := _dict.get('database_registrations')) is not None:
            args['database_registrations'] = [DatabaseRegistration.from_dict(v) for v in database_registrations]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a DatabaseRegistrationCollection object from a json dictionary."""
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
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this DatabaseRegistrationCollection object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'DatabaseRegistrationCollection') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'DatabaseRegistrationCollection') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class DatabaseRegistrationDatabasePropertiesItems:
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
        Initialize a DatabaseRegistrationDatabasePropertiesItems object.

        :param bool encrypt: Wether the value is to be encrypted before storing.
        :param str key: Key of the database property.
        :param str value: Value of the database property.
        """
        self.encrypt = encrypt
        self.key = key
        self.value = value

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'DatabaseRegistrationDatabasePropertiesItems':
        """Initialize a DatabaseRegistrationDatabasePropertiesItems object from a json dictionary."""
        args = {}
        if (encrypt := _dict.get('encrypt')) is not None:
            args['encrypt'] = encrypt
        else:
            raise ValueError('Required property \'encrypt\' not present in DatabaseRegistrationDatabasePropertiesItems JSON')
        if (key := _dict.get('key')) is not None:
            args['key'] = key
        else:
            raise ValueError('Required property \'key\' not present in DatabaseRegistrationDatabasePropertiesItems JSON')
        if (value := _dict.get('value')) is not None:
            args['value'] = value
        else:
            raise ValueError('Required property \'value\' not present in DatabaseRegistrationDatabasePropertiesItems JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a DatabaseRegistrationDatabasePropertiesItems object from a json dictionary."""
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
        """Return a `str` version of this DatabaseRegistrationDatabasePropertiesItems object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'DatabaseRegistrationDatabasePropertiesItems') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'DatabaseRegistrationDatabasePropertiesItems') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class DatabaseRegistrationPatch:
    """
    update db body.

    :param DatabaseRegistrationPatchDatabaseDetails database_details: (optional) New
          database details.
    :param str database_display_name: (optional) New database display name.
    :param str description: (optional) New database description.
    :param List[DatabaseRegistrationPatchTablesItems] tables: (optional) List of
          tables.
    :param List[str] tags: (optional) New tags.
    :param List[DatabaseRegistrationPatchDatabaseDetailsDatabasePropertiesItems]
          database_properties: (optional) This will hold all the properties for a custom
          database.
    :param List[DatabaseRegistrationPatchTopicsItems] topics: (optional) List of
          topics.
    """

    def __init__(
        self,
        *,
        database_details: Optional['DatabaseRegistrationPatchDatabaseDetails'] = None,
        database_display_name: Optional[str] = None,
        description: Optional[str] = None,
        tables: Optional[List['DatabaseRegistrationPatchTablesItems']] = None,
        tags: Optional[List[str]] = None,
        database_properties: Optional[List['DatabaseRegistrationPatchDatabaseDetailsDatabasePropertiesItems']] = None,
        topics: Optional[List['DatabaseRegistrationPatchTopicsItems']] = None,
    ) -> None:
        """
        Initialize a DatabaseRegistrationPatch object.

        :param DatabaseRegistrationPatchDatabaseDetails database_details:
               (optional) New database details.
        :param str database_display_name: (optional) New database display name.
        :param str description: (optional) New database description.
        :param List[DatabaseRegistrationPatchTablesItems] tables: (optional) List
               of tables.
        :param List[str] tags: (optional) New tags.
        :param
               List[DatabaseRegistrationPatchDatabaseDetailsDatabasePropertiesItems]
               database_properties: (optional) This will hold all the properties for a
               custom database.
        :param List[DatabaseRegistrationPatchTopicsItems] topics: (optional) List
               of topics.
        """
        self.database_details = database_details
        self.database_display_name = database_display_name
        self.description = description
        self.tables = tables
        self.tags = tags
        self.database_properties = database_properties
        self.topics = topics

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'DatabaseRegistrationPatch':
        """Initialize a DatabaseRegistrationPatch object from a json dictionary."""
        args = {}
        if (database_details := _dict.get('database_details')) is not None:
            args['database_details'] = DatabaseRegistrationPatchDatabaseDetails.from_dict(database_details)
        if (database_display_name := _dict.get('database_display_name')) is not None:
            args['database_display_name'] = database_display_name
        if (description := _dict.get('description')) is not None:
            args['description'] = description
        if (tables := _dict.get('tables')) is not None:
            args['tables'] = [DatabaseRegistrationPatchTablesItems.from_dict(v) for v in tables]
        if (tags := _dict.get('tags')) is not None:
            args['tags'] = tags
        if (database_properties := _dict.get('database_properties')) is not None:
            args['database_properties'] = [DatabaseRegistrationPatchDatabaseDetailsDatabasePropertiesItems.from_dict(v) for v in database_properties]
        if (topics := _dict.get('topics')) is not None:
            args['topics'] = [DatabaseRegistrationPatchTopicsItems.from_dict(v) for v in topics]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a DatabaseRegistrationPatch object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'database_details') and self.database_details is not None:
            if isinstance(self.database_details, dict):
                _dict['database_details'] = self.database_details
            else:
                _dict['database_details'] = self.database_details.to_dict()
        if hasattr(self, 'database_display_name') and self.database_display_name is not None:
            _dict['database_display_name'] = self.database_display_name
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'tables') and self.tables is not None:
            tables_list = []
            for v in self.tables:
                if isinstance(v, dict):
                    tables_list.append(v)
                else:
                    tables_list.append(v.to_dict())
            _dict['tables'] = tables_list
        if hasattr(self, 'tags') and self.tags is not None:
            _dict['tags'] = self.tags
        if hasattr(self, 'database_properties') and self.database_properties is not None:
            database_properties_list = []
            for v in self.database_properties:
                if isinstance(v, dict):
                    database_properties_list.append(v)
                else:
                    database_properties_list.append(v.to_dict())
            _dict['database_properties'] = database_properties_list
        if hasattr(self, 'topics') and self.topics is not None:
            topics_list = []
            for v in self.topics:
                if isinstance(v, dict):
                    topics_list.append(v)
                else:
                    topics_list.append(v.to_dict())
            _dict['topics'] = topics_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this DatabaseRegistrationPatch object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'DatabaseRegistrationPatch') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'DatabaseRegistrationPatch') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class DatabaseRegistrationPatchDatabaseDetails:
    """
    New database details.

    :param str authentication_value: (optional) Authentication method.
    :param str broker_authentication_password: (optional) Broker authentication
          password.
    :param str broker_authentication_type: (optional) Broker authentication type.
    :param str broker_authentication_user: (optional) Broker authentication user.
    :param str controller_authentication_password: (optional) Controller
          authentication password.
    :param str controller_authentication_type: (optional) Controller authentication
          type.
    :param str controller_authentication_user: (optional) Controller authentication
          user.
    :param str credentials_key: (optional) Base 64 encoded json file.
    :param List[DatabaseRegistrationPatchDatabaseDetailsDatabasePropertiesItems]
          database_properties: (optional) This will hold all the properties for a custom
          database.
    :param str password: (optional) New password.
    :param str username: (optional) New username.
    """

    def __init__(
        self,
        *,
        authentication_value: Optional[str] = None,
        broker_authentication_password: Optional[str] = None,
        broker_authentication_type: Optional[str] = None,
        broker_authentication_user: Optional[str] = None,
        controller_authentication_password: Optional[str] = None,
        controller_authentication_type: Optional[str] = None,
        controller_authentication_user: Optional[str] = None,
        credentials_key: Optional[str] = None,
        database_properties: Optional[List['DatabaseRegistrationPatchDatabaseDetailsDatabasePropertiesItems']] = None,
        password: Optional[str] = None,
        username: Optional[str] = None,
    ) -> None:
        """
        Initialize a DatabaseRegistrationPatchDatabaseDetails object.

        :param str authentication_value: (optional) Authentication method.
        :param str broker_authentication_password: (optional) Broker authentication
               password.
        :param str broker_authentication_type: (optional) Broker authentication
               type.
        :param str broker_authentication_user: (optional) Broker authentication
               user.
        :param str controller_authentication_password: (optional) Controller
               authentication password.
        :param str controller_authentication_type: (optional) Controller
               authentication type.
        :param str controller_authentication_user: (optional) Controller
               authentication user.
        :param str credentials_key: (optional) Base 64 encoded json file.
        :param
               List[DatabaseRegistrationPatchDatabaseDetailsDatabasePropertiesItems]
               database_properties: (optional) This will hold all the properties for a
               custom database.
        :param str password: (optional) New password.
        :param str username: (optional) New username.
        """
        self.authentication_value = authentication_value
        self.broker_authentication_password = broker_authentication_password
        self.broker_authentication_type = broker_authentication_type
        self.broker_authentication_user = broker_authentication_user
        self.controller_authentication_password = controller_authentication_password
        self.controller_authentication_type = controller_authentication_type
        self.controller_authentication_user = controller_authentication_user
        self.credentials_key = credentials_key
        self.database_properties = database_properties
        self.password = password
        self.username = username

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'DatabaseRegistrationPatchDatabaseDetails':
        """Initialize a DatabaseRegistrationPatchDatabaseDetails object from a json dictionary."""
        args = {}
        if (authentication_value := _dict.get('authentication_value')) is not None:
            args['authentication_value'] = authentication_value
        if (broker_authentication_password := _dict.get('broker_authentication_password')) is not None:
            args['broker_authentication_password'] = broker_authentication_password
        if (broker_authentication_type := _dict.get('broker_authentication_type')) is not None:
            args['broker_authentication_type'] = broker_authentication_type
        if (broker_authentication_user := _dict.get('broker_authentication_user')) is not None:
            args['broker_authentication_user'] = broker_authentication_user
        if (controller_authentication_password := _dict.get('controller_authentication_password')) is not None:
            args['controller_authentication_password'] = controller_authentication_password
        if (controller_authentication_type := _dict.get('controller_authentication_type')) is not None:
            args['controller_authentication_type'] = controller_authentication_type
        if (controller_authentication_user := _dict.get('controller_authentication_user')) is not None:
            args['controller_authentication_user'] = controller_authentication_user
        if (credentials_key := _dict.get('credentials_key')) is not None:
            args['credentials_key'] = credentials_key
        if (database_properties := _dict.get('database_properties')) is not None:
            args['database_properties'] = [DatabaseRegistrationPatchDatabaseDetailsDatabasePropertiesItems.from_dict(v) for v in database_properties]
        if (password := _dict.get('password')) is not None:
            args['password'] = password
        if (username := _dict.get('username')) is not None:
            args['username'] = username
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a DatabaseRegistrationPatchDatabaseDetails object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'authentication_value') and self.authentication_value is not None:
            _dict['authentication_value'] = self.authentication_value
        if hasattr(self, 'broker_authentication_password') and self.broker_authentication_password is not None:
            _dict['broker_authentication_password'] = self.broker_authentication_password
        if hasattr(self, 'broker_authentication_type') and self.broker_authentication_type is not None:
            _dict['broker_authentication_type'] = self.broker_authentication_type
        if hasattr(self, 'broker_authentication_user') and self.broker_authentication_user is not None:
            _dict['broker_authentication_user'] = self.broker_authentication_user
        if hasattr(self, 'controller_authentication_password') and self.controller_authentication_password is not None:
            _dict['controller_authentication_password'] = self.controller_authentication_password
        if hasattr(self, 'controller_authentication_type') and self.controller_authentication_type is not None:
            _dict['controller_authentication_type'] = self.controller_authentication_type
        if hasattr(self, 'controller_authentication_user') and self.controller_authentication_user is not None:
            _dict['controller_authentication_user'] = self.controller_authentication_user
        if hasattr(self, 'credentials_key') and self.credentials_key is not None:
            _dict['credentials_key'] = self.credentials_key
        if hasattr(self, 'database_properties') and self.database_properties is not None:
            database_properties_list = []
            for v in self.database_properties:
                if isinstance(v, dict):
                    database_properties_list.append(v)
                else:
                    database_properties_list.append(v.to_dict())
            _dict['database_properties'] = database_properties_list
        if hasattr(self, 'password') and self.password is not None:
            _dict['password'] = self.password
        if hasattr(self, 'username') and self.username is not None:
            _dict['username'] = self.username
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this DatabaseRegistrationPatchDatabaseDetails object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'DatabaseRegistrationPatchDatabaseDetails') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'DatabaseRegistrationPatchDatabaseDetails') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class DatabaseRegistrationPatchDatabaseDetailsDatabasePropertiesItems:
    """
    Key value object.

    :param bool encrypt: Indicates if the value must be encrypted before storing.
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
        Initialize a DatabaseRegistrationPatchDatabaseDetailsDatabasePropertiesItems object.

        :param bool encrypt: Indicates if the value must be encrypted before
               storing.
        :param str key: Key of the database property.
        :param str value: Value of the database property.
        """
        self.encrypt = encrypt
        self.key = key
        self.value = value

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'DatabaseRegistrationPatchDatabaseDetailsDatabasePropertiesItems':
        """Initialize a DatabaseRegistrationPatchDatabaseDetailsDatabasePropertiesItems object from a json dictionary."""
        args = {}
        if (encrypt := _dict.get('encrypt')) is not None:
            args['encrypt'] = encrypt
        else:
            raise ValueError('Required property \'encrypt\' not present in DatabaseRegistrationPatchDatabaseDetailsDatabasePropertiesItems JSON')
        if (key := _dict.get('key')) is not None:
            args['key'] = key
        else:
            raise ValueError('Required property \'key\' not present in DatabaseRegistrationPatchDatabaseDetailsDatabasePropertiesItems JSON')
        if (value := _dict.get('value')) is not None:
            args['value'] = value
        else:
            raise ValueError('Required property \'value\' not present in DatabaseRegistrationPatchDatabaseDetailsDatabasePropertiesItems JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a DatabaseRegistrationPatchDatabaseDetailsDatabasePropertiesItems object from a json dictionary."""
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
        """Return a `str` version of this DatabaseRegistrationPatchDatabaseDetailsDatabasePropertiesItems object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'DatabaseRegistrationPatchDatabaseDetailsDatabasePropertiesItems') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'DatabaseRegistrationPatchDatabaseDetailsDatabasePropertiesItems') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class DatabaseRegistrationPatchTablesItems:
    """
    Table.

    :param str created_on: (optional) Created on.
    :param str file_contents: (optional) file content.
    :param str file_name: (optional) file name.
    :param str schema_name: (optional) schema name.
    :param str table_name: (optional) table name.
    """

    def __init__(
        self,
        *,
        created_on: Optional[str] = None,
        file_contents: Optional[str] = None,
        file_name: Optional[str] = None,
        schema_name: Optional[str] = None,
        table_name: Optional[str] = None,
    ) -> None:
        """
        Initialize a DatabaseRegistrationPatchTablesItems object.

        :param str created_on: (optional) Created on.
        :param str file_contents: (optional) file content.
        :param str file_name: (optional) file name.
        :param str schema_name: (optional) schema name.
        :param str table_name: (optional) table name.
        """
        self.created_on = created_on
        self.file_contents = file_contents
        self.file_name = file_name
        self.schema_name = schema_name
        self.table_name = table_name

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'DatabaseRegistrationPatchTablesItems':
        """Initialize a DatabaseRegistrationPatchTablesItems object from a json dictionary."""
        args = {}
        if (created_on := _dict.get('created_on')) is not None:
            args['created_on'] = created_on
        if (file_contents := _dict.get('file_contents')) is not None:
            args['file_contents'] = file_contents
        if (file_name := _dict.get('file_name')) is not None:
            args['file_name'] = file_name
        if (schema_name := _dict.get('schema_name')) is not None:
            args['schema_name'] = schema_name
        if (table_name := _dict.get('table_name')) is not None:
            args['table_name'] = table_name
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a DatabaseRegistrationPatchTablesItems object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'created_on') and self.created_on is not None:
            _dict['created_on'] = self.created_on
        if hasattr(self, 'file_contents') and self.file_contents is not None:
            _dict['file_contents'] = self.file_contents
        if hasattr(self, 'file_name') and self.file_name is not None:
            _dict['file_name'] = self.file_name
        if hasattr(self, 'schema_name') and self.schema_name is not None:
            _dict['schema_name'] = self.schema_name
        if hasattr(self, 'table_name') and self.table_name is not None:
            _dict['table_name'] = self.table_name
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this DatabaseRegistrationPatchTablesItems object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'DatabaseRegistrationPatchTablesItems') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'DatabaseRegistrationPatchTablesItems') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class DatabaseRegistrationPatchTopicsItems:
    """
    Topic.

    :param str created_on: (optional) Created on.
    :param str file_contents: (optional) file contents.
    :param str file_name: (optional) file name.
    :param str topic_name: (optional) topic name.
    """

    def __init__(
        self,
        *,
        created_on: Optional[str] = None,
        file_contents: Optional[str] = None,
        file_name: Optional[str] = None,
        topic_name: Optional[str] = None,
    ) -> None:
        """
        Initialize a DatabaseRegistrationPatchTopicsItems object.

        :param str created_on: (optional) Created on.
        :param str file_contents: (optional) file contents.
        :param str file_name: (optional) file name.
        :param str topic_name: (optional) topic name.
        """
        self.created_on = created_on
        self.file_contents = file_contents
        self.file_name = file_name
        self.topic_name = topic_name

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'DatabaseRegistrationPatchTopicsItems':
        """Initialize a DatabaseRegistrationPatchTopicsItems object from a json dictionary."""
        args = {}
        if (created_on := _dict.get('created_on')) is not None:
            args['created_on'] = created_on
        if (file_contents := _dict.get('file_contents')) is not None:
            args['file_contents'] = file_contents
        if (file_name := _dict.get('file_name')) is not None:
            args['file_name'] = file_name
        if (topic_name := _dict.get('topic_name')) is not None:
            args['topic_name'] = topic_name
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a DatabaseRegistrationPatchTopicsItems object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'created_on') and self.created_on is not None:
            _dict['created_on'] = self.created_on
        if hasattr(self, 'file_contents') and self.file_contents is not None:
            _dict['file_contents'] = self.file_contents
        if hasattr(self, 'file_name') and self.file_name is not None:
            _dict['file_name'] = self.file_name
        if hasattr(self, 'topic_name') and self.topic_name is not None:
            _dict['topic_name'] = self.topic_name
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this DatabaseRegistrationPatchTopicsItems object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'DatabaseRegistrationPatchTopicsItems') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'DatabaseRegistrationPatchTopicsItems') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class DatabaseRegistrationPrototypeDatabasePropertiesItems:
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
        Initialize a DatabaseRegistrationPrototypeDatabasePropertiesItems object.

        :param bool encrypt: Wether the value is to be encrypted before storing.
        :param str key: Key of the database property.
        :param str value: Value of the database property.
        """
        self.encrypt = encrypt
        self.key = key
        self.value = value

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'DatabaseRegistrationPrototypeDatabasePropertiesItems':
        """Initialize a DatabaseRegistrationPrototypeDatabasePropertiesItems object from a json dictionary."""
        args = {}
        if (encrypt := _dict.get('encrypt')) is not None:
            args['encrypt'] = encrypt
        else:
            raise ValueError('Required property \'encrypt\' not present in DatabaseRegistrationPrototypeDatabasePropertiesItems JSON')
        if (key := _dict.get('key')) is not None:
            args['key'] = key
        else:
            raise ValueError('Required property \'key\' not present in DatabaseRegistrationPrototypeDatabasePropertiesItems JSON')
        if (value := _dict.get('value')) is not None:
            args['value'] = value
        else:
            raise ValueError('Required property \'value\' not present in DatabaseRegistrationPrototypeDatabasePropertiesItems JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a DatabaseRegistrationPrototypeDatabasePropertiesItems object from a json dictionary."""
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
        """Return a `str` version of this DatabaseRegistrationPrototypeDatabasePropertiesItems object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'DatabaseRegistrationPrototypeDatabasePropertiesItems') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'DatabaseRegistrationPrototypeDatabasePropertiesItems') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class DatabaseRegistrationTopicsItems:
    """
    Topic.

    :param str created_on: (optional) Created on.
    :param str file_contents: (optional) file content.
    :param str file_name: (optional) file name.
    :param str topic_name: (optional) topic name.
    """

    def __init__(
        self,
        *,
        created_on: Optional[str] = None,
        file_contents: Optional[str] = None,
        file_name: Optional[str] = None,
        topic_name: Optional[str] = None,
    ) -> None:
        """
        Initialize a DatabaseRegistrationTopicsItems object.

        :param str created_on: (optional) Created on.
        :param str file_contents: (optional) file content.
        :param str file_name: (optional) file name.
        :param str topic_name: (optional) topic name.
        """
        self.created_on = created_on
        self.file_contents = file_contents
        self.file_name = file_name
        self.topic_name = topic_name

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'DatabaseRegistrationTopicsItems':
        """Initialize a DatabaseRegistrationTopicsItems object from a json dictionary."""
        args = {}
        if (created_on := _dict.get('created_on')) is not None:
            args['created_on'] = created_on
        if (file_contents := _dict.get('file_contents')) is not None:
            args['file_contents'] = file_contents
        if (file_name := _dict.get('file_name')) is not None:
            args['file_name'] = file_name
        if (topic_name := _dict.get('topic_name')) is not None:
            args['topic_name'] = topic_name
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a DatabaseRegistrationTopicsItems object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'created_on') and self.created_on is not None:
            _dict['created_on'] = self.created_on
        if hasattr(self, 'file_contents') and self.file_contents is not None:
            _dict['file_contents'] = self.file_contents
        if hasattr(self, 'file_name') and self.file_name is not None:
            _dict['file_name'] = self.file_name
        if hasattr(self, 'topic_name') and self.topic_name is not None:
            _dict['topic_name'] = self.topic_name
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this DatabaseRegistrationTopicsItems object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'DatabaseRegistrationTopicsItems') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'DatabaseRegistrationTopicsItems') -> bool:
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
        if (actions := _dict.get('actions')) is not None:
            args['actions'] = actions
        if (build_version := _dict.get('build_version')) is not None:
            args['build_version'] = build_version
        if (created_by := _dict.get('created_by')) is not None:
            args['created_by'] = created_by
        if (created_on := _dict.get('created_on')) is not None:
            args['created_on'] = created_on
        if (description := _dict.get('description')) is not None:
            args['description'] = description
        if (engine_details := _dict.get('engine_details')) is not None:
            args['engine_details'] = Db2EngineDetails.from_dict(engine_details)
        if (engine_display_name := _dict.get('engine_display_name')) is not None:
            args['engine_display_name'] = engine_display_name
        if (engine_id := _dict.get('engine_id')) is not None:
            args['engine_id'] = engine_id
        if (host_name := _dict.get('host_name')) is not None:
            args['host_name'] = host_name
        if (origin := _dict.get('origin')) is not None:
            args['origin'] = origin
        if (port := _dict.get('port')) is not None:
            args['port'] = port
        if (status := _dict.get('status')) is not None:
            args['status'] = status
        if (tags := _dict.get('tags')) is not None:
            args['tags'] = tags
        if (type := _dict.get('type')) is not None:
            args['type'] = type
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


class Db2EngineCollection:
    """
    list db2 engines.

    :param List[Db2Engine] db2_engines: (optional) list db2 engines.
    """

    def __init__(
        self,
        *,
        db2_engines: Optional[List['Db2Engine']] = None,
    ) -> None:
        """
        Initialize a Db2EngineCollection object.

        :param List[Db2Engine] db2_engines: (optional) list db2 engines.
        """
        self.db2_engines = db2_engines

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'Db2EngineCollection':
        """Initialize a Db2EngineCollection object from a json dictionary."""
        args = {}
        if (db2_engines := _dict.get('db2_engines')) is not None:
            args['db2_engines'] = [Db2Engine.from_dict(v) for v in db2_engines]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a Db2EngineCollection object from a json dictionary."""
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
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this Db2EngineCollection object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'Db2EngineCollection') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'Db2EngineCollection') -> bool:
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
        if (connection_string := _dict.get('connection_string')) is not None:
            args['connection_string'] = connection_string
        if (metastore_host := _dict.get('metastore_host')) is not None:
            args['metastore_host'] = metastore_host
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


class Db2EngineDetailsBody:
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
        Initialize a Db2EngineDetailsBody object.

        :param str connection_string: (optional) External engine connection string.
        """
        self.connection_string = connection_string

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'Db2EngineDetailsBody':
        """Initialize a Db2EngineDetailsBody object from a json dictionary."""
        args = {}
        if (connection_string := _dict.get('connection_string')) is not None:
            args['connection_string'] = connection_string
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a Db2EngineDetailsBody object from a json dictionary."""
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
        """Return a `str` version of this Db2EngineDetailsBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'Db2EngineDetailsBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'Db2EngineDetailsBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class Db2EnginePatch:
    """
    UpdateEngine body.

    :param str description: (optional) Modified description.
    :param str engine_display_name: (optional) Engine display name.
    :param List[str] tags: (optional) Tags.
    """

    def __init__(
        self,
        *,
        description: Optional[str] = None,
        engine_display_name: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a Db2EnginePatch object.

        :param str description: (optional) Modified description.
        :param str engine_display_name: (optional) Engine display name.
        :param List[str] tags: (optional) Tags.
        """
        self.description = description
        self.engine_display_name = engine_display_name
        self.tags = tags

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'Db2EnginePatch':
        """Initialize a Db2EnginePatch object from a json dictionary."""
        args = {}
        if (description := _dict.get('description')) is not None:
            args['description'] = description
        if (engine_display_name := _dict.get('engine_display_name')) is not None:
            args['engine_display_name'] = engine_display_name
        if (tags := _dict.get('tags')) is not None:
            args['tags'] = tags
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a Db2EnginePatch object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'engine_display_name') and self.engine_display_name is not None:
            _dict['engine_display_name'] = self.engine_display_name
        if hasattr(self, 'tags') and self.tags is not None:
            _dict['tags'] = self.tags
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this Db2EnginePatch object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'Db2EnginePatch') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'Db2EnginePatch') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class DisplayNameInfoResponse:
    """
    DisplayNameInfoResponse.

    :param str display_name: Display name.
    """

    def __init__(
        self,
        display_name: str,
    ) -> None:
        """
        Initialize a DisplayNameInfoResponse object.

        :param str display_name: Display name.
        """
        self.display_name = display_name

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'DisplayNameInfoResponse':
        """Initialize a DisplayNameInfoResponse object from a json dictionary."""
        args = {}
        if (display_name := _dict.get('display_name')) is not None:
            args['display_name'] = display_name
        else:
            raise ValueError('Required property \'display_name\' not present in DisplayNameInfoResponse JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a DisplayNameInfoResponse object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'display_name') and self.display_name is not None:
            _dict['display_name'] = self.display_name
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this DisplayNameInfoResponse object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'DisplayNameInfoResponse') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'DisplayNameInfoResponse') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class Driver:
    """
    Driver.

    :param str connection_type: (optional) Connection type.
    :param str driver_id: (optional) Driver name.
    :param str driver_name: (optional) Driver name.
    :param str driver_version: (optional) Driver version.
    """

    def __init__(
        self,
        *,
        connection_type: Optional[str] = None,
        driver_id: Optional[str] = None,
        driver_name: Optional[str] = None,
        driver_version: Optional[str] = None,
    ) -> None:
        """
        Initialize a Driver object.

        :param str connection_type: (optional) Connection type.
        :param str driver_id: (optional) Driver name.
        :param str driver_name: (optional) Driver name.
        :param str driver_version: (optional) Driver version.
        """
        self.connection_type = connection_type
        self.driver_id = driver_id
        self.driver_name = driver_name
        self.driver_version = driver_version

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'Driver':
        """Initialize a Driver object from a json dictionary."""
        args = {}
        if (connection_type := _dict.get('connection_type')) is not None:
            args['connection_type'] = connection_type
        if (driver_id := _dict.get('driver_id')) is not None:
            args['driver_id'] = driver_id
        if (driver_name := _dict.get('driver_name')) is not None:
            args['driver_name'] = driver_name
        if (driver_version := _dict.get('driver_version')) is not None:
            args['driver_version'] = driver_version
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a Driver object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'connection_type') and self.connection_type is not None:
            _dict['connection_type'] = self.connection_type
        if hasattr(self, 'driver_id') and self.driver_id is not None:
            _dict['driver_id'] = self.driver_id
        if hasattr(self, 'driver_name') and self.driver_name is not None:
            _dict['driver_name'] = self.driver_name
        if hasattr(self, 'driver_version') and self.driver_version is not None:
            _dict['driver_version'] = self.driver_version
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this Driver object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'Driver') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'Driver') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class Endpoint:
    """
    The service endpoint.

    :param str external_host: (optional) The external host of the service.
    :param str service_type: (optional) The service type.
    """

    def __init__(
        self,
        *,
        external_host: Optional[str] = None,
        service_type: Optional[str] = None,
    ) -> None:
        """
        Initialize a Endpoint object.

        :param str external_host: (optional) The external host of the service.
        :param str service_type: (optional) The service type.
        """
        self.external_host = external_host
        self.service_type = service_type

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'Endpoint':
        """Initialize a Endpoint object from a json dictionary."""
        args = {}
        if (external_host := _dict.get('external_host')) is not None:
            args['external_host'] = external_host
        if (service_type := _dict.get('service_type')) is not None:
            args['service_type'] = service_type
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a Endpoint object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'external_host') and self.external_host is not None:
            _dict['external_host'] = self.external_host
        if hasattr(self, 'service_type') and self.service_type is not None:
            _dict['service_type'] = self.service_type
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this Endpoint object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'Endpoint') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'Endpoint') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class EndpointCollection:
    """
    List endpoints.

    :param List[Endpoint] endpoints: (optional) List of the endpoints CPG and CAS.
    """

    def __init__(
        self,
        *,
        endpoints: Optional[List['Endpoint']] = None,
    ) -> None:
        """
        Initialize a EndpointCollection object.

        :param List[Endpoint] endpoints: (optional) List of the endpoints CPG and
               CAS.
        """
        self.endpoints = endpoints

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'EndpointCollection':
        """Initialize a EndpointCollection object from a json dictionary."""
        args = {}
        if (endpoints := _dict.get('endpoints')) is not None:
            args['endpoints'] = [Endpoint.from_dict(v) for v in endpoints]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a EndpointCollection object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'endpoints') and self.endpoints is not None:
            endpoints_list = []
            for v in self.endpoints:
                if isinstance(v, dict):
                    endpoints_list.append(v)
                else:
                    endpoints_list.append(v.to_dict())
            _dict['endpoints'] = endpoints_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this EndpointCollection object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'EndpointCollection') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'EndpointCollection') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class EngineDetailsBody:
    """
    Node details.

    :param str api_key: (optional) api key to work with the saas IAE instance.
    :param str connection_string: (optional) External engine connection string.
    :param NodeDescriptionBody coordinator: (optional) Coordinator/ worker
          properties.
    :param str instance_id: (optional) Instance to access the instance.
    :param str managed_by: (optional) How is the spark instance managed.
    :param str size_config: (optional) Size config.
    :param NodeDescriptionBody worker: (optional) Coordinator/ worker properties.
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
        :param NodeDescriptionBody coordinator: (optional) Coordinator/ worker
               properties.
        :param str instance_id: (optional) Instance to access the instance.
        :param str managed_by: (optional) How is the spark instance managed.
        :param str size_config: (optional) Size config.
        :param NodeDescriptionBody worker: (optional) Coordinator/ worker
               properties.
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
        if (api_key := _dict.get('api_key')) is not None:
            args['api_key'] = api_key
        if (connection_string := _dict.get('connection_string')) is not None:
            args['connection_string'] = connection_string
        if (coordinator := _dict.get('coordinator')) is not None:
            args['coordinator'] = NodeDescriptionBody.from_dict(coordinator)
        if (instance_id := _dict.get('instance_id')) is not None:
            args['instance_id'] = instance_id
        if (managed_by := _dict.get('managed_by')) is not None:
            args['managed_by'] = managed_by
        if (size_config := _dict.get('size_config')) is not None:
            args['size_config'] = size_config
        if (worker := _dict.get('worker')) is not None:
            args['worker'] = NodeDescriptionBody.from_dict(worker)
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



class EnginePropertiesLogConfiguration:
    """
    Log Configuration settings.

    :param NodeDescriptionBody coordinator: (optional) Coordinator/ worker
          properties.
    :param NodeDescriptionBody worker: (optional) Coordinator/ worker properties.
    """

    def __init__(
        self,
        *,
        coordinator: Optional['NodeDescriptionBody'] = None,
        worker: Optional['NodeDescriptionBody'] = None,
    ) -> None:
        """
        Initialize a EnginePropertiesLogConfiguration object.

        :param NodeDescriptionBody coordinator: (optional) Coordinator/ worker
               properties.
        :param NodeDescriptionBody worker: (optional) Coordinator/ worker
               properties.
        """
        self.coordinator = coordinator
        self.worker = worker

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'EnginePropertiesLogConfiguration':
        """Initialize a EnginePropertiesLogConfiguration object from a json dictionary."""
        args = {}
        if (coordinator := _dict.get('coordinator')) is not None:
            args['coordinator'] = NodeDescriptionBody.from_dict(coordinator)
        if (worker := _dict.get('worker')) is not None:
            args['worker'] = NodeDescriptionBody.from_dict(worker)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a EnginePropertiesLogConfiguration object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'coordinator') and self.coordinator is not None:
            if isinstance(self.coordinator, dict):
                _dict['coordinator'] = self.coordinator
            else:
                _dict['coordinator'] = self.coordinator.to_dict()
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
        """Return a `str` version of this EnginePropertiesLogConfiguration object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'EnginePropertiesLogConfiguration') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'EnginePropertiesLogConfiguration') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class EnginePropertiesOaiGen1Configuration:
    """
    Configuration settings.

    :param NodeDescriptionBody coordinator: (optional) Coordinator/ worker
          properties.
    :param NodeDescriptionBody worker: (optional) Coordinator/ worker properties.
    """

    def __init__(
        self,
        *,
        coordinator: Optional['NodeDescriptionBody'] = None,
        worker: Optional['NodeDescriptionBody'] = None,
    ) -> None:
        """
        Initialize a EnginePropertiesOaiGen1Configuration object.

        :param NodeDescriptionBody coordinator: (optional) Coordinator/ worker
               properties.
        :param NodeDescriptionBody worker: (optional) Coordinator/ worker
               properties.
        """
        self.coordinator = coordinator
        self.worker = worker

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'EnginePropertiesOaiGen1Configuration':
        """Initialize a EnginePropertiesOaiGen1Configuration object from a json dictionary."""
        args = {}
        if (coordinator := _dict.get('coordinator')) is not None:
            args['coordinator'] = NodeDescriptionBody.from_dict(coordinator)
        if (worker := _dict.get('worker')) is not None:
            args['worker'] = NodeDescriptionBody.from_dict(worker)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a EnginePropertiesOaiGen1Configuration object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'coordinator') and self.coordinator is not None:
            if isinstance(self.coordinator, dict):
                _dict['coordinator'] = self.coordinator
            else:
                _dict['coordinator'] = self.coordinator.to_dict()
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
        """Return a `str` version of this EnginePropertiesOaiGen1Configuration object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'EnginePropertiesOaiGen1Configuration') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'EnginePropertiesOaiGen1Configuration') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class EnginePropertiesOaiGen1Jvm:
    """
    JVM settings.

    :param NodeDescriptionBody coordinator: (optional) Coordinator/ worker
          properties.
    :param NodeDescriptionBody worker: (optional) Coordinator/ worker properties.
    """

    def __init__(
        self,
        *,
        coordinator: Optional['NodeDescriptionBody'] = None,
        worker: Optional['NodeDescriptionBody'] = None,
    ) -> None:
        """
        Initialize a EnginePropertiesOaiGen1Jvm object.

        :param NodeDescriptionBody coordinator: (optional) Coordinator/ worker
               properties.
        :param NodeDescriptionBody worker: (optional) Coordinator/ worker
               properties.
        """
        self.coordinator = coordinator
        self.worker = worker

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'EnginePropertiesOaiGen1Jvm':
        """Initialize a EnginePropertiesOaiGen1Jvm object from a json dictionary."""
        args = {}
        if (coordinator := _dict.get('coordinator')) is not None:
            args['coordinator'] = NodeDescriptionBody.from_dict(coordinator)
        if (worker := _dict.get('worker')) is not None:
            args['worker'] = NodeDescriptionBody.from_dict(worker)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a EnginePropertiesOaiGen1Jvm object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'coordinator') and self.coordinator is not None:
            if isinstance(self.coordinator, dict):
                _dict['coordinator'] = self.coordinator
            else:
                _dict['coordinator'] = self.coordinator.to_dict()
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
        """Return a `str` version of this EnginePropertiesOaiGen1Jvm object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'EnginePropertiesOaiGen1Jvm') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'EnginePropertiesOaiGen1Jvm') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class EnginePropertiesOaiGenConfiguration:
    """
    Configuration settings for the engine properties.

    :param PrestissimoNodeDescriptionBody coordinator: (optional) coordinator/worker
          property settings.
    :param PrestissimoNodeDescriptionBody worker: (optional) coordinator/worker
          property settings.
    """

    def __init__(
        self,
        *,
        coordinator: Optional['PrestissimoNodeDescriptionBody'] = None,
        worker: Optional['PrestissimoNodeDescriptionBody'] = None,
    ) -> None:
        """
        Initialize a EnginePropertiesOaiGenConfiguration object.

        :param PrestissimoNodeDescriptionBody coordinator: (optional)
               coordinator/worker property settings.
        :param PrestissimoNodeDescriptionBody worker: (optional) coordinator/worker
               property settings.
        """
        self.coordinator = coordinator
        self.worker = worker

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'EnginePropertiesOaiGenConfiguration':
        """Initialize a EnginePropertiesOaiGenConfiguration object from a json dictionary."""
        args = {}
        if (coordinator := _dict.get('coordinator')) is not None:
            args['coordinator'] = PrestissimoNodeDescriptionBody.from_dict(coordinator)
        if (worker := _dict.get('worker')) is not None:
            args['worker'] = PrestissimoNodeDescriptionBody.from_dict(worker)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a EnginePropertiesOaiGenConfiguration object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'coordinator') and self.coordinator is not None:
            if isinstance(self.coordinator, dict):
                _dict['coordinator'] = self.coordinator
            else:
                _dict['coordinator'] = self.coordinator.to_dict()
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
        """Return a `str` version of this EnginePropertiesOaiGenConfiguration object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'EnginePropertiesOaiGenConfiguration') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'EnginePropertiesOaiGenConfiguration') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class EnrichmentAsset:
    """
    Encrichment asset.

    :param List[str] asset_attributes: (optional) schema name.
    :param str asset_id: (optional) data asset id.
    :param str asset_name: (optional) asset name.
    :param str resource_key: (optional) resource name.
    :param str schema_name: (optional) schema.
    """

    def __init__(
        self,
        *,
        asset_attributes: Optional[List[str]] = None,
        asset_id: Optional[str] = None,
        asset_name: Optional[str] = None,
        resource_key: Optional[str] = None,
        schema_name: Optional[str] = None,
    ) -> None:
        """
        Initialize a EnrichmentAsset object.

        :param List[str] asset_attributes: (optional) schema name.
        :param str asset_id: (optional) data asset id.
        :param str asset_name: (optional) asset name.
        :param str resource_key: (optional) resource name.
        :param str schema_name: (optional) schema.
        """
        self.asset_attributes = asset_attributes
        self.asset_id = asset_id
        self.asset_name = asset_name
        self.resource_key = resource_key
        self.schema_name = schema_name

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'EnrichmentAsset':
        """Initialize a EnrichmentAsset object from a json dictionary."""
        args = {}
        if (asset_attributes := _dict.get('asset_attributes')) is not None:
            args['asset_attributes'] = asset_attributes
        if (asset_id := _dict.get('asset_id')) is not None:
            args['asset_id'] = asset_id
        if (asset_name := _dict.get('asset_name')) is not None:
            args['asset_name'] = asset_name
        if (resource_key := _dict.get('resource_key')) is not None:
            args['resource_key'] = resource_key
        if (schema_name := _dict.get('schema_name')) is not None:
            args['schema_name'] = schema_name
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a EnrichmentAsset object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'asset_attributes') and self.asset_attributes is not None:
            _dict['asset_attributes'] = self.asset_attributes
        if hasattr(self, 'asset_id') and self.asset_id is not None:
            _dict['asset_id'] = self.asset_id
        if hasattr(self, 'asset_name') and self.asset_name is not None:
            _dict['asset_name'] = self.asset_name
        if hasattr(self, 'resource_key') and self.resource_key is not None:
            _dict['resource_key'] = self.resource_key
        if hasattr(self, 'schema_name') and self.schema_name is not None:
            _dict['schema_name'] = self.schema_name
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this EnrichmentAsset object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'EnrichmentAsset') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'EnrichmentAsset') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class EnrichmentObj:
    """
    Encrichment api object.

    :param str catalog: catalog name.
    :param str operation: operation type.
    :param str schema: schema name.
    :param List[str] tables: (optional) schema name.
    """

    def __init__(
        self,
        catalog: str,
        operation: str,
        schema: str,
        *,
        tables: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a EnrichmentObj object.

        :param str catalog: catalog name.
        :param str operation: operation type.
        :param str schema: schema name.
        :param List[str] tables: (optional) schema name.
        """
        self.catalog = catalog
        self.operation = operation
        self.schema = schema
        self.tables = tables

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'EnrichmentObj':
        """Initialize a EnrichmentObj object from a json dictionary."""
        args = {}
        if (catalog := _dict.get('catalog')) is not None:
            args['catalog'] = catalog
        else:
            raise ValueError('Required property \'catalog\' not present in EnrichmentObj JSON')
        if (operation := _dict.get('operation')) is not None:
            args['operation'] = operation
        else:
            raise ValueError('Required property \'operation\' not present in EnrichmentObj JSON')
        if (schema := _dict.get('schema')) is not None:
            args['schema'] = schema
        else:
            raise ValueError('Required property \'schema\' not present in EnrichmentObj JSON')
        if (tables := _dict.get('tables')) is not None:
            args['tables'] = tables
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a EnrichmentObj object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'catalog') and self.catalog is not None:
            _dict['catalog'] = self.catalog
        if hasattr(self, 'operation') and self.operation is not None:
            _dict['operation'] = self.operation
        if hasattr(self, 'schema') and self.schema is not None:
            _dict['schema'] = self.schema
        if hasattr(self, 'tables') and self.tables is not None:
            _dict['tables'] = self.tables
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this EnrichmentObj object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'EnrichmentObj') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'EnrichmentObj') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ErrorObj:
    """
    integration error object.

    :param str code: (optional) error code.
    :param str message: (optional) error message.
    """

    def __init__(
        self,
        *,
        code: Optional[str] = None,
        message: Optional[str] = None,
    ) -> None:
        """
        Initialize a ErrorObj object.

        :param str code: (optional) error code.
        :param str message: (optional) error message.
        """
        self.code = code
        self.message = message

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ErrorObj':
        """Initialize a ErrorObj object from a json dictionary."""
        args = {}
        if (code := _dict.get('code')) is not None:
            args['code'] = code
        if (message := _dict.get('message')) is not None:
            args['message'] = message
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ErrorObj object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'code') and self.code is not None:
            _dict['code'] = self.code
        if hasattr(self, 'message') and self.message is not None:
            _dict['message'] = self.message
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ErrorObj object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ErrorObj') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ErrorObj') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ExecuteQueryCreatedBody:
    """
    success response.

    :param ResultExecuteQuery response: (optional) ResultExecuteQuery OK.
    """

    def __init__(
        self,
        *,
        response: Optional['ResultExecuteQuery'] = None,
    ) -> None:
        """
        Initialize a ExecuteQueryCreatedBody object.

        :param ResultExecuteQuery response: (optional) ResultExecuteQuery OK.
        """
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ExecuteQueryCreatedBody':
        """Initialize a ExecuteQueryCreatedBody object from a json dictionary."""
        args = {}
        if (response := _dict.get('response')) is not None:
            args['response'] = ResultExecuteQuery.from_dict(response)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ExecuteQueryCreatedBody object from a json dictionary."""
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
        """Return a `str` version of this ExecuteQueryCreatedBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ExecuteQueryCreatedBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ExecuteQueryCreatedBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GlossaryObject:
    """
    glossary object.

    :param str description: (optional) description.
    :param str name: (optional) glossary term.
    """

    def __init__(
        self,
        *,
        description: Optional[str] = None,
        name: Optional[str] = None,
    ) -> None:
        """
        Initialize a GlossaryObject object.

        :param str description: (optional) description.
        :param str name: (optional) glossary term.
        """
        self.description = description
        self.name = name

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GlossaryObject':
        """Initialize a GlossaryObject object from a json dictionary."""
        args = {}
        if (description := _dict.get('description')) is not None:
            args['description'] = description
        if (name := _dict.get('name')) is not None:
            args['name'] = name
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GlossaryObject object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GlossaryObject object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GlossaryObject') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GlossaryObject') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class HdfsStorageRegistration:
    """
    HDFS storage registration.

    :param List[str] actions: (optional) Actions.
    :param BucketCatalog associated_catalog: bucket catalog.
    :param str bucket_display_name: (optional) HDFS storage display name.
    :param str bucket_id: (optional) HDFS Storage ID auto generated during
          registration.
    :param str bucket_type: HDFS type.
    :param str created_by: Username who created the HDFS storage.
    :param str created_on: Creation date.
    :param str description: HDFS description.
    :param str managed_by: managed by.
    :param str state: mark hdfs active or inactive.
    :param List[str] tags: (optional) tags.
    """

    def __init__(
        self,
        associated_catalog: 'BucketCatalog',
        bucket_type: str,
        created_by: str,
        created_on: str,
        description: str,
        managed_by: str,
        state: str,
        *,
        actions: Optional[List[str]] = None,
        bucket_display_name: Optional[str] = None,
        bucket_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a HdfsStorageRegistration object.

        :param BucketCatalog associated_catalog: bucket catalog.
        :param str bucket_type: HDFS type.
        :param str created_by: Username who created the HDFS storage.
        :param str created_on: Creation date.
        :param str description: HDFS description.
        :param str managed_by: managed by.
        :param str state: mark hdfs active or inactive.
        :param List[str] actions: (optional) Actions.
        :param str bucket_display_name: (optional) HDFS storage display name.
        :param str bucket_id: (optional) HDFS Storage ID auto generated during
               registration.
        :param List[str] tags: (optional) tags.
        """
        self.actions = actions
        self.associated_catalog = associated_catalog
        self.bucket_display_name = bucket_display_name
        self.bucket_id = bucket_id
        self.bucket_type = bucket_type
        self.created_by = created_by
        self.created_on = created_on
        self.description = description
        self.managed_by = managed_by
        self.state = state
        self.tags = tags

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'HdfsStorageRegistration':
        """Initialize a HdfsStorageRegistration object from a json dictionary."""
        args = {}
        if (actions := _dict.get('actions')) is not None:
            args['actions'] = actions
        if (associated_catalog := _dict.get('associated_catalog')) is not None:
            args['associated_catalog'] = BucketCatalog.from_dict(associated_catalog)
        else:
            raise ValueError('Required property \'associated_catalog\' not present in HdfsStorageRegistration JSON')
        if (bucket_display_name := _dict.get('bucket_display_name')) is not None:
            args['bucket_display_name'] = bucket_display_name
        if (bucket_id := _dict.get('bucket_id')) is not None:
            args['bucket_id'] = bucket_id
        if (bucket_type := _dict.get('bucket_type')) is not None:
            args['bucket_type'] = bucket_type
        else:
            raise ValueError('Required property \'bucket_type\' not present in HdfsStorageRegistration JSON')
        if (created_by := _dict.get('created_by')) is not None:
            args['created_by'] = created_by
        else:
            raise ValueError('Required property \'created_by\' not present in HdfsStorageRegistration JSON')
        if (created_on := _dict.get('created_on')) is not None:
            args['created_on'] = created_on
        else:
            raise ValueError('Required property \'created_on\' not present in HdfsStorageRegistration JSON')
        if (description := _dict.get('description')) is not None:
            args['description'] = description
        else:
            raise ValueError('Required property \'description\' not present in HdfsStorageRegistration JSON')
        if (managed_by := _dict.get('managed_by')) is not None:
            args['managed_by'] = managed_by
        else:
            raise ValueError('Required property \'managed_by\' not present in HdfsStorageRegistration JSON')
        if (state := _dict.get('state')) is not None:
            args['state'] = state
        else:
            raise ValueError('Required property \'state\' not present in HdfsStorageRegistration JSON')
        if (tags := _dict.get('tags')) is not None:
            args['tags'] = tags
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a HdfsStorageRegistration object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'actions') and self.actions is not None:
            _dict['actions'] = self.actions
        if hasattr(self, 'associated_catalog') and self.associated_catalog is not None:
            if isinstance(self.associated_catalog, dict):
                _dict['associated_catalog'] = self.associated_catalog
            else:
                _dict['associated_catalog'] = self.associated_catalog.to_dict()
        if hasattr(self, 'bucket_display_name') and self.bucket_display_name is not None:
            _dict['bucket_display_name'] = self.bucket_display_name
        if hasattr(self, 'bucket_id') and self.bucket_id is not None:
            _dict['bucket_id'] = self.bucket_id
        if hasattr(self, 'bucket_type') and self.bucket_type is not None:
            _dict['bucket_type'] = self.bucket_type
        if hasattr(self, 'created_by') and self.created_by is not None:
            _dict['created_by'] = self.created_by
        if hasattr(self, 'created_on') and self.created_on is not None:
            _dict['created_on'] = self.created_on
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'managed_by') and self.managed_by is not None:
            _dict['managed_by'] = self.managed_by
        if hasattr(self, 'state') and self.state is not None:
            _dict['state'] = self.state
        if hasattr(self, 'tags') and self.tags is not None:
            _dict['tags'] = self.tags
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this HdfsStorageRegistration object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'HdfsStorageRegistration') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'HdfsStorageRegistration') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class BucketTypeEnum(str, Enum):
        """
        HDFS type.
        """

        HDFS = 'hdfs'


    class ManagedByEnum(str, Enum):
        """
        managed by.
        """

        CUSTOMER = 'customer'


    class StateEnum(str, Enum):
        """
        mark hdfs active or inactive.
        """

        ACTIVE = 'active'
        INACTIVE = 'inactive'



class IngestionJob:
    """
    Ingestion job.

    :param bool create_if_not_exist: (optional) Create new target table (if True);
          Insert into pre-existing target table (if False).
    :param IngestionJobCsvProperty csv_property: (optional) Ingestion CSV
          properties.
    :param str details: (optional) Error messages of failed ingestion job.
    :param str end_timestamp: (optional) Unix timestamp of ingestion job completing.
    :param str engine_id: (optional) ID of the spark engine to be used for
          ingestion.
    :param str engine_name: (optional) Name of the spark engine to be used for
          ingestion.
    :param IngestionJobExecuteConfig execute_config: (optional) Ingestion engine
          configuration.
    :param str instance_id: (optional) Instance ID of the lakehouse where ingestion
          job is executed.
    :param str job_id: (optional) Job ID of the ingestion job.
    :param str partition_by: (optional) partition by expression of the target table.
    :param str schema: (optional) Schema definition of the source table.
    :param str source_data_files: (optional) Source data location of the ingestion
          job.
    :param str source_file_type: (optional) Source file types (parquet or csv).
    :param str start_timestamp: (optional) Unix timestamp of ingestion job starting.
    :param str status: (optional) Current state of ingestion job.
    :param str target_table: (optional) Target table name in format
          catalog.schema.table.
    :param str username: (optional) Ingestion job user.
    :param bool validate_csv_header: (optional) Validate CSV header if the target
          table exist.
    """

    def __init__(
        self,
        *,
        create_if_not_exist: Optional[bool] = None,
        csv_property: Optional['IngestionJobCsvProperty'] = None,
        details: Optional[str] = None,
        end_timestamp: Optional[str] = None,
        engine_id: Optional[str] = None,
        engine_name: Optional[str] = None,
        execute_config: Optional['IngestionJobExecuteConfig'] = None,
        instance_id: Optional[str] = None,
        job_id: Optional[str] = None,
        partition_by: Optional[str] = None,
        schema: Optional[str] = None,
        source_data_files: Optional[str] = None,
        source_file_type: Optional[str] = None,
        start_timestamp: Optional[str] = None,
        status: Optional[str] = None,
        target_table: Optional[str] = None,
        username: Optional[str] = None,
        validate_csv_header: Optional[bool] = None,
    ) -> None:
        """
        Initialize a IngestionJob object.

        :param bool create_if_not_exist: (optional) Create new target table (if
               True); Insert into pre-existing target table (if False).
        :param IngestionJobCsvProperty csv_property: (optional) Ingestion CSV
               properties.
        :param str details: (optional) Error messages of failed ingestion job.
        :param str end_timestamp: (optional) Unix timestamp of ingestion job
               completing.
        :param str engine_id: (optional) ID of the spark engine to be used for
               ingestion.
        :param str engine_name: (optional) Name of the spark engine to be used for
               ingestion.
        :param IngestionJobExecuteConfig execute_config: (optional) Ingestion
               engine configuration.
        :param str instance_id: (optional) Instance ID of the lakehouse where
               ingestion job is executed.
        :param str job_id: (optional) Job ID of the ingestion job.
        :param str partition_by: (optional) partition by expression of the target
               table.
        :param str schema: (optional) Schema definition of the source table.
        :param str source_data_files: (optional) Source data location of the
               ingestion job.
        :param str source_file_type: (optional) Source file types (parquet or csv).
        :param str start_timestamp: (optional) Unix timestamp of ingestion job
               starting.
        :param str status: (optional) Current state of ingestion job.
        :param str target_table: (optional) Target table name in format
               catalog.schema.table.
        :param str username: (optional) Ingestion job user.
        :param bool validate_csv_header: (optional) Validate CSV header if the
               target table exist.
        """
        self.create_if_not_exist = create_if_not_exist
        self.csv_property = csv_property
        self.details = details
        self.end_timestamp = end_timestamp
        self.engine_id = engine_id
        self.engine_name = engine_name
        self.execute_config = execute_config
        self.instance_id = instance_id
        self.job_id = job_id
        self.partition_by = partition_by
        self.schema = schema
        self.source_data_files = source_data_files
        self.source_file_type = source_file_type
        self.start_timestamp = start_timestamp
        self.status = status
        self.target_table = target_table
        self.username = username
        self.validate_csv_header = validate_csv_header

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'IngestionJob':
        """Initialize a IngestionJob object from a json dictionary."""
        args = {}
        if (create_if_not_exist := _dict.get('create_if_not_exist')) is not None:
            args['create_if_not_exist'] = create_if_not_exist
        if (csv_property := _dict.get('csv_property')) is not None:
            args['csv_property'] = IngestionJobCsvProperty.from_dict(csv_property)
        if (details := _dict.get('details')) is not None:
            args['details'] = details
        if (end_timestamp := _dict.get('end_timestamp')) is not None:
            args['end_timestamp'] = end_timestamp
        if (engine_id := _dict.get('engine_id')) is not None:
            args['engine_id'] = engine_id
        if (engine_name := _dict.get('engine_name')) is not None:
            args['engine_name'] = engine_name
        if (execute_config := _dict.get('execute_config')) is not None:
            args['execute_config'] = IngestionJobExecuteConfig.from_dict(execute_config)
        if (instance_id := _dict.get('instance_id')) is not None:
            args['instance_id'] = instance_id
        if (job_id := _dict.get('job_id')) is not None:
            args['job_id'] = job_id
        if (partition_by := _dict.get('partition_by')) is not None:
            args['partition_by'] = partition_by
        if (schema := _dict.get('schema')) is not None:
            args['schema'] = schema
        if (source_data_files := _dict.get('source_data_files')) is not None:
            args['source_data_files'] = source_data_files
        if (source_file_type := _dict.get('source_file_type')) is not None:
            args['source_file_type'] = source_file_type
        if (start_timestamp := _dict.get('start_timestamp')) is not None:
            args['start_timestamp'] = start_timestamp
        if (status := _dict.get('status')) is not None:
            args['status'] = status
        if (target_table := _dict.get('target_table')) is not None:
            args['target_table'] = target_table
        if (username := _dict.get('username')) is not None:
            args['username'] = username
        if (validate_csv_header := _dict.get('validate_csv_header')) is not None:
            args['validate_csv_header'] = validate_csv_header
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a IngestionJob object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'create_if_not_exist') and self.create_if_not_exist is not None:
            _dict['create_if_not_exist'] = self.create_if_not_exist
        if hasattr(self, 'csv_property') and self.csv_property is not None:
            if isinstance(self.csv_property, dict):
                _dict['csv_property'] = self.csv_property
            else:
                _dict['csv_property'] = self.csv_property.to_dict()
        if hasattr(self, 'details') and self.details is not None:
            _dict['details'] = self.details
        if hasattr(self, 'end_timestamp') and self.end_timestamp is not None:
            _dict['end_timestamp'] = self.end_timestamp
        if hasattr(self, 'engine_id') and self.engine_id is not None:
            _dict['engine_id'] = self.engine_id
        if hasattr(self, 'engine_name') and self.engine_name is not None:
            _dict['engine_name'] = self.engine_name
        if hasattr(self, 'execute_config') and self.execute_config is not None:
            if isinstance(self.execute_config, dict):
                _dict['execute_config'] = self.execute_config
            else:
                _dict['execute_config'] = self.execute_config.to_dict()
        if hasattr(self, 'instance_id') and self.instance_id is not None:
            _dict['instance_id'] = self.instance_id
        if hasattr(self, 'job_id') and self.job_id is not None:
            _dict['job_id'] = self.job_id
        if hasattr(self, 'partition_by') and self.partition_by is not None:
            _dict['partition_by'] = self.partition_by
        if hasattr(self, 'schema') and self.schema is not None:
            _dict['schema'] = self.schema
        if hasattr(self, 'source_data_files') and self.source_data_files is not None:
            _dict['source_data_files'] = self.source_data_files
        if hasattr(self, 'source_file_type') and self.source_file_type is not None:
            _dict['source_file_type'] = self.source_file_type
        if hasattr(self, 'start_timestamp') and self.start_timestamp is not None:
            _dict['start_timestamp'] = self.start_timestamp
        if hasattr(self, 'status') and self.status is not None:
            _dict['status'] = self.status
        if hasattr(self, 'target_table') and self.target_table is not None:
            _dict['target_table'] = self.target_table
        if hasattr(self, 'username') and self.username is not None:
            _dict['username'] = self.username
        if hasattr(self, 'validate_csv_header') and self.validate_csv_header is not None:
            _dict['validate_csv_header'] = self.validate_csv_header
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this IngestionJob object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'IngestionJob') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'IngestionJob') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class SourceFileTypeEnum(str, Enum):
        """
        Source file types (parquet or csv).
        """

        CSV = 'csv'
        PARQUET = 'parquet'



class IngestionJobCollection:
    """
    List ingestion jobs.

    :param List[IngestionJob] ingestion_jobs: (optional) Ingestion jobs.
    :param IngestionJobCollectionPage first: (optional) A page in a pagination
          collection.
    :param IngestionJobCollectionPage next: (optional) A page in a pagination
          collection.
    """

    def __init__(
        self,
        *,
        ingestion_jobs: Optional[List['IngestionJob']] = None,
        first: Optional['IngestionJobCollectionPage'] = None,
        next: Optional['IngestionJobCollectionPage'] = None,
    ) -> None:
        """
        Initialize a IngestionJobCollection object.

        :param List[IngestionJob] ingestion_jobs: (optional) Ingestion jobs.
        :param IngestionJobCollectionPage first: (optional) A page in a pagination
               collection.
        :param IngestionJobCollectionPage next: (optional) A page in a pagination
               collection.
        """
        self.ingestion_jobs = ingestion_jobs
        self.first = first
        self.next = next

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'IngestionJobCollection':
        """Initialize a IngestionJobCollection object from a json dictionary."""
        args = {}
        if (ingestion_jobs := _dict.get('ingestion_jobs')) is not None:
            args['ingestion_jobs'] = [IngestionJob.from_dict(v) for v in ingestion_jobs]
        if (first := _dict.get('first')) is not None:
            args['first'] = IngestionJobCollectionPage.from_dict(first)
        if (next := _dict.get('next')) is not None:
            args['next'] = IngestionJobCollectionPage.from_dict(next)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a IngestionJobCollection object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'ingestion_jobs') and self.ingestion_jobs is not None:
            ingestion_jobs_list = []
            for v in self.ingestion_jobs:
                if isinstance(v, dict):
                    ingestion_jobs_list.append(v)
                else:
                    ingestion_jobs_list.append(v.to_dict())
            _dict['ingestion_jobs'] = ingestion_jobs_list
        if hasattr(self, 'first') and self.first is not None:
            if isinstance(self.first, dict):
                _dict['first'] = self.first
            else:
                _dict['first'] = self.first.to_dict()
        if hasattr(self, 'next') and self.next is not None:
            if isinstance(self.next, dict):
                _dict['next'] = self.next
            else:
                _dict['next'] = self.next.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this IngestionJobCollection object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'IngestionJobCollection') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'IngestionJobCollection') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class IngestionJobCollectionPage:
    """
    A page in a pagination collection.

    :param str href: (optional) Link to the a page in the collection.
    """

    def __init__(
        self,
        *,
        href: Optional[str] = None,
    ) -> None:
        """
        Initialize a IngestionJobCollectionPage object.

        """
        self.href = href

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'IngestionJobCollectionPage':
        """Initialize a IngestionJobCollectionPage object from a json dictionary."""
        args = {}
        if (href := _dict.get('href')) is not None:
            args['href'] = href
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a IngestionJobCollectionPage object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'href') and getattr(self, 'href') is not None:
            _dict['href'] = getattr(self, 'href')
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this IngestionJobCollectionPage object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'IngestionJobCollectionPage') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'IngestionJobCollectionPage') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class IngestionJobCsvProperty:
    """
    Ingestion CSV properties.

    :param str encoding: (optional) Encoding used in CSV file.
    :param str escape_character: (optional) Escape character of CSV file.
    :param str field_delimiter: (optional) Field delimiter of CSV file.
    :param bool header: (optional) Identify if header exists in CSV file.
    :param str line_delimiter: (optional) Line delimiter of CSV file.
    """

    def __init__(
        self,
        *,
        encoding: Optional[str] = None,
        escape_character: Optional[str] = None,
        field_delimiter: Optional[str] = None,
        header: Optional[bool] = None,
        line_delimiter: Optional[str] = None,
    ) -> None:
        """
        Initialize a IngestionJobCsvProperty object.

        :param str encoding: (optional) Encoding used in CSV file.
        :param str escape_character: (optional) Escape character of CSV file.
        :param str field_delimiter: (optional) Field delimiter of CSV file.
        :param bool header: (optional) Identify if header exists in CSV file.
        :param str line_delimiter: (optional) Line delimiter of CSV file.
        """
        self.encoding = encoding
        self.escape_character = escape_character
        self.field_delimiter = field_delimiter
        self.header = header
        self.line_delimiter = line_delimiter

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'IngestionJobCsvProperty':
        """Initialize a IngestionJobCsvProperty object from a json dictionary."""
        args = {}
        if (encoding := _dict.get('encoding')) is not None:
            args['encoding'] = encoding
        if (escape_character := _dict.get('escape_character')) is not None:
            args['escape_character'] = escape_character
        if (field_delimiter := _dict.get('field_delimiter')) is not None:
            args['field_delimiter'] = field_delimiter
        if (header := _dict.get('header')) is not None:
            args['header'] = header
        if (line_delimiter := _dict.get('line_delimiter')) is not None:
            args['line_delimiter'] = line_delimiter
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a IngestionJobCsvProperty object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'encoding') and self.encoding is not None:
            _dict['encoding'] = self.encoding
        if hasattr(self, 'escape_character') and self.escape_character is not None:
            _dict['escape_character'] = self.escape_character
        if hasattr(self, 'field_delimiter') and self.field_delimiter is not None:
            _dict['field_delimiter'] = self.field_delimiter
        if hasattr(self, 'header') and self.header is not None:
            _dict['header'] = self.header
        if hasattr(self, 'line_delimiter') and self.line_delimiter is not None:
            _dict['line_delimiter'] = self.line_delimiter
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this IngestionJobCsvProperty object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'IngestionJobCsvProperty') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'IngestionJobCsvProperty') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class IngestionJobExecuteConfig:
    """
    Ingestion engine configuration.

    :param int driver_cores: (optional) Driver core(s) configuration for Spark
          engine.
    :param str driver_memory: (optional) Driver memory configuration (in GB) for
          Spark engine.
    :param int executor_cores: (optional) Executor core(s) configuration for Spark
          engine.
    :param str executor_memory: (optional) Executor memory configuration (in GB) for
          Spark engine.
    :param int num_executors: (optional) Number of executors to assign for Spark
          engine.
    """

    def __init__(
        self,
        *,
        driver_cores: Optional[int] = None,
        driver_memory: Optional[str] = None,
        executor_cores: Optional[int] = None,
        executor_memory: Optional[str] = None,
        num_executors: Optional[int] = None,
    ) -> None:
        """
        Initialize a IngestionJobExecuteConfig object.

        :param int driver_cores: (optional) Driver core(s) configuration for Spark
               engine.
        :param str driver_memory: (optional) Driver memory configuration (in GB)
               for Spark engine.
        :param int executor_cores: (optional) Executor core(s) configuration for
               Spark engine.
        :param str executor_memory: (optional) Executor memory configuration (in
               GB) for Spark engine.
        :param int num_executors: (optional) Number of executors to assign for
               Spark engine.
        """
        self.driver_cores = driver_cores
        self.driver_memory = driver_memory
        self.executor_cores = executor_cores
        self.executor_memory = executor_memory
        self.num_executors = num_executors

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'IngestionJobExecuteConfig':
        """Initialize a IngestionJobExecuteConfig object from a json dictionary."""
        args = {}
        if (driver_cores := _dict.get('driver_cores')) is not None:
            args['driver_cores'] = driver_cores
        if (driver_memory := _dict.get('driver_memory')) is not None:
            args['driver_memory'] = driver_memory
        if (executor_cores := _dict.get('executor_cores')) is not None:
            args['executor_cores'] = executor_cores
        if (executor_memory := _dict.get('executor_memory')) is not None:
            args['executor_memory'] = executor_memory
        if (num_executors := _dict.get('num_executors')) is not None:
            args['num_executors'] = num_executors
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a IngestionJobExecuteConfig object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'driver_cores') and self.driver_cores is not None:
            _dict['driver_cores'] = self.driver_cores
        if hasattr(self, 'driver_memory') and self.driver_memory is not None:
            _dict['driver_memory'] = self.driver_memory
        if hasattr(self, 'executor_cores') and self.executor_cores is not None:
            _dict['executor_cores'] = self.executor_cores
        if hasattr(self, 'executor_memory') and self.executor_memory is not None:
            _dict['executor_memory'] = self.executor_memory
        if hasattr(self, 'num_executors') and self.num_executors is not None:
            _dict['num_executors'] = self.num_executors
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this IngestionJobExecuteConfig object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'IngestionJobExecuteConfig') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'IngestionJobExecuteConfig') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class IngestionJobPrototypeCsvProperty:
    """
    Ingestion CSV properties.

    :param str encoding: (optional) Encoding used in CSV file.
    :param str escape_character: (optional) Escape character of CSV file.
    :param str field_delimiter: (optional) Field delimiter of CSV file.
    :param bool header: (optional) Identify if header exists in CSV file.
    :param str line_delimiter: (optional) Line delimiter of CSV file.
    """

    def __init__(
        self,
        *,
        encoding: Optional[str] = None,
        escape_character: Optional[str] = None,
        field_delimiter: Optional[str] = None,
        header: Optional[bool] = None,
        line_delimiter: Optional[str] = None,
    ) -> None:
        """
        Initialize a IngestionJobPrototypeCsvProperty object.

        :param str encoding: (optional) Encoding used in CSV file.
        :param str escape_character: (optional) Escape character of CSV file.
        :param str field_delimiter: (optional) Field delimiter of CSV file.
        :param bool header: (optional) Identify if header exists in CSV file.
        :param str line_delimiter: (optional) Line delimiter of CSV file.
        """
        self.encoding = encoding
        self.escape_character = escape_character
        self.field_delimiter = field_delimiter
        self.header = header
        self.line_delimiter = line_delimiter

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'IngestionJobPrototypeCsvProperty':
        """Initialize a IngestionJobPrototypeCsvProperty object from a json dictionary."""
        args = {}
        if (encoding := _dict.get('encoding')) is not None:
            args['encoding'] = encoding
        if (escape_character := _dict.get('escape_character')) is not None:
            args['escape_character'] = escape_character
        if (field_delimiter := _dict.get('field_delimiter')) is not None:
            args['field_delimiter'] = field_delimiter
        if (header := _dict.get('header')) is not None:
            args['header'] = header
        if (line_delimiter := _dict.get('line_delimiter')) is not None:
            args['line_delimiter'] = line_delimiter
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a IngestionJobPrototypeCsvProperty object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'encoding') and self.encoding is not None:
            _dict['encoding'] = self.encoding
        if hasattr(self, 'escape_character') and self.escape_character is not None:
            _dict['escape_character'] = self.escape_character
        if hasattr(self, 'field_delimiter') and self.field_delimiter is not None:
            _dict['field_delimiter'] = self.field_delimiter
        if hasattr(self, 'header') and self.header is not None:
            _dict['header'] = self.header
        if hasattr(self, 'line_delimiter') and self.line_delimiter is not None:
            _dict['line_delimiter'] = self.line_delimiter
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this IngestionJobPrototypeCsvProperty object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'IngestionJobPrototypeCsvProperty') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'IngestionJobPrototypeCsvProperty') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class IngestionJobPrototypeExecuteConfig:
    """
    Ingestion engine configuration.

    :param int driver_cores: (optional) Driver core(s) configuration for Spark
          engine.
    :param str driver_memory: (optional) Driver memory configuration (in GB) for
          Spark engine.
    :param int executor_cores: (optional) Executor core(s) configuration for Spark
          engine.
    :param str executor_memory: (optional) Executor memory configuration (in GB) for
          Spark engine.
    :param int num_executors: (optional) Number of executors to assign for Spark
          engine.
    """

    def __init__(
        self,
        *,
        driver_cores: Optional[int] = None,
        driver_memory: Optional[str] = None,
        executor_cores: Optional[int] = None,
        executor_memory: Optional[str] = None,
        num_executors: Optional[int] = None,
    ) -> None:
        """
        Initialize a IngestionJobPrototypeExecuteConfig object.

        :param int driver_cores: (optional) Driver core(s) configuration for Spark
               engine.
        :param str driver_memory: (optional) Driver memory configuration (in GB)
               for Spark engine.
        :param int executor_cores: (optional) Executor core(s) configuration for
               Spark engine.
        :param str executor_memory: (optional) Executor memory configuration (in
               GB) for Spark engine.
        :param int num_executors: (optional) Number of executors to assign for
               Spark engine.
        """
        self.driver_cores = driver_cores
        self.driver_memory = driver_memory
        self.executor_cores = executor_cores
        self.executor_memory = executor_memory
        self.num_executors = num_executors

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'IngestionJobPrototypeExecuteConfig':
        """Initialize a IngestionJobPrototypeExecuteConfig object from a json dictionary."""
        args = {}
        if (driver_cores := _dict.get('driver_cores')) is not None:
            args['driver_cores'] = driver_cores
        if (driver_memory := _dict.get('driver_memory')) is not None:
            args['driver_memory'] = driver_memory
        if (executor_cores := _dict.get('executor_cores')) is not None:
            args['executor_cores'] = executor_cores
        if (executor_memory := _dict.get('executor_memory')) is not None:
            args['executor_memory'] = executor_memory
        if (num_executors := _dict.get('num_executors')) is not None:
            args['num_executors'] = num_executors
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a IngestionJobPrototypeExecuteConfig object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'driver_cores') and self.driver_cores is not None:
            _dict['driver_cores'] = self.driver_cores
        if hasattr(self, 'driver_memory') and self.driver_memory is not None:
            _dict['driver_memory'] = self.driver_memory
        if hasattr(self, 'executor_cores') and self.executor_cores is not None:
            _dict['executor_cores'] = self.executor_cores
        if hasattr(self, 'executor_memory') and self.executor_memory is not None:
            _dict['executor_memory'] = self.executor_memory
        if hasattr(self, 'num_executors') and self.num_executors is not None:
            _dict['num_executors'] = self.num_executors
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this IngestionJobPrototypeExecuteConfig object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'IngestionJobPrototypeExecuteConfig') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'IngestionJobPrototypeExecuteConfig') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class Integration:
    """
    Integration.

    :param str apikey: (optional) Integration APIKEY.
    :param str config_properties: (optional) Properties.
    :param bool enable_data_policy_within_wxd: (optional) data policy enabler with
          wxd for ranger.
    :param str governance_properties: (optional) Properties.
    :param str integration_id: (optional) resouce for ranger.
    :param int modified_at: (optional) modified time in epoch format.
    :param str modified_by: (optional) modified user name.
    :param str password: (optional) Integration password.
    :param str resource: (optional) resouce for ranger.
    :param str service_type: (optional) Integration type.
    :param str state: (optional) current state.
    :param List[str] storage_catalogs: (optional) Comma separated list of storage
          catalogs for which ikc needs to be enabled.
    :param str url: (optional) Integration Connection URL.
    :param str username: (optional) Username.
    """

    def __init__(
        self,
        *,
        apikey: Optional[str] = None,
        config_properties: Optional[str] = None,
        enable_data_policy_within_wxd: Optional[bool] = None,
        governance_properties: Optional[str] = None,
        integration_id: Optional[str] = None,
        modified_at: Optional[int] = None,
        modified_by: Optional[str] = None,
        password: Optional[str] = None,
        resource: Optional[str] = None,
        service_type: Optional[str] = None,
        state: Optional[str] = None,
        storage_catalogs: Optional[List[str]] = None,
        url: Optional[str] = None,
        username: Optional[str] = None,
    ) -> None:
        """
        Initialize a Integration object.

        :param str apikey: (optional) Integration APIKEY.
        :param str config_properties: (optional) Properties.
        :param bool enable_data_policy_within_wxd: (optional) data policy enabler
               with wxd for ranger.
        :param str governance_properties: (optional) Properties.
        :param str integration_id: (optional) resouce for ranger.
        :param int modified_at: (optional) modified time in epoch format.
        :param str modified_by: (optional) modified user name.
        :param str password: (optional) Integration password.
        :param str resource: (optional) resouce for ranger.
        :param str service_type: (optional) Integration type.
        :param str state: (optional) current state.
        :param List[str] storage_catalogs: (optional) Comma separated list of
               storage catalogs for which ikc needs to be enabled.
        :param str url: (optional) Integration Connection URL.
        :param str username: (optional) Username.
        """
        self.apikey = apikey
        self.config_properties = config_properties
        self.enable_data_policy_within_wxd = enable_data_policy_within_wxd
        self.governance_properties = governance_properties
        self.integration_id = integration_id
        self.modified_at = modified_at
        self.modified_by = modified_by
        self.password = password
        self.resource = resource
        self.service_type = service_type
        self.state = state
        self.storage_catalogs = storage_catalogs
        self.url = url
        self.username = username

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'Integration':
        """Initialize a Integration object from a json dictionary."""
        args = {}
        if (apikey := _dict.get('apikey')) is not None:
            args['apikey'] = apikey
        if (config_properties := _dict.get('config_properties')) is not None:
            args['config_properties'] = config_properties
        if (enable_data_policy_within_wxd := _dict.get('enable_data_policy_within_wxd')) is not None:
            args['enable_data_policy_within_wxd'] = enable_data_policy_within_wxd
        if (governance_properties := _dict.get('governance_properties')) is not None:
            args['governance_properties'] = governance_properties
        if (integration_id := _dict.get('integration_id')) is not None:
            args['integration_id'] = integration_id
        if (modified_at := _dict.get('modified_at')) is not None:
            args['modified_at'] = modified_at
        if (modified_by := _dict.get('modified_by')) is not None:
            args['modified_by'] = modified_by
        if (password := _dict.get('password')) is not None:
            args['password'] = password
        if (resource := _dict.get('resource')) is not None:
            args['resource'] = resource
        if (service_type := _dict.get('service_type')) is not None:
            args['service_type'] = service_type
        if (state := _dict.get('state')) is not None:
            args['state'] = state
        if (storage_catalogs := _dict.get('storage_catalogs')) is not None:
            args['storage_catalogs'] = storage_catalogs
        if (url := _dict.get('url')) is not None:
            args['url'] = url
        if (username := _dict.get('username')) is not None:
            args['username'] = username
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a Integration object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'apikey') and self.apikey is not None:
            _dict['apikey'] = self.apikey
        if hasattr(self, 'config_properties') and self.config_properties is not None:
            _dict['config_properties'] = self.config_properties
        if hasattr(self, 'enable_data_policy_within_wxd') and self.enable_data_policy_within_wxd is not None:
            _dict['enable_data_policy_within_wxd'] = self.enable_data_policy_within_wxd
        if hasattr(self, 'governance_properties') and self.governance_properties is not None:
            _dict['governance_properties'] = self.governance_properties
        if hasattr(self, 'integration_id') and self.integration_id is not None:
            _dict['integration_id'] = self.integration_id
        if hasattr(self, 'modified_at') and self.modified_at is not None:
            _dict['modified_at'] = self.modified_at
        if hasattr(self, 'modified_by') and self.modified_by is not None:
            _dict['modified_by'] = self.modified_by
        if hasattr(self, 'password') and self.password is not None:
            _dict['password'] = self.password
        if hasattr(self, 'resource') and self.resource is not None:
            _dict['resource'] = self.resource
        if hasattr(self, 'service_type') and self.service_type is not None:
            _dict['service_type'] = self.service_type
        if hasattr(self, 'state') and self.state is not None:
            _dict['state'] = self.state
        if hasattr(self, 'storage_catalogs') and self.storage_catalogs is not None:
            _dict['storage_catalogs'] = self.storage_catalogs
        if hasattr(self, 'url') and self.url is not None:
            _dict['url'] = self.url
        if hasattr(self, 'username') and self.username is not None:
            _dict['username'] = self.username
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this Integration object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'Integration') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'Integration') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class IntegrationCollection:
    """
    list all existing integrations.

    :param List[Integration] integrations: (optional) Database body.
    """

    def __init__(
        self,
        *,
        integrations: Optional[List['Integration']] = None,
    ) -> None:
        """
        Initialize a IntegrationCollection object.

        :param List[Integration] integrations: (optional) Database body.
        """
        self.integrations = integrations

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'IntegrationCollection':
        """Initialize a IntegrationCollection object from a json dictionary."""
        args = {}
        if (integrations := _dict.get('integrations')) is not None:
            args['integrations'] = [Integration.from_dict(v) for v in integrations]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a IntegrationCollection object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'integrations') and self.integrations is not None:
            integrations_list = []
            for v in self.integrations:
                if isinstance(v, dict):
                    integrations_list.append(v)
                else:
                    integrations_list.append(v.to_dict())
            _dict['integrations'] = integrations_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this IntegrationCollection object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'IntegrationCollection') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'IntegrationCollection') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class IntegrationPatch:
    """
    Update an Integration body.

    :param str apikey: (optional) Integration APIKEY.
    :param bool enable_data_policy_within_wxd: (optional) data policy enabler with
          wxd for ranger.
    :param str password: (optional) Integration password.
    :param str resource: (optional) resouce for ranger.
    :param List[str] storage_catalogs: (optional) Comma separated list of bucket
          catalogs which have ikc enabled.
    :param str url: (optional) Integration Connection URL.
    :param str username: (optional) Integration username.
    """

    def __init__(
        self,
        *,
        apikey: Optional[str] = None,
        enable_data_policy_within_wxd: Optional[bool] = None,
        password: Optional[str] = None,
        resource: Optional[str] = None,
        storage_catalogs: Optional[List[str]] = None,
        url: Optional[str] = None,
        username: Optional[str] = None,
    ) -> None:
        """
        Initialize a IntegrationPatch object.

        :param str apikey: (optional) Integration APIKEY.
        :param bool enable_data_policy_within_wxd: (optional) data policy enabler
               with wxd for ranger.
        :param str password: (optional) Integration password.
        :param str resource: (optional) resouce for ranger.
        :param List[str] storage_catalogs: (optional) Comma separated list of
               bucket catalogs which have ikc enabled.
        :param str url: (optional) Integration Connection URL.
        :param str username: (optional) Integration username.
        """
        self.apikey = apikey
        self.enable_data_policy_within_wxd = enable_data_policy_within_wxd
        self.password = password
        self.resource = resource
        self.storage_catalogs = storage_catalogs
        self.url = url
        self.username = username

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'IntegrationPatch':
        """Initialize a IntegrationPatch object from a json dictionary."""
        args = {}
        if (apikey := _dict.get('apikey')) is not None:
            args['apikey'] = apikey
        if (enable_data_policy_within_wxd := _dict.get('enable_data_policy_within_wxd')) is not None:
            args['enable_data_policy_within_wxd'] = enable_data_policy_within_wxd
        if (password := _dict.get('password')) is not None:
            args['password'] = password
        if (resource := _dict.get('resource')) is not None:
            args['resource'] = resource
        if (storage_catalogs := _dict.get('storage_catalogs')) is not None:
            args['storage_catalogs'] = storage_catalogs
        if (url := _dict.get('url')) is not None:
            args['url'] = url
        if (username := _dict.get('username')) is not None:
            args['username'] = username
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a IntegrationPatch object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'apikey') and self.apikey is not None:
            _dict['apikey'] = self.apikey
        if hasattr(self, 'enable_data_policy_within_wxd') and self.enable_data_policy_within_wxd is not None:
            _dict['enable_data_policy_within_wxd'] = self.enable_data_policy_within_wxd
        if hasattr(self, 'password') and self.password is not None:
            _dict['password'] = self.password
        if hasattr(self, 'resource') and self.resource is not None:
            _dict['resource'] = self.resource
        if hasattr(self, 'storage_catalogs') and self.storage_catalogs is not None:
            _dict['storage_catalogs'] = self.storage_catalogs
        if hasattr(self, 'url') and self.url is not None:
            _dict['url'] = self.url
        if hasattr(self, 'username') and self.username is not None:
            _dict['username'] = self.username
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this IntegrationPatch object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'IntegrationPatch') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'IntegrationPatch') -> bool:
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
        if (response := _dict.get('response')) is not None:
            args['response'] = SuccessResponse.from_dict(response)
        else:
            raise ValueError('Required property \'response\' not present in ListSchemasOKBody JSON')
        if (schemas := _dict.get('schemas')) is not None:
            args['schemas'] = schemas
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


class ListSparkVersionsOKBody:
    """
    List spark version.

    :param SuccessResponse response: Response of success.
    :param List[DisplayNameInfoResponse] spark_versions: Spark versions list.
    """

    def __init__(
        self,
        response: 'SuccessResponse',
        spark_versions: List['DisplayNameInfoResponse'],
    ) -> None:
        """
        Initialize a ListSparkVersionsOKBody object.

        :param SuccessResponse response: Response of success.
        :param List[DisplayNameInfoResponse] spark_versions: Spark versions list.
        """
        self.response = response
        self.spark_versions = spark_versions

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ListSparkVersionsOKBody':
        """Initialize a ListSparkVersionsOKBody object from a json dictionary."""
        args = {}
        if (response := _dict.get('response')) is not None:
            args['response'] = SuccessResponse.from_dict(response)
        else:
            raise ValueError('Required property \'response\' not present in ListSparkVersionsOKBody JSON')
        if (spark_versions := _dict.get('spark_versions')) is not None:
            args['spark_versions'] = [DisplayNameInfoResponse.from_dict(v) for v in spark_versions]
        else:
            raise ValueError('Required property \'spark_versions\' not present in ListSparkVersionsOKBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListSparkVersionsOKBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'response') and self.response is not None:
            if isinstance(self.response, dict):
                _dict['response'] = self.response
            else:
                _dict['response'] = self.response.to_dict()
        if hasattr(self, 'spark_versions') and self.spark_versions is not None:
            spark_versions_list = []
            for v in self.spark_versions:
                if isinstance(v, dict):
                    spark_versions_list.append(v)
                else:
                    spark_versions_list.append(v.to_dict())
            _dict['spark_versions'] = spark_versions_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ListSparkVersionsOKBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ListSparkVersionsOKBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ListSparkVersionsOKBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class MilvusDatabaseCollections:
    """
    List milvus collections.

    :param List[Milvusdbcollection] collections: (optional) milvus collections.
    """

    def __init__(
        self,
        *,
        collections: Optional[List['Milvusdbcollection']] = None,
    ) -> None:
        """
        Initialize a MilvusDatabaseCollections object.

        :param List[Milvusdbcollection] collections: (optional) milvus collections.
        """
        self.collections = collections

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'MilvusDatabaseCollections':
        """Initialize a MilvusDatabaseCollections object from a json dictionary."""
        args = {}
        if (collections := _dict.get('collections')) is not None:
            args['collections'] = [Milvusdbcollection.from_dict(v) for v in collections]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a MilvusDatabaseCollections object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'collections') and self.collections is not None:
            collections_list = []
            for v in self.collections:
                if isinstance(v, dict):
                    collections_list.append(v)
                else:
                    collections_list.append(v.to_dict())
            _dict['collections'] = collections_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this MilvusDatabaseCollections object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'MilvusDatabaseCollections') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'MilvusDatabaseCollections') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class MilvusService:
    """
    milvus service details.

    :param str access_key: (optional) bucket access key.
    :param List[str] actions: (optional) Actions.
    :param str bucket_name: (optional) bucket name.
    :param str bucket_type: (optional) bucket type.
    :param str created_by: (optional) Username of the user who created the
          watsonx.data instance.
    :param int created_on: (optional) Created time in epoch format.
    :param str description: (optional) Service description.
    :param str endpoint: (optional) bucket endpoint.
    :param str grpc_host: (optional) milvus grpc_host.
    :param int grpc_port: (optional) milvus port.
    :param str host_name: (optional) milvus display name.
    :param str https_host: (optional) milvus https_host.
    :param int https_port: (optional) milvus port.
    :param str origin: (optional) Origin - place holder.
    :param str root_path: (optional) root path.
    :param str secret_key: (optional) bucket secret access key.
    :param str service_display_name: (optional) Service display name.
    :param str service_id: (optional) Service programmatic name.
    :param str status: (optional) milvus status.
    :param int status_code: milvus status code.
    :param List[str] tags: (optional) Tags.
    :param str tshirt_size: (optional) tshirt size.
    :param str type: (optional) service type.
    """

    def __init__(
        self,
        status_code: int,
        *,
        access_key: Optional[str] = None,
        actions: Optional[List[str]] = None,
        bucket_name: Optional[str] = None,
        bucket_type: Optional[str] = None,
        created_by: Optional[str] = None,
        created_on: Optional[int] = None,
        description: Optional[str] = None,
        endpoint: Optional[str] = None,
        grpc_host: Optional[str] = None,
        grpc_port: Optional[int] = None,
        host_name: Optional[str] = None,
        https_host: Optional[str] = None,
        https_port: Optional[int] = None,
        origin: Optional[str] = None,
        root_path: Optional[str] = None,
        secret_key: Optional[str] = None,
        service_display_name: Optional[str] = None,
        service_id: Optional[str] = None,
        status: Optional[str] = None,
        tags: Optional[List[str]] = None,
        tshirt_size: Optional[str] = None,
        type: Optional[str] = None,
    ) -> None:
        """
        Initialize a MilvusService object.

        :param int status_code: milvus status code.
        :param str access_key: (optional) bucket access key.
        :param List[str] actions: (optional) Actions.
        :param str bucket_name: (optional) bucket name.
        :param str bucket_type: (optional) bucket type.
        :param str created_by: (optional) Username of the user who created the
               watsonx.data instance.
        :param int created_on: (optional) Created time in epoch format.
        :param str description: (optional) Service description.
        :param str endpoint: (optional) bucket endpoint.
        :param str grpc_host: (optional) milvus grpc_host.
        :param int grpc_port: (optional) milvus port.
        :param str host_name: (optional) milvus display name.
        :param str https_host: (optional) milvus https_host.
        :param int https_port: (optional) milvus port.
        :param str origin: (optional) Origin - place holder.
        :param str root_path: (optional) root path.
        :param str secret_key: (optional) bucket secret access key.
        :param str service_display_name: (optional) Service display name.
        :param str service_id: (optional) Service programmatic name.
        :param str status: (optional) milvus status.
        :param List[str] tags: (optional) Tags.
        :param str tshirt_size: (optional) tshirt size.
        :param str type: (optional) service type.
        """
        self.access_key = access_key
        self.actions = actions
        self.bucket_name = bucket_name
        self.bucket_type = bucket_type
        self.created_by = created_by
        self.created_on = created_on
        self.description = description
        self.endpoint = endpoint
        self.grpc_host = grpc_host
        self.grpc_port = grpc_port
        self.host_name = host_name
        self.https_host = https_host
        self.https_port = https_port
        self.origin = origin
        self.root_path = root_path
        self.secret_key = secret_key
        self.service_display_name = service_display_name
        self.service_id = service_id
        self.status = status
        self.status_code = status_code
        self.tags = tags
        self.tshirt_size = tshirt_size
        self.type = type

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'MilvusService':
        """Initialize a MilvusService object from a json dictionary."""
        args = {}
        if (access_key := _dict.get('access_key')) is not None:
            args['access_key'] = access_key
        if (actions := _dict.get('actions')) is not None:
            args['actions'] = actions
        if (bucket_name := _dict.get('bucket_name')) is not None:
            args['bucket_name'] = bucket_name
        if (bucket_type := _dict.get('bucket_type')) is not None:
            args['bucket_type'] = bucket_type
        if (created_by := _dict.get('created_by')) is not None:
            args['created_by'] = created_by
        if (created_on := _dict.get('created_on')) is not None:
            args['created_on'] = created_on
        if (description := _dict.get('description')) is not None:
            args['description'] = description
        if (endpoint := _dict.get('endpoint')) is not None:
            args['endpoint'] = endpoint
        if (grpc_host := _dict.get('grpc_host')) is not None:
            args['grpc_host'] = grpc_host
        if (grpc_port := _dict.get('grpc_port')) is not None:
            args['grpc_port'] = grpc_port
        if (host_name := _dict.get('host_name')) is not None:
            args['host_name'] = host_name
        if (https_host := _dict.get('https_host')) is not None:
            args['https_host'] = https_host
        if (https_port := _dict.get('https_port')) is not None:
            args['https_port'] = https_port
        if (origin := _dict.get('origin')) is not None:
            args['origin'] = origin
        if (root_path := _dict.get('root_path')) is not None:
            args['root_path'] = root_path
        if (secret_key := _dict.get('secret_key')) is not None:
            args['secret_key'] = secret_key
        if (service_display_name := _dict.get('service_display_name')) is not None:
            args['service_display_name'] = service_display_name
        if (service_id := _dict.get('service_id')) is not None:
            args['service_id'] = service_id
        if (status := _dict.get('status')) is not None:
            args['status'] = status
        if (status_code := _dict.get('status_code')) is not None:
            args['status_code'] = status_code
        else:
            raise ValueError('Required property \'status_code\' not present in MilvusService JSON')
        if (tags := _dict.get('tags')) is not None:
            args['tags'] = tags
        if (tshirt_size := _dict.get('tshirt_size')) is not None:
            args['tshirt_size'] = tshirt_size
        if (type := _dict.get('type')) is not None:
            args['type'] = type
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a MilvusService object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'access_key') and self.access_key is not None:
            _dict['access_key'] = self.access_key
        if hasattr(self, 'actions') and self.actions is not None:
            _dict['actions'] = self.actions
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
        if hasattr(self, 'grpc_host') and self.grpc_host is not None:
            _dict['grpc_host'] = self.grpc_host
        if hasattr(self, 'grpc_port') and self.grpc_port is not None:
            _dict['grpc_port'] = self.grpc_port
        if hasattr(self, 'host_name') and self.host_name is not None:
            _dict['host_name'] = self.host_name
        if hasattr(self, 'https_host') and self.https_host is not None:
            _dict['https_host'] = self.https_host
        if hasattr(self, 'https_port') and self.https_port is not None:
            _dict['https_port'] = self.https_port
        if hasattr(self, 'origin') and self.origin is not None:
            _dict['origin'] = self.origin
        if hasattr(self, 'root_path') and self.root_path is not None:
            _dict['root_path'] = self.root_path
        if hasattr(self, 'secret_key') and self.secret_key is not None:
            _dict['secret_key'] = self.secret_key
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
        if hasattr(self, 'tshirt_size') and self.tshirt_size is not None:
            _dict['tshirt_size'] = self.tshirt_size
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



class MilvusServiceCollection:
    """
    List milvus services.

    :param List[MilvusService] milvus_services: (optional) milvus service body.
    """

    def __init__(
        self,
        *,
        milvus_services: Optional[List['MilvusService']] = None,
    ) -> None:
        """
        Initialize a MilvusServiceCollection object.

        :param List[MilvusService] milvus_services: (optional) milvus service body.
        """
        self.milvus_services = milvus_services

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'MilvusServiceCollection':
        """Initialize a MilvusServiceCollection object from a json dictionary."""
        args = {}
        if (milvus_services := _dict.get('milvus_services')) is not None:
            args['milvus_services'] = [MilvusService.from_dict(v) for v in milvus_services]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a MilvusServiceCollection object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'milvus_services') and self.milvus_services is not None:
            milvus_services_list = []
            for v in self.milvus_services:
                if isinstance(v, dict):
                    milvus_services_list.append(v)
                else:
                    milvus_services_list.append(v.to_dict())
            _dict['milvus_services'] = milvus_services_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this MilvusServiceCollection object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'MilvusServiceCollection') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'MilvusServiceCollection') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class MilvusServiceDatabases:
    """
    List milvus databases.

    :param List[str] databases: (optional) milvus database body.
    """

    def __init__(
        self,
        *,
        databases: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a MilvusServiceDatabases object.

        :param List[str] databases: (optional) milvus database body.
        """
        self.databases = databases

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'MilvusServiceDatabases':
        """Initialize a MilvusServiceDatabases object from a json dictionary."""
        args = {}
        if (databases := _dict.get('databases')) is not None:
            args['databases'] = databases
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a MilvusServiceDatabases object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'databases') and self.databases is not None:
            _dict['databases'] = self.databases
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this MilvusServiceDatabases object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'MilvusServiceDatabases') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'MilvusServiceDatabases') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class MilvusServicePatch:
    """
    UpdateService body.

    :param str description: (optional) Modified description.
    :param str service_display_name: (optional) Service display name.
    :param List[str] tags: (optional) Tags.
    """

    def __init__(
        self,
        *,
        description: Optional[str] = None,
        service_display_name: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a MilvusServicePatch object.

        :param str description: (optional) Modified description.
        :param str service_display_name: (optional) Service display name.
        :param List[str] tags: (optional) Tags.
        """
        self.description = description
        self.service_display_name = service_display_name
        self.tags = tags

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'MilvusServicePatch':
        """Initialize a MilvusServicePatch object from a json dictionary."""
        args = {}
        if (description := _dict.get('description')) is not None:
            args['description'] = description
        if (service_display_name := _dict.get('service_display_name')) is not None:
            args['service_display_name'] = service_display_name
        if (tags := _dict.get('tags')) is not None:
            args['tags'] = tags
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a MilvusServicePatch object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'service_display_name') and self.service_display_name is not None:
            _dict['service_display_name'] = self.service_display_name
        if hasattr(self, 'tags') and self.tags is not None:
            _dict['tags'] = self.tags
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this MilvusServicePatch object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'MilvusServicePatch') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'MilvusServicePatch') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class Milvusdbcollection:
    """
    milvus service details.

    :param int collection_id: (optional) milvus collection id.
    :param str collection_name: (optional) milvus status.
    :param List[str] physical_channels: (optional) milvus physical channels.
    :param List[str] virtual_channels: (optional) milvus virtual channels.
    """

    def __init__(
        self,
        *,
        collection_id: Optional[int] = None,
        collection_name: Optional[str] = None,
        physical_channels: Optional[List[str]] = None,
        virtual_channels: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a Milvusdbcollection object.

        :param int collection_id: (optional) milvus collection id.
        :param str collection_name: (optional) milvus status.
        :param List[str] physical_channels: (optional) milvus physical channels.
        :param List[str] virtual_channels: (optional) milvus virtual channels.
        """
        self.collection_id = collection_id
        self.collection_name = collection_name
        self.physical_channels = physical_channels
        self.virtual_channels = virtual_channels

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'Milvusdbcollection':
        """Initialize a Milvusdbcollection object from a json dictionary."""
        args = {}
        if (collection_id := _dict.get('collection_id')) is not None:
            args['collection_id'] = collection_id
        if (collection_name := _dict.get('collection_name')) is not None:
            args['collection_name'] = collection_name
        if (physical_channels := _dict.get('physical_channels')) is not None:
            args['physical_channels'] = physical_channels
        if (virtual_channels := _dict.get('virtual_channels')) is not None:
            args['virtual_channels'] = virtual_channels
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a Milvusdbcollection object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'collection_id') and self.collection_id is not None:
            _dict['collection_id'] = self.collection_id
        if hasattr(self, 'collection_name') and self.collection_name is not None:
            _dict['collection_name'] = self.collection_name
        if hasattr(self, 'physical_channels') and self.physical_channels is not None:
            _dict['physical_channels'] = self.physical_channels
        if hasattr(self, 'virtual_channels') and self.virtual_channels is not None:
            _dict['virtual_channels'] = self.virtual_channels
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this Milvusdbcollection object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'Milvusdbcollection') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'Milvusdbcollection') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


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
        if (actions := _dict.get('actions')) is not None:
            args['actions'] = actions
        if (build_version := _dict.get('build_version')) is not None:
            args['build_version'] = build_version
        if (created_by := _dict.get('created_by')) is not None:
            args['created_by'] = created_by
        if (created_on := _dict.get('created_on')) is not None:
            args['created_on'] = created_on
        if (description := _dict.get('description')) is not None:
            args['description'] = description
        if (engine_details := _dict.get('engine_details')) is not None:
            args['engine_details'] = NetezzaEngineDetails.from_dict(engine_details)
        if (engine_display_name := _dict.get('engine_display_name')) is not None:
            args['engine_display_name'] = engine_display_name
        if (engine_id := _dict.get('engine_id')) is not None:
            args['engine_id'] = engine_id
        if (host_name := _dict.get('host_name')) is not None:
            args['host_name'] = host_name
        if (origin := _dict.get('origin')) is not None:
            args['origin'] = origin
        if (port := _dict.get('port')) is not None:
            args['port'] = port
        if (status := _dict.get('status')) is not None:
            args['status'] = status
        if (tags := _dict.get('tags')) is not None:
            args['tags'] = tags
        if (type := _dict.get('type')) is not None:
            args['type'] = type
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


class NetezzaEngineCollection:
    """
    list Netezza engines.

    :param List[NetezzaEngine] netezza_engines: (optional) list Netezza engines.
    """

    def __init__(
        self,
        *,
        netezza_engines: Optional[List['NetezzaEngine']] = None,
    ) -> None:
        """
        Initialize a NetezzaEngineCollection object.

        :param List[NetezzaEngine] netezza_engines: (optional) list Netezza
               engines.
        """
        self.netezza_engines = netezza_engines

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'NetezzaEngineCollection':
        """Initialize a NetezzaEngineCollection object from a json dictionary."""
        args = {}
        if (netezza_engines := _dict.get('netezza_engines')) is not None:
            args['netezza_engines'] = [NetezzaEngine.from_dict(v) for v in netezza_engines]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a NetezzaEngineCollection object from a json dictionary."""
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
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this NetezzaEngineCollection object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'NetezzaEngineCollection') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'NetezzaEngineCollection') -> bool:
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
        if (connection_string := _dict.get('connection_string')) is not None:
            args['connection_string'] = connection_string
        if (metastore_host := _dict.get('metastore_host')) is not None:
            args['metastore_host'] = metastore_host
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


class NetezzaEngineDetailsBody:
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
        Initialize a NetezzaEngineDetailsBody object.

        :param str connection_string: (optional) External engine connection string.
        """
        self.connection_string = connection_string

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'NetezzaEngineDetailsBody':
        """Initialize a NetezzaEngineDetailsBody object from a json dictionary."""
        args = {}
        if (connection_string := _dict.get('connection_string')) is not None:
            args['connection_string'] = connection_string
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a NetezzaEngineDetailsBody object from a json dictionary."""
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
        """Return a `str` version of this NetezzaEngineDetailsBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'NetezzaEngineDetailsBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'NetezzaEngineDetailsBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class NetezzaEnginePatch:
    """
    UpdateEngine body.

    :param str description: (optional) Modified description.
    :param str engine_display_name: (optional) Engine display name.
    :param List[str] tags: (optional) Tags.
    """

    def __init__(
        self,
        *,
        description: Optional[str] = None,
        engine_display_name: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a NetezzaEnginePatch object.

        :param str description: (optional) Modified description.
        :param str engine_display_name: (optional) Engine display name.
        :param List[str] tags: (optional) Tags.
        """
        self.description = description
        self.engine_display_name = engine_display_name
        self.tags = tags

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'NetezzaEnginePatch':
        """Initialize a NetezzaEnginePatch object from a json dictionary."""
        args = {}
        if (description := _dict.get('description')) is not None:
            args['description'] = description
        if (engine_display_name := _dict.get('engine_display_name')) is not None:
            args['engine_display_name'] = engine_display_name
        if (tags := _dict.get('tags')) is not None:
            args['tags'] = tags
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a NetezzaEnginePatch object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'engine_display_name') and self.engine_display_name is not None:
            _dict['engine_display_name'] = self.engine_display_name
        if hasattr(self, 'tags') and self.tags is not None:
            _dict['tags'] = self.tags
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this NetezzaEnginePatch object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'NetezzaEnginePatch') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'NetezzaEnginePatch') -> bool:
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
        if (node_type := _dict.get('node_type')) is not None:
            args['node_type'] = node_type
        if (quantity := _dict.get('quantity')) is not None:
            args['quantity'] = quantity
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
    Coordinator/ worker properties.

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
        if (node_type := _dict.get('node_type')) is not None:
            args['node_type'] = node_type
        if (quantity := _dict.get('quantity')) is not None:
            args['quantity'] = quantity
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

    :param List[str] actions: (optional) Actions.
    :param str created_by: (optional) created user name.
    :param int created_on: (optional) created time in epoch format.
    :param str description: (optional) engine description.
    :param OtherEngineDetails engine_details: (optional) External engine details.
    :param str engine_display_name: (optional) Engine display name.
    :param str engine_id: (optional) engine programmatic name.
    :param str host_name: (optional) Engine host name. In case of OCP based
          clusters, this is internal hostname.
    :param str origin: (optional) origin.
    :param int port: (optional) Engine port.
    :param str status: (optional) engine status.
    :param List[str] tags: (optional) Tags.
    :param str type: (optional) Type like presto, netezza, external,..
    """

    def __init__(
        self,
        *,
        actions: Optional[List[str]] = None,
        created_by: Optional[str] = None,
        created_on: Optional[int] = None,
        description: Optional[str] = None,
        engine_details: Optional['OtherEngineDetails'] = None,
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
        Initialize a OtherEngine object.

        :param List[str] actions: (optional) Actions.
        :param str created_by: (optional) created user name.
        :param int created_on: (optional) created time in epoch format.
        :param str description: (optional) engine description.
        :param OtherEngineDetails engine_details: (optional) External engine
               details.
        :param str engine_display_name: (optional) Engine display name.
        :param str engine_id: (optional) engine programmatic name.
        :param str host_name: (optional) Engine host name. In case of OCP based
               clusters, this is internal hostname.
        :param str origin: (optional) origin.
        :param int port: (optional) Engine port.
        :param str status: (optional) engine status.
        :param List[str] tags: (optional) Tags.
        :param str type: (optional) Type like presto, netezza, external,..
        """
        self.actions = actions
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
    def from_dict(cls, _dict: Dict) -> 'OtherEngine':
        """Initialize a OtherEngine object from a json dictionary."""
        args = {}
        if (actions := _dict.get('actions')) is not None:
            args['actions'] = actions
        if (created_by := _dict.get('created_by')) is not None:
            args['created_by'] = created_by
        if (created_on := _dict.get('created_on')) is not None:
            args['created_on'] = created_on
        if (description := _dict.get('description')) is not None:
            args['description'] = description
        if (engine_details := _dict.get('engine_details')) is not None:
            args['engine_details'] = OtherEngineDetails.from_dict(engine_details)
        if (engine_display_name := _dict.get('engine_display_name')) is not None:
            args['engine_display_name'] = engine_display_name
        if (engine_id := _dict.get('engine_id')) is not None:
            args['engine_id'] = engine_id
        if (host_name := _dict.get('host_name')) is not None:
            args['host_name'] = host_name
        if (origin := _dict.get('origin')) is not None:
            args['origin'] = origin
        if (port := _dict.get('port')) is not None:
            args['port'] = port
        if (status := _dict.get('status')) is not None:
            args['status'] = status
        if (tags := _dict.get('tags')) is not None:
            args['tags'] = tags
        if (type := _dict.get('type')) is not None:
            args['type'] = type
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a OtherEngine object from a json dictionary."""
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


class OtherEngineCollection:
    """
    list other engines.

    :param List[OtherEngine] other_engines: (optional) list other engines.
    """

    def __init__(
        self,
        *,
        other_engines: Optional[List['OtherEngine']] = None,
    ) -> None:
        """
        Initialize a OtherEngineCollection object.

        :param List[OtherEngine] other_engines: (optional) list other engines.
        """
        self.other_engines = other_engines

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'OtherEngineCollection':
        """Initialize a OtherEngineCollection object from a json dictionary."""
        args = {}
        if (other_engines := _dict.get('other_engines')) is not None:
            args['other_engines'] = [OtherEngine.from_dict(v) for v in other_engines]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a OtherEngineCollection object from a json dictionary."""
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
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this OtherEngineCollection object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'OtherEngineCollection') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'OtherEngineCollection') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class OtherEngineDetails:
    """
    External engine details.

    :param str connection_string: external engine connection string.
    :param str engine_type: Actual engine type.
    :param str metastore_host: (optional) metastore host - not required while
          registering an engine.
    """

    def __init__(
        self,
        connection_string: str,
        engine_type: str,
        *,
        metastore_host: Optional[str] = None,
    ) -> None:
        """
        Initialize a OtherEngineDetails object.

        :param str connection_string: external engine connection string.
        :param str engine_type: Actual engine type.
        :param str metastore_host: (optional) metastore host - not required while
               registering an engine.
        """
        self.connection_string = connection_string
        self.engine_type = engine_type
        self.metastore_host = metastore_host

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'OtherEngineDetails':
        """Initialize a OtherEngineDetails object from a json dictionary."""
        args = {}
        if (connection_string := _dict.get('connection_string')) is not None:
            args['connection_string'] = connection_string
        else:
            raise ValueError('Required property \'connection_string\' not present in OtherEngineDetails JSON')
        if (engine_type := _dict.get('engine_type')) is not None:
            args['engine_type'] = engine_type
        else:
            raise ValueError('Required property \'engine_type\' not present in OtherEngineDetails JSON')
        if (metastore_host := _dict.get('metastore_host')) is not None:
            args['metastore_host'] = metastore_host
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


class OtherEngineDetailsBody:
    """
    External engine details.

    :param str connection_string: External engine connection string.
    :param str engine_type: Actual engine type.
    """

    def __init__(
        self,
        connection_string: str,
        engine_type: str,
    ) -> None:
        """
        Initialize a OtherEngineDetailsBody object.

        :param str connection_string: External engine connection string.
        :param str engine_type: Actual engine type.
        """
        self.connection_string = connection_string
        self.engine_type = engine_type

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'OtherEngineDetailsBody':
        """Initialize a OtherEngineDetailsBody object from a json dictionary."""
        args = {}
        if (connection_string := _dict.get('connection_string')) is not None:
            args['connection_string'] = connection_string
        else:
            raise ValueError('Required property \'connection_string\' not present in OtherEngineDetailsBody JSON')
        if (engine_type := _dict.get('engine_type')) is not None:
            args['engine_type'] = engine_type
        else:
            raise ValueError('Required property \'engine_type\' not present in OtherEngineDetailsBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a OtherEngineDetailsBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'connection_string') and self.connection_string is not None:
            _dict['connection_string'] = self.connection_string
        if hasattr(self, 'engine_type') and self.engine_type is not None:
            _dict['engine_type'] = self.engine_type
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this OtherEngineDetailsBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'OtherEngineDetailsBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'OtherEngineDetailsBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class Path:
    """
    Bucket object size.

    :param str path: (optional) object path.
    """

    def __init__(
        self,
        *,
        path: Optional[str] = None,
    ) -> None:
        """
        Initialize a Path object.

        :param str path: (optional) object path.
        """
        self.path = path

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'Path':
        """Initialize a Path object from a json dictionary."""
        args = {}
        if (path := _dict.get('path')) is not None:
            args['path'] = path
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a Path object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'path') and self.path is not None:
            _dict['path'] = self.path
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this Path object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'Path') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'Path') -> bool:
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
        if (applications_api := _dict.get('applications_api')) is not None:
            args['applications_api'] = applications_api
        if (history_server_endpoint := _dict.get('history_server_endpoint')) is not None:
            args['history_server_endpoint'] = history_server_endpoint
        if (spark_access_endpoint := _dict.get('spark_access_endpoint')) is not None:
            args['spark_access_endpoint'] = spark_access_endpoint
        if (spark_jobs_v4_endpoint := _dict.get('spark_jobs_v4_endpoint')) is not None:
            args['spark_jobs_v4_endpoint'] = spark_jobs_v4_endpoint
        if (spark_kernel_endpoint := _dict.get('spark_kernel_endpoint')) is not None:
            args['spark_kernel_endpoint'] = spark_kernel_endpoint
        if (view_history_server := _dict.get('view_history_server')) is not None:
            args['view_history_server'] = view_history_server
        if (wxd_application_endpoint := _dict.get('wxd_application_endpoint')) is not None:
            args['wxd_application_endpoint'] = wxd_application_endpoint
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
    :param PrestissimoNodeDescriptionBody coordinator: (optional) coordinator/worker
          property settings.
    :param str created_by: (optional) Created user name.
    :param int created_on: (optional) Created time in epoch format.
    :param str description: (optional) Engine description.
    :param PrestissimoEngineDetails engine_details: (optional) External engine
          details.
    :param str engine_display_name: (optional) Engine display name.
    :param str engine_id: (optional) Engine programmatic name.
    :param PrestissimoEngineEngineProperties engine_properties: (optional) Engine
          properties.
    :param str engine_restart: (optional) Triggers engine restart if value is force.
    :param str external_host_name: Applicable only for OCP based clusters.  This is
          typically  servicename+route.
    :param str group_id: (optional) Group ID.
    :param str host_name: (optional) Engine host name. In case of OCP based
          clusters, this is internal hostname.
    :param str origin: (optional) Origin - place holder.
    :param int port: (optional) Engine port.
    :param str region: (optional) Region - place holder.
    :param RemoveEngineProperties remove_engine_properties: (optional) RemoveEngine
          properties.
    :param str size_config: (optional) Size config.
    :param str status: (optional) Engine status.
    :param int status_code: Engine status code.
    :param List[str] tags: (optional) Tags.
    :param str type: (optional) Engine type.
    :param str version: (optional) Version of the engine.
    :param PrestissimoNodeDescriptionBody worker: (optional) coordinator/worker
          property settings.
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
        engine_properties: Optional['PrestissimoEngineEngineProperties'] = None,
        engine_restart: Optional[str] = None,
        group_id: Optional[str] = None,
        host_name: Optional[str] = None,
        origin: Optional[str] = None,
        port: Optional[int] = None,
        region: Optional[str] = None,
        remove_engine_properties: Optional['RemoveEngineProperties'] = None,
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
        :param PrestissimoNodeDescriptionBody coordinator: (optional)
               coordinator/worker property settings.
        :param str created_by: (optional) Created user name.
        :param int created_on: (optional) Created time in epoch format.
        :param str description: (optional) Engine description.
        :param PrestissimoEngineDetails engine_details: (optional) External engine
               details.
        :param str engine_display_name: (optional) Engine display name.
        :param str engine_id: (optional) Engine programmatic name.
        :param PrestissimoEngineEngineProperties engine_properties: (optional)
               Engine properties.
        :param str engine_restart: (optional) Triggers engine restart if value is
               force.
        :param str group_id: (optional) Group ID.
        :param str host_name: (optional) Engine host name. In case of OCP based
               clusters, this is internal hostname.
        :param str origin: (optional) Origin - place holder.
        :param int port: (optional) Engine port.
        :param str region: (optional) Region - place holder.
        :param RemoveEngineProperties remove_engine_properties: (optional)
               RemoveEngine properties.
        :param str size_config: (optional) Size config.
        :param str status: (optional) Engine status.
        :param List[str] tags: (optional) Tags.
        :param str type: (optional) Engine type.
        :param str version: (optional) Version of the engine.
        :param PrestissimoNodeDescriptionBody worker: (optional) coordinator/worker
               property settings.
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
        self.engine_properties = engine_properties
        self.engine_restart = engine_restart
        self.external_host_name = external_host_name
        self.group_id = group_id
        self.host_name = host_name
        self.origin = origin
        self.port = port
        self.region = region
        self.remove_engine_properties = remove_engine_properties
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
        if (actions := _dict.get('actions')) is not None:
            args['actions'] = actions
        if (associated_catalogs := _dict.get('associated_catalogs')) is not None:
            args['associated_catalogs'] = associated_catalogs
        if (build_version := _dict.get('build_version')) is not None:
            args['build_version'] = build_version
        if (coordinator := _dict.get('coordinator')) is not None:
            args['coordinator'] = PrestissimoNodeDescriptionBody.from_dict(coordinator)
        if (created_by := _dict.get('created_by')) is not None:
            args['created_by'] = created_by
        if (created_on := _dict.get('created_on')) is not None:
            args['created_on'] = created_on
        if (description := _dict.get('description')) is not None:
            args['description'] = description
        if (engine_details := _dict.get('engine_details')) is not None:
            args['engine_details'] = PrestissimoEngineDetails.from_dict(engine_details)
        if (engine_display_name := _dict.get('engine_display_name')) is not None:
            args['engine_display_name'] = engine_display_name
        if (engine_id := _dict.get('engine_id')) is not None:
            args['engine_id'] = engine_id
        if (engine_properties := _dict.get('engine_properties')) is not None:
            args['engine_properties'] = PrestissimoEngineEngineProperties.from_dict(engine_properties)
        if (engine_restart := _dict.get('engine_restart')) is not None:
            args['engine_restart'] = engine_restart
        if (external_host_name := _dict.get('external_host_name')) is not None:
            args['external_host_name'] = external_host_name
        else:
            raise ValueError('Required property \'external_host_name\' not present in PrestissimoEngine JSON')
        if (group_id := _dict.get('group_id')) is not None:
            args['group_id'] = group_id
        if (host_name := _dict.get('host_name')) is not None:
            args['host_name'] = host_name
        if (origin := _dict.get('origin')) is not None:
            args['origin'] = origin
        if (port := _dict.get('port')) is not None:
            args['port'] = port
        if (region := _dict.get('region')) is not None:
            args['region'] = region
        if (remove_engine_properties := _dict.get('remove_engine_properties')) is not None:
            args['remove_engine_properties'] = RemoveEngineProperties.from_dict(remove_engine_properties)
        if (size_config := _dict.get('size_config')) is not None:
            args['size_config'] = size_config
        if (status := _dict.get('status')) is not None:
            args['status'] = status
        if (status_code := _dict.get('status_code')) is not None:
            args['status_code'] = status_code
        else:
            raise ValueError('Required property \'status_code\' not present in PrestissimoEngine JSON')
        if (tags := _dict.get('tags')) is not None:
            args['tags'] = tags
        if (type := _dict.get('type')) is not None:
            args['type'] = type
        if (version := _dict.get('version')) is not None:
            args['version'] = version
        if (worker := _dict.get('worker')) is not None:
            args['worker'] = PrestissimoNodeDescriptionBody.from_dict(worker)
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
        if hasattr(self, 'engine_properties') and self.engine_properties is not None:
            if isinstance(self.engine_properties, dict):
                _dict['engine_properties'] = self.engine_properties
            else:
                _dict['engine_properties'] = self.engine_properties.to_dict()
        if hasattr(self, 'engine_restart') and self.engine_restart is not None:
            _dict['engine_restart'] = self.engine_restart
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
        if hasattr(self, 'remove_engine_properties') and self.remove_engine_properties is not None:
            if isinstance(self.remove_engine_properties, dict):
                _dict['remove_engine_properties'] = self.remove_engine_properties
            else:
                _dict['remove_engine_properties'] = self.remove_engine_properties.to_dict()
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

    class EngineRestartEnum(str, Enum):
        """
        Triggers engine restart if value is force.
        """

        FORCE = 'force'
        FALSE = 'false'


    class OriginEnum(str, Enum):
        """
        Origin - place holder.
        """

        NATIVE = 'native'
        EXTERNAL = 'external'
        DISCOVER = 'discover'


    class StatusEnum(str, Enum):
        """
        Engine status.
        """

        RUNNING = 'running'
        PENDING = 'pending'
        STOPPED = 'stopped'



class PrestissimoEngineCollection:
    """
    list Prestissimo Engines.

    :param List[PrestissimoEngine] prestissimo_engines: (optional) list prestissimo
          engines.
    """

    def __init__(
        self,
        *,
        prestissimo_engines: Optional[List['PrestissimoEngine']] = None,
    ) -> None:
        """
        Initialize a PrestissimoEngineCollection object.

        :param List[PrestissimoEngine] prestissimo_engines: (optional) list
               prestissimo engines.
        """
        self.prestissimo_engines = prestissimo_engines

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrestissimoEngineCollection':
        """Initialize a PrestissimoEngineCollection object from a json dictionary."""
        args = {}
        if (prestissimo_engines := _dict.get('prestissimo_engines')) is not None:
            args['prestissimo_engines'] = [PrestissimoEngine.from_dict(v) for v in prestissimo_engines]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrestissimoEngineCollection object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'prestissimo_engines') and self.prestissimo_engines is not None:
            prestissimo_engines_list = []
            for v in self.prestissimo_engines:
                if isinstance(v, dict):
                    prestissimo_engines_list.append(v)
                else:
                    prestissimo_engines_list.append(v.to_dict())
            _dict['prestissimo_engines'] = prestissimo_engines_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PrestissimoEngineCollection object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PrestissimoEngineCollection') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PrestissimoEngineCollection') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class PrestissimoEngineDetails:
    """
    External engine details.

    :param str api_key: (optional) api key to work with the saas IAE instance.
    :param str connection_string: (optional) External engine connection string.
    :param PrestissimoNodeDescriptionBody coordinator: (optional) coordinator/worker
          property settings.
    :param PrestissimoEndpoints endpoints: (optional) Endpoints.
    :param str instance_id: (optional) Instance to access the instance.
    :param str managed_by: (optional) How is the spark instance managed.
    :param str metastore_host: (optional) Metastore host.
    :param str size_config: (optional) Size config.
    :param PrestissimoNodeDescriptionBody worker: (optional) coordinator/worker
          property settings.
    """

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        connection_string: Optional[str] = None,
        coordinator: Optional['PrestissimoNodeDescriptionBody'] = None,
        endpoints: Optional['PrestissimoEndpoints'] = None,
        instance_id: Optional[str] = None,
        managed_by: Optional[str] = None,
        metastore_host: Optional[str] = None,
        size_config: Optional[str] = None,
        worker: Optional['PrestissimoNodeDescriptionBody'] = None,
    ) -> None:
        """
        Initialize a PrestissimoEngineDetails object.

        :param str api_key: (optional) api key to work with the saas IAE instance.
        :param str connection_string: (optional) External engine connection string.
        :param PrestissimoNodeDescriptionBody coordinator: (optional)
               coordinator/worker property settings.
        :param PrestissimoEndpoints endpoints: (optional) Endpoints.
        :param str instance_id: (optional) Instance to access the instance.
        :param str managed_by: (optional) How is the spark instance managed.
        :param str metastore_host: (optional) Metastore host.
        :param str size_config: (optional) Size config.
        :param PrestissimoNodeDescriptionBody worker: (optional) coordinator/worker
               property settings.
        """
        self.api_key = api_key
        self.connection_string = connection_string
        self.coordinator = coordinator
        self.endpoints = endpoints
        self.instance_id = instance_id
        self.managed_by = managed_by
        self.metastore_host = metastore_host
        self.size_config = size_config
        self.worker = worker

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrestissimoEngineDetails':
        """Initialize a PrestissimoEngineDetails object from a json dictionary."""
        args = {}
        if (api_key := _dict.get('api_key')) is not None:
            args['api_key'] = api_key
        if (connection_string := _dict.get('connection_string')) is not None:
            args['connection_string'] = connection_string
        if (coordinator := _dict.get('coordinator')) is not None:
            args['coordinator'] = PrestissimoNodeDescriptionBody.from_dict(coordinator)
        if (endpoints := _dict.get('endpoints')) is not None:
            args['endpoints'] = PrestissimoEndpoints.from_dict(endpoints)
        if (instance_id := _dict.get('instance_id')) is not None:
            args['instance_id'] = instance_id
        if (managed_by := _dict.get('managed_by')) is not None:
            args['managed_by'] = managed_by
        if (metastore_host := _dict.get('metastore_host')) is not None:
            args['metastore_host'] = metastore_host
        if (size_config := _dict.get('size_config')) is not None:
            args['size_config'] = size_config
        if (worker := _dict.get('worker')) is not None:
            args['worker'] = PrestissimoNodeDescriptionBody.from_dict(worker)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrestissimoEngineDetails object from a json dictionary."""
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
        if hasattr(self, 'endpoints') and self.endpoints is not None:
            if isinstance(self.endpoints, dict):
                _dict['endpoints'] = self.endpoints
            else:
                _dict['endpoints'] = self.endpoints.to_dict()
        if hasattr(self, 'instance_id') and self.instance_id is not None:
            _dict['instance_id'] = self.instance_id
        if hasattr(self, 'managed_by') and self.managed_by is not None:
            _dict['managed_by'] = self.managed_by
        if hasattr(self, 'metastore_host') and self.metastore_host is not None:
            _dict['metastore_host'] = self.metastore_host
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



class PrestissimoEngineEngineProperties:
    """
    Engine properties.

    :param PrestissimoEnginePropertiesCatalog catalog: (optional) Catalog settings.
    :param EnginePropertiesOaiGenConfiguration configuration: (optional)
          Configuration settings for the engine properties.
    :param PrestissimoEnginePropertiesVelox velox: (optional) velox settings.
    :param PrestissimoEnginePropertiesGlobal global_: (optional) Global session is
          to accomodate all the custom properties that can be applicable for both
          coordinator and worker.
    :param PrestissimoEnginePropertiesOaiGen1Jvm jvm: (optional) JVM settings.
    """

    def __init__(
        self,
        *,
        catalog: Optional['PrestissimoEnginePropertiesCatalog'] = None,
        configuration: Optional['EnginePropertiesOaiGenConfiguration'] = None,
        velox: Optional['PrestissimoEnginePropertiesVelox'] = None,
        global_: Optional['PrestissimoEnginePropertiesGlobal'] = None,
        jvm: Optional['PrestissimoEnginePropertiesOaiGen1Jvm'] = None,
    ) -> None:
        """
        Initialize a PrestissimoEngineEngineProperties object.

        :param PrestissimoEnginePropertiesCatalog catalog: (optional) Catalog
               settings.
        :param EnginePropertiesOaiGenConfiguration configuration: (optional)
               Configuration settings for the engine properties.
        :param PrestissimoEnginePropertiesVelox velox: (optional) velox settings.
        :param PrestissimoEnginePropertiesGlobal global_: (optional) Global session
               is to accomodate all the custom properties that can be applicable for both
               coordinator and worker.
        :param PrestissimoEnginePropertiesOaiGen1Jvm jvm: (optional) JVM settings.
        """
        self.catalog = catalog
        self.configuration = configuration
        self.velox = velox
        self.global_ = global_
        self.jvm = jvm

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrestissimoEngineEngineProperties':
        """Initialize a PrestissimoEngineEngineProperties object from a json dictionary."""
        args = {}
        if (catalog := _dict.get('catalog')) is not None:
            args['catalog'] = PrestissimoEnginePropertiesCatalog.from_dict(catalog)
        if (configuration := _dict.get('configuration')) is not None:
            args['configuration'] = EnginePropertiesOaiGenConfiguration.from_dict(configuration)
        if (velox := _dict.get('velox')) is not None:
            args['velox'] = PrestissimoEnginePropertiesVelox.from_dict(velox)
        if (global_ := _dict.get('global')) is not None:
            args['global_'] = PrestissimoEnginePropertiesGlobal.from_dict(global_)
        if (jvm := _dict.get('jvm')) is not None:
            args['jvm'] = PrestissimoEnginePropertiesOaiGen1Jvm.from_dict(jvm)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrestissimoEngineEngineProperties object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'catalog') and self.catalog is not None:
            if isinstance(self.catalog, dict):
                _dict['catalog'] = self.catalog
            else:
                _dict['catalog'] = self.catalog.to_dict()
        if hasattr(self, 'configuration') and self.configuration is not None:
            if isinstance(self.configuration, dict):
                _dict['configuration'] = self.configuration
            else:
                _dict['configuration'] = self.configuration.to_dict()
        if hasattr(self, 'velox') and self.velox is not None:
            if isinstance(self.velox, dict):
                _dict['velox'] = self.velox
            else:
                _dict['velox'] = self.velox.to_dict()
        if hasattr(self, 'global_') and self.global_ is not None:
            if isinstance(self.global_, dict):
                _dict['global'] = self.global_
            else:
                _dict['global'] = self.global_.to_dict()
        if hasattr(self, 'jvm') and self.jvm is not None:
            if isinstance(self.jvm, dict):
                _dict['jvm'] = self.jvm
            else:
                _dict['jvm'] = self.jvm.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PrestissimoEngineEngineProperties object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PrestissimoEngineEngineProperties') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PrestissimoEngineEngineProperties') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class PrestissimoEnginePatch:
    """
    Update prestissimo engine body.

    :param str description: (optional) Modified description.
    :param str engine_display_name: (optional) Engine display name.
    :param PrestissimoEngineEngineProperties engine_properties: (optional) Engine
          properties.
    :param str engine_restart: (optional) Triggers engine restart if value is force.
    :param RemoveEngineProperties remove_engine_properties: (optional) RemoveEngine
          properties.
    :param List[str] tags: (optional) Tags.
    """

    def __init__(
        self,
        *,
        description: Optional[str] = None,
        engine_display_name: Optional[str] = None,
        engine_properties: Optional['PrestissimoEngineEngineProperties'] = None,
        engine_restart: Optional[str] = None,
        remove_engine_properties: Optional['RemoveEngineProperties'] = None,
        tags: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a PrestissimoEnginePatch object.

        :param str description: (optional) Modified description.
        :param str engine_display_name: (optional) Engine display name.
        :param PrestissimoEngineEngineProperties engine_properties: (optional)
               Engine properties.
        :param str engine_restart: (optional) Triggers engine restart if value is
               force.
        :param RemoveEngineProperties remove_engine_properties: (optional)
               RemoveEngine properties.
        :param List[str] tags: (optional) Tags.
        """
        self.description = description
        self.engine_display_name = engine_display_name
        self.engine_properties = engine_properties
        self.engine_restart = engine_restart
        self.remove_engine_properties = remove_engine_properties
        self.tags = tags

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrestissimoEnginePatch':
        """Initialize a PrestissimoEnginePatch object from a json dictionary."""
        args = {}
        if (description := _dict.get('description')) is not None:
            args['description'] = description
        if (engine_display_name := _dict.get('engine_display_name')) is not None:
            args['engine_display_name'] = engine_display_name
        if (engine_properties := _dict.get('engine_properties')) is not None:
            args['engine_properties'] = PrestissimoEngineEngineProperties.from_dict(engine_properties)
        if (engine_restart := _dict.get('engine_restart')) is not None:
            args['engine_restart'] = engine_restart
        if (remove_engine_properties := _dict.get('remove_engine_properties')) is not None:
            args['remove_engine_properties'] = RemoveEngineProperties.from_dict(remove_engine_properties)
        if (tags := _dict.get('tags')) is not None:
            args['tags'] = tags
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrestissimoEnginePatch object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'engine_display_name') and self.engine_display_name is not None:
            _dict['engine_display_name'] = self.engine_display_name
        if hasattr(self, 'engine_properties') and self.engine_properties is not None:
            if isinstance(self.engine_properties, dict):
                _dict['engine_properties'] = self.engine_properties
            else:
                _dict['engine_properties'] = self.engine_properties.to_dict()
        if hasattr(self, 'engine_restart') and self.engine_restart is not None:
            _dict['engine_restart'] = self.engine_restart
        if hasattr(self, 'remove_engine_properties') and self.remove_engine_properties is not None:
            if isinstance(self.remove_engine_properties, dict):
                _dict['remove_engine_properties'] = self.remove_engine_properties
            else:
                _dict['remove_engine_properties'] = self.remove_engine_properties.to_dict()
        if hasattr(self, 'tags') and self.tags is not None:
            _dict['tags'] = self.tags
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PrestissimoEnginePatch object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PrestissimoEnginePatch') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PrestissimoEnginePatch') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class EngineRestartEnum(str, Enum):
        """
        Triggers engine restart if value is force.
        """

        FORCE = 'force'
        FALSE = 'false'



class PrestissimoEnginePropertiesCatalog:
    """
    Catalog settings.

    :param List[str] catalog_name: (optional) catalog name.
    """

    def __init__(
        self,
        *,
        catalog_name: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a PrestissimoEnginePropertiesCatalog object.

        :param List[str] catalog_name: (optional) catalog name.
        """
        self.catalog_name = catalog_name

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrestissimoEnginePropertiesCatalog':
        """Initialize a PrestissimoEnginePropertiesCatalog object from a json dictionary."""
        args = {}
        if (catalog_name := _dict.get('catalog_name')) is not None:
            args['catalog_name'] = catalog_name
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrestissimoEnginePropertiesCatalog object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'catalog_name') and self.catalog_name is not None:
            _dict['catalog_name'] = self.catalog_name
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PrestissimoEnginePropertiesCatalog object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PrestissimoEnginePropertiesCatalog') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PrestissimoEnginePropertiesCatalog') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class PrestissimoEnginePropertiesGlobal:
    """
    Global session is to accomodate all the custom properties that can be applicable for
    both coordinator and worker.

    :param str global_property: (optional) Global property settings.
    """

    def __init__(
        self,
        *,
        global_property: Optional[str] = None,
    ) -> None:
        """
        Initialize a PrestissimoEnginePropertiesGlobal object.

        :param str global_property: (optional) Global property settings.
        """
        self.global_property = global_property

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrestissimoEnginePropertiesGlobal':
        """Initialize a PrestissimoEnginePropertiesGlobal object from a json dictionary."""
        args = {}
        if (global_property := _dict.get('global_property')) is not None:
            args['global_property'] = global_property
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrestissimoEnginePropertiesGlobal object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'global_property') and self.global_property is not None:
            _dict['global_property'] = self.global_property
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PrestissimoEnginePropertiesGlobal object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PrestissimoEnginePropertiesGlobal') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PrestissimoEnginePropertiesGlobal') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class PrestissimoEnginePropertiesOaiGen1Jvm:
    """
    JVM settings.

    :param NodeDescriptionBody coordinator: (optional) Coordinator/ worker
          properties.
    """

    def __init__(
        self,
        *,
        coordinator: Optional['NodeDescriptionBody'] = None,
    ) -> None:
        """
        Initialize a PrestissimoEnginePropertiesOaiGen1Jvm object.

        :param NodeDescriptionBody coordinator: (optional) Coordinator/ worker
               properties.
        """
        self.coordinator = coordinator

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrestissimoEnginePropertiesOaiGen1Jvm':
        """Initialize a PrestissimoEnginePropertiesOaiGen1Jvm object from a json dictionary."""
        args = {}
        if (coordinator := _dict.get('coordinator')) is not None:
            args['coordinator'] = NodeDescriptionBody.from_dict(coordinator)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrestissimoEnginePropertiesOaiGen1Jvm object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'coordinator') and self.coordinator is not None:
            if isinstance(self.coordinator, dict):
                _dict['coordinator'] = self.coordinator
            else:
                _dict['coordinator'] = self.coordinator.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PrestissimoEnginePropertiesOaiGen1Jvm object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PrestissimoEnginePropertiesOaiGen1Jvm') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PrestissimoEnginePropertiesOaiGen1Jvm') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class PrestissimoEnginePropertiesVelox:
    """
    velox settings.

    :param List[str] velox_property: (optional) velox property.
    """

    def __init__(
        self,
        *,
        velox_property: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a PrestissimoEnginePropertiesVelox object.

        :param List[str] velox_property: (optional) velox property.
        """
        self.velox_property = velox_property

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrestissimoEnginePropertiesVelox':
        """Initialize a PrestissimoEnginePropertiesVelox object from a json dictionary."""
        args = {}
        if (velox_property := _dict.get('velox_property')) is not None:
            args['velox_property'] = velox_property
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrestissimoEnginePropertiesVelox object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'velox_property') and self.velox_property is not None:
            _dict['velox_property'] = self.velox_property
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PrestissimoEnginePropertiesVelox object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PrestissimoEnginePropertiesVelox') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PrestissimoEnginePropertiesVelox') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class PrestissimoNodeDescriptionBody:
    """
    coordinator/worker property settings.

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
        if (node_type := _dict.get('node_type')) is not None:
            args['node_type'] = node_type
        if (quantity := _dict.get('quantity')) is not None:
            args['quantity'] = quantity
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
    :param List[str] associated_catalogs: (optional) Associated catalogs.
    :param str build_version: (optional) watsonx.data build version.
    :param NodeDescription coordinator: (optional) NodeDescription.
    :param str created_by: (optional) Created user name.
    :param int created_on: (optional) Created time in epoch format.
    :param str description: (optional) Engine description.
    :param List[Driver] drivers: (optional) Driver details.
    :param EngineDetailsBody engine_details: (optional) Node details.
    :param str engine_display_name: (optional) Engine display name.
    :param str engine_id: (optional) Engine programmatic name.
    :param PrestoEngineEngineProperties engine_properties: (optional) Engine
          properties.
    :param str engine_restart: (optional) Triggers engine restart if value is force.
    :param str external_host_name: Applicable only for OCP based clusters.  This is
          typically  servicename+route.
    :param str group_id: (optional) Group ID.
    :param str host_name: (optional) Engine host name. In case of OCP based
          clusters, this is internal hostname.
    :param str origin: (optional) Origin - created or registered.
    :param int port: (optional) Engine port.
    :param str region: (optional) Region (cloud).
    :param PrestoEnginePatchRemoveEngineProperties remove_engine_properties:
          (optional) RemoveEngine properties.
    :param str size_config: (optional) Size config.
    :param str status: (optional) Engine status.
    :param int status_code: Engine status code.
    :param List[str] tags: (optional) Tags.
    :param str type: (optional) Engine type presto.
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
        drivers: Optional[List['Driver']] = None,
        engine_details: Optional['EngineDetailsBody'] = None,
        engine_display_name: Optional[str] = None,
        engine_id: Optional[str] = None,
        engine_properties: Optional['PrestoEngineEngineProperties'] = None,
        engine_restart: Optional[str] = None,
        group_id: Optional[str] = None,
        host_name: Optional[str] = None,
        origin: Optional[str] = None,
        port: Optional[int] = None,
        region: Optional[str] = None,
        remove_engine_properties: Optional['PrestoEnginePatchRemoveEngineProperties'] = None,
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
        :param List[str] associated_catalogs: (optional) Associated catalogs.
        :param str build_version: (optional) watsonx.data build version.
        :param NodeDescription coordinator: (optional) NodeDescription.
        :param str created_by: (optional) Created user name.
        :param int created_on: (optional) Created time in epoch format.
        :param str description: (optional) Engine description.
        :param List[Driver] drivers: (optional) Driver details.
        :param EngineDetailsBody engine_details: (optional) Node details.
        :param str engine_display_name: (optional) Engine display name.
        :param str engine_id: (optional) Engine programmatic name.
        :param PrestoEngineEngineProperties engine_properties: (optional) Engine
               properties.
        :param str engine_restart: (optional) Triggers engine restart if value is
               force.
        :param str group_id: (optional) Group ID.
        :param str host_name: (optional) Engine host name. In case of OCP based
               clusters, this is internal hostname.
        :param str origin: (optional) Origin - created or registered.
        :param int port: (optional) Engine port.
        :param str region: (optional) Region (cloud).
        :param PrestoEnginePatchRemoveEngineProperties remove_engine_properties:
               (optional) RemoveEngine properties.
        :param str size_config: (optional) Size config.
        :param str status: (optional) Engine status.
        :param List[str] tags: (optional) Tags.
        :param str type: (optional) Engine type presto.
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
        self.drivers = drivers
        self.engine_details = engine_details
        self.engine_display_name = engine_display_name
        self.engine_id = engine_id
        self.engine_properties = engine_properties
        self.engine_restart = engine_restart
        self.external_host_name = external_host_name
        self.group_id = group_id
        self.host_name = host_name
        self.origin = origin
        self.port = port
        self.region = region
        self.remove_engine_properties = remove_engine_properties
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
        if (actions := _dict.get('actions')) is not None:
            args['actions'] = actions
        if (associated_catalogs := _dict.get('associated_catalogs')) is not None:
            args['associated_catalogs'] = associated_catalogs
        if (build_version := _dict.get('build_version')) is not None:
            args['build_version'] = build_version
        if (coordinator := _dict.get('coordinator')) is not None:
            args['coordinator'] = NodeDescription.from_dict(coordinator)
        if (created_by := _dict.get('created_by')) is not None:
            args['created_by'] = created_by
        if (created_on := _dict.get('created_on')) is not None:
            args['created_on'] = created_on
        if (description := _dict.get('description')) is not None:
            args['description'] = description
        if (drivers := _dict.get('drivers')) is not None:
            args['drivers'] = [Driver.from_dict(v) for v in drivers]
        if (engine_details := _dict.get('engine_details')) is not None:
            args['engine_details'] = EngineDetailsBody.from_dict(engine_details)
        if (engine_display_name := _dict.get('engine_display_name')) is not None:
            args['engine_display_name'] = engine_display_name
        if (engine_id := _dict.get('engine_id')) is not None:
            args['engine_id'] = engine_id
        if (engine_properties := _dict.get('engine_properties')) is not None:
            args['engine_properties'] = PrestoEngineEngineProperties.from_dict(engine_properties)
        if (engine_restart := _dict.get('engine_restart')) is not None:
            args['engine_restart'] = engine_restart
        if (external_host_name := _dict.get('external_host_name')) is not None:
            args['external_host_name'] = external_host_name
        else:
            raise ValueError('Required property \'external_host_name\' not present in PrestoEngine JSON')
        if (group_id := _dict.get('group_id')) is not None:
            args['group_id'] = group_id
        if (host_name := _dict.get('host_name')) is not None:
            args['host_name'] = host_name
        if (origin := _dict.get('origin')) is not None:
            args['origin'] = origin
        if (port := _dict.get('port')) is not None:
            args['port'] = port
        if (region := _dict.get('region')) is not None:
            args['region'] = region
        if (remove_engine_properties := _dict.get('remove_engine_properties')) is not None:
            args['remove_engine_properties'] = PrestoEnginePatchRemoveEngineProperties.from_dict(remove_engine_properties)
        if (size_config := _dict.get('size_config')) is not None:
            args['size_config'] = size_config
        if (status := _dict.get('status')) is not None:
            args['status'] = status
        if (status_code := _dict.get('status_code')) is not None:
            args['status_code'] = status_code
        else:
            raise ValueError('Required property \'status_code\' not present in PrestoEngine JSON')
        if (tags := _dict.get('tags')) is not None:
            args['tags'] = tags
        if (type := _dict.get('type')) is not None:
            args['type'] = type
        if (version := _dict.get('version')) is not None:
            args['version'] = version
        if (worker := _dict.get('worker')) is not None:
            args['worker'] = NodeDescription.from_dict(worker)
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
        if hasattr(self, 'drivers') and self.drivers is not None:
            drivers_list = []
            for v in self.drivers:
                if isinstance(v, dict):
                    drivers_list.append(v)
                else:
                    drivers_list.append(v.to_dict())
            _dict['drivers'] = drivers_list
        if hasattr(self, 'engine_details') and self.engine_details is not None:
            if isinstance(self.engine_details, dict):
                _dict['engine_details'] = self.engine_details
            else:
                _dict['engine_details'] = self.engine_details.to_dict()
        if hasattr(self, 'engine_display_name') and self.engine_display_name is not None:
            _dict['engine_display_name'] = self.engine_display_name
        if hasattr(self, 'engine_id') and self.engine_id is not None:
            _dict['engine_id'] = self.engine_id
        if hasattr(self, 'engine_properties') and self.engine_properties is not None:
            if isinstance(self.engine_properties, dict):
                _dict['engine_properties'] = self.engine_properties
            else:
                _dict['engine_properties'] = self.engine_properties.to_dict()
        if hasattr(self, 'engine_restart') and self.engine_restart is not None:
            _dict['engine_restart'] = self.engine_restart
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
        if hasattr(self, 'remove_engine_properties') and self.remove_engine_properties is not None:
            if isinstance(self.remove_engine_properties, dict):
                _dict['remove_engine_properties'] = self.remove_engine_properties
            else:
                _dict['remove_engine_properties'] = self.remove_engine_properties.to_dict()
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

    class EngineRestartEnum(str, Enum):
        """
        Triggers engine restart if value is force.
        """

        FORCE = 'force'
        FALSE = 'false'


    class OriginEnum(str, Enum):
        """
        Origin - created or registered.
        """

        NATIVE = 'native'
        EXTERNAL = 'external'
        DISCOVER = 'discover'


    class StatusEnum(str, Enum):
        """
        Engine status.
        """

        RUNNING = 'running'
        PENDING = 'pending'
        STOPPED = 'stopped'



class PrestoEngineCollection:
    """
    List Presto engines.

    :param List[PrestoEngine] presto_engines: (optional) Presto engine.
    """

    def __init__(
        self,
        *,
        presto_engines: Optional[List['PrestoEngine']] = None,
    ) -> None:
        """
        Initialize a PrestoEngineCollection object.

        :param List[PrestoEngine] presto_engines: (optional) Presto engine.
        """
        self.presto_engines = presto_engines

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrestoEngineCollection':
        """Initialize a PrestoEngineCollection object from a json dictionary."""
        args = {}
        if (presto_engines := _dict.get('presto_engines')) is not None:
            args['presto_engines'] = [PrestoEngine.from_dict(v) for v in presto_engines]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrestoEngineCollection object from a json dictionary."""
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
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PrestoEngineCollection object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PrestoEngineCollection') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PrestoEngineCollection') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class PrestoEngineEngineProperties:
    """
    Engine properties.

    :param PrestoEnginePropertiesCatalog catalog: (optional) Catalog settings.
    :param EnginePropertiesOaiGen1Configuration configuration: (optional)
          Configuration settings.
    :param PrestoEnginePropertiesEventListener event_listener: (optional) Event
          Listener settings.
    :param PrestoEnginePropertiesGlobal global_: (optional) Global session is to
          accomodate all the custom properties that can be applicable for both coordinator
          and worker.
    :param EnginePropertiesOaiGen1Jvm jvm: (optional) JVM settings.
    :param EnginePropertiesLogConfiguration log_config: (optional) Log Configuration
          settings.
    """

    def __init__(
        self,
        *,
        catalog: Optional['PrestoEnginePropertiesCatalog'] = None,
        configuration: Optional['EnginePropertiesOaiGen1Configuration'] = None,
        event_listener: Optional['PrestoEnginePropertiesEventListener'] = None,
        global_: Optional['PrestoEnginePropertiesGlobal'] = None,
        jvm: Optional['EnginePropertiesOaiGen1Jvm'] = None,
        log_config: Optional['EnginePropertiesLogConfiguration'] = None,
    ) -> None:
        """
        Initialize a PrestoEngineEngineProperties object.

        :param PrestoEnginePropertiesCatalog catalog: (optional) Catalog settings.
        :param EnginePropertiesOaiGen1Configuration configuration: (optional)
               Configuration settings.
        :param PrestoEnginePropertiesEventListener event_listener: (optional) Event
               Listener settings.
        :param PrestoEnginePropertiesGlobal global_: (optional) Global session is
               to accomodate all the custom properties that can be applicable for both
               coordinator and worker.
        :param EnginePropertiesOaiGen1Jvm jvm: (optional) JVM settings.
        :param EnginePropertiesLogConfiguration log_config: (optional) Log
               Configuration settings.
        """
        self.catalog = catalog
        self.configuration = configuration
        self.event_listener = event_listener
        self.global_ = global_
        self.jvm = jvm
        self.log_config = log_config

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrestoEngineEngineProperties':
        """Initialize a PrestoEngineEngineProperties object from a json dictionary."""
        args = {}
        if (catalog := _dict.get('catalog')) is not None:
            args['catalog'] = PrestoEnginePropertiesCatalog.from_dict(catalog)
        if (configuration := _dict.get('configuration')) is not None:
            args['configuration'] = EnginePropertiesOaiGen1Configuration.from_dict(configuration)
        if (event_listener := _dict.get('event_listener')) is not None:
            args['event_listener'] = PrestoEnginePropertiesEventListener.from_dict(event_listener)
        if (global_ := _dict.get('global')) is not None:
            args['global_'] = PrestoEnginePropertiesGlobal.from_dict(global_)
        if (jvm := _dict.get('jvm')) is not None:
            args['jvm'] = EnginePropertiesOaiGen1Jvm.from_dict(jvm)
        if (log_config := _dict.get('log_config')) is not None:
            args['log_config'] = EnginePropertiesLogConfiguration.from_dict(log_config)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrestoEngineEngineProperties object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'catalog') and self.catalog is not None:
            if isinstance(self.catalog, dict):
                _dict['catalog'] = self.catalog
            else:
                _dict['catalog'] = self.catalog.to_dict()
        if hasattr(self, 'configuration') and self.configuration is not None:
            if isinstance(self.configuration, dict):
                _dict['configuration'] = self.configuration
            else:
                _dict['configuration'] = self.configuration.to_dict()
        if hasattr(self, 'event_listener') and self.event_listener is not None:
            if isinstance(self.event_listener, dict):
                _dict['event_listener'] = self.event_listener
            else:
                _dict['event_listener'] = self.event_listener.to_dict()
        if hasattr(self, 'global_') and self.global_ is not None:
            if isinstance(self.global_, dict):
                _dict['global'] = self.global_
            else:
                _dict['global'] = self.global_.to_dict()
        if hasattr(self, 'jvm') and self.jvm is not None:
            if isinstance(self.jvm, dict):
                _dict['jvm'] = self.jvm
            else:
                _dict['jvm'] = self.jvm.to_dict()
        if hasattr(self, 'log_config') and self.log_config is not None:
            if isinstance(self.log_config, dict):
                _dict['log_config'] = self.log_config
            else:
                _dict['log_config'] = self.log_config.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PrestoEngineEngineProperties object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PrestoEngineEngineProperties') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PrestoEngineEngineProperties') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class PrestoEnginePatch:
    """
    UpdateEngine body.

    :param str description: (optional) Modified description.
    :param str engine_display_name: (optional) Engine display name.
    :param PrestoEngineEngineProperties engine_properties: (optional) Engine
          properties.
    :param str engine_restart: (optional) Triggers engine restart if value is force.
    :param PrestoEnginePatchRemoveEngineProperties remove_engine_properties:
          (optional) RemoveEngine properties.
    :param List[str] tags: (optional) Tags.
    """

    def __init__(
        self,
        *,
        description: Optional[str] = None,
        engine_display_name: Optional[str] = None,
        engine_properties: Optional['PrestoEngineEngineProperties'] = None,
        engine_restart: Optional[str] = None,
        remove_engine_properties: Optional['PrestoEnginePatchRemoveEngineProperties'] = None,
        tags: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a PrestoEnginePatch object.

        :param str description: (optional) Modified description.
        :param str engine_display_name: (optional) Engine display name.
        :param PrestoEngineEngineProperties engine_properties: (optional) Engine
               properties.
        :param str engine_restart: (optional) Triggers engine restart if value is
               force.
        :param PrestoEnginePatchRemoveEngineProperties remove_engine_properties:
               (optional) RemoveEngine properties.
        :param List[str] tags: (optional) Tags.
        """
        self.description = description
        self.engine_display_name = engine_display_name
        self.engine_properties = engine_properties
        self.engine_restart = engine_restart
        self.remove_engine_properties = remove_engine_properties
        self.tags = tags

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrestoEnginePatch':
        """Initialize a PrestoEnginePatch object from a json dictionary."""
        args = {}
        if (description := _dict.get('description')) is not None:
            args['description'] = description
        if (engine_display_name := _dict.get('engine_display_name')) is not None:
            args['engine_display_name'] = engine_display_name
        if (engine_properties := _dict.get('engine_properties')) is not None:
            args['engine_properties'] = PrestoEngineEngineProperties.from_dict(engine_properties)
        if (engine_restart := _dict.get('engine_restart')) is not None:
            args['engine_restart'] = engine_restart
        if (remove_engine_properties := _dict.get('remove_engine_properties')) is not None:
            args['remove_engine_properties'] = PrestoEnginePatchRemoveEngineProperties.from_dict(remove_engine_properties)
        if (tags := _dict.get('tags')) is not None:
            args['tags'] = tags
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrestoEnginePatch object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'engine_display_name') and self.engine_display_name is not None:
            _dict['engine_display_name'] = self.engine_display_name
        if hasattr(self, 'engine_properties') and self.engine_properties is not None:
            if isinstance(self.engine_properties, dict):
                _dict['engine_properties'] = self.engine_properties
            else:
                _dict['engine_properties'] = self.engine_properties.to_dict()
        if hasattr(self, 'engine_restart') and self.engine_restart is not None:
            _dict['engine_restart'] = self.engine_restart
        if hasattr(self, 'remove_engine_properties') and self.remove_engine_properties is not None:
            if isinstance(self.remove_engine_properties, dict):
                _dict['remove_engine_properties'] = self.remove_engine_properties
            else:
                _dict['remove_engine_properties'] = self.remove_engine_properties.to_dict()
        if hasattr(self, 'tags') and self.tags is not None:
            _dict['tags'] = self.tags
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PrestoEnginePatch object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PrestoEnginePatch') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PrestoEnginePatch') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class EngineRestartEnum(str, Enum):
        """
        Triggers engine restart if value is force.
        """

        FORCE = 'force'
        FALSE = 'false'



class PrestoEnginePatchRemoveEngineProperties:
    """
    RemoveEngine properties.

    :param PrestoEnginePropertiesCatalog catalog: (optional) Catalog settings.
    :param RemoveEnginePropertiesOaiGenConfiguration configuration: (optional)
          Configuration settings for removing engine properties.
    :param RemoveEnginePropertiesOaiGenJvm jvm: (optional) JVM properties.
    :param List[str] event_listener: (optional) Event Listener properties.
    """

    def __init__(
        self,
        *,
        catalog: Optional['PrestoEnginePropertiesCatalog'] = None,
        configuration: Optional['RemoveEnginePropertiesOaiGenConfiguration'] = None,
        jvm: Optional['RemoveEnginePropertiesOaiGenJvm'] = None,
        event_listener: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a PrestoEnginePatchRemoveEngineProperties object.

        :param PrestoEnginePropertiesCatalog catalog: (optional) Catalog settings.
        :param RemoveEnginePropertiesOaiGenConfiguration configuration: (optional)
               Configuration settings for removing engine properties.
        :param RemoveEnginePropertiesOaiGenJvm jvm: (optional) JVM properties.
        :param List[str] event_listener: (optional) Event Listener properties.
        """
        self.catalog = catalog
        self.configuration = configuration
        self.jvm = jvm
        self.event_listener = event_listener

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrestoEnginePatchRemoveEngineProperties':
        """Initialize a PrestoEnginePatchRemoveEngineProperties object from a json dictionary."""
        args = {}
        if (catalog := _dict.get('catalog')) is not None:
            args['catalog'] = PrestoEnginePropertiesCatalog.from_dict(catalog)
        if (configuration := _dict.get('configuration')) is not None:
            args['configuration'] = RemoveEnginePropertiesOaiGenConfiguration.from_dict(configuration)
        if (jvm := _dict.get('jvm')) is not None:
            args['jvm'] = RemoveEnginePropertiesOaiGenJvm.from_dict(jvm)
        if (event_listener := _dict.get('event_listener')) is not None:
            args['event_listener'] = event_listener
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrestoEnginePatchRemoveEngineProperties object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'catalog') and self.catalog is not None:
            if isinstance(self.catalog, dict):
                _dict['catalog'] = self.catalog
            else:
                _dict['catalog'] = self.catalog.to_dict()
        if hasattr(self, 'configuration') and self.configuration is not None:
            if isinstance(self.configuration, dict):
                _dict['configuration'] = self.configuration
            else:
                _dict['configuration'] = self.configuration.to_dict()
        if hasattr(self, 'jvm') and self.jvm is not None:
            if isinstance(self.jvm, dict):
                _dict['jvm'] = self.jvm
            else:
                _dict['jvm'] = self.jvm.to_dict()
        if hasattr(self, 'event_listener') and self.event_listener is not None:
            _dict['event_listener'] = self.event_listener
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PrestoEnginePatchRemoveEngineProperties object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PrestoEnginePatchRemoveEngineProperties') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PrestoEnginePatchRemoveEngineProperties') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class PrestoEnginePropertiesCatalog:
    """
    Catalog settings.

    :param str catalog_name: (optional) Name of the catalog.
    """

    def __init__(
        self,
        *,
        catalog_name: Optional[str] = None,
    ) -> None:
        """
        Initialize a PrestoEnginePropertiesCatalog object.

        :param str catalog_name: (optional) Name of the catalog.
        """
        self.catalog_name = catalog_name

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrestoEnginePropertiesCatalog':
        """Initialize a PrestoEnginePropertiesCatalog object from a json dictionary."""
        args = {}
        if (catalog_name := _dict.get('catalog_name')) is not None:
            args['catalog_name'] = catalog_name
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrestoEnginePropertiesCatalog object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'catalog_name') and self.catalog_name is not None:
            _dict['catalog_name'] = self.catalog_name
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PrestoEnginePropertiesCatalog object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PrestoEnginePropertiesCatalog') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PrestoEnginePropertiesCatalog') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class PrestoEnginePropertiesEventListener:
    """
    Event Listener settings.

    :param str event_listener_property: (optional) Event listener properties.
    """

    def __init__(
        self,
        *,
        event_listener_property: Optional[str] = None,
    ) -> None:
        """
        Initialize a PrestoEnginePropertiesEventListener object.

        :param str event_listener_property: (optional) Event listener properties.
        """
        self.event_listener_property = event_listener_property

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrestoEnginePropertiesEventListener':
        """Initialize a PrestoEnginePropertiesEventListener object from a json dictionary."""
        args = {}
        if (event_listener_property := _dict.get('event_listener_property')) is not None:
            args['event_listener_property'] = event_listener_property
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrestoEnginePropertiesEventListener object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'event_listener_property') and self.event_listener_property is not None:
            _dict['event_listener_property'] = self.event_listener_property
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PrestoEnginePropertiesEventListener object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PrestoEnginePropertiesEventListener') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PrestoEnginePropertiesEventListener') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class PrestoEnginePropertiesGlobal:
    """
    Global session is to accomodate all the custom properties that can be applicable for
    both coordinator and worker.

    :param str global_property: (optional) Global property settings.
    """

    def __init__(
        self,
        *,
        global_property: Optional[str] = None,
    ) -> None:
        """
        Initialize a PrestoEnginePropertiesGlobal object.

        :param str global_property: (optional) Global property settings.
        """
        self.global_property = global_property

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrestoEnginePropertiesGlobal':
        """Initialize a PrestoEnginePropertiesGlobal object from a json dictionary."""
        args = {}
        if (global_property := _dict.get('global_property')) is not None:
            args['global_property'] = global_property
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrestoEnginePropertiesGlobal object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'global_property') and self.global_property is not None:
            _dict['global_property'] = self.global_property
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PrestoEnginePropertiesGlobal object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PrestoEnginePropertiesGlobal') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PrestoEnginePropertiesGlobal') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class PreviewIngestionFile:
    """
    Schema of the data in the source file.

    :param List[str] column_names: Array of column names of the table.
    :param List[str] column_types: Array of column types of the table.
    :param str file_name: Name of the file being previewed.
    :param PreviewIngestionFileRows rows: First 10 rows of the table.
    """

    def __init__(
        self,
        column_names: List[str],
        column_types: List[str],
        file_name: str,
        rows: 'PreviewIngestionFileRows',
    ) -> None:
        """
        Initialize a PreviewIngestionFile object.

        :param List[str] column_names: Array of column names of the table.
        :param List[str] column_types: Array of column types of the table.
        :param str file_name: Name of the file being previewed.
        :param PreviewIngestionFileRows rows: First 10 rows of the table.
        """
        self.column_names = column_names
        self.column_types = column_types
        self.file_name = file_name
        self.rows = rows

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PreviewIngestionFile':
        """Initialize a PreviewIngestionFile object from a json dictionary."""
        args = {}
        if (column_names := _dict.get('column_names')) is not None:
            args['column_names'] = column_names
        else:
            raise ValueError('Required property \'column_names\' not present in PreviewIngestionFile JSON')
        if (column_types := _dict.get('column_types')) is not None:
            args['column_types'] = column_types
        else:
            raise ValueError('Required property \'column_types\' not present in PreviewIngestionFile JSON')
        if (file_name := _dict.get('file_name')) is not None:
            args['file_name'] = file_name
        else:
            raise ValueError('Required property \'file_name\' not present in PreviewIngestionFile JSON')
        if (rows := _dict.get('rows')) is not None:
            args['rows'] = PreviewIngestionFileRows.from_dict(rows)
        else:
            raise ValueError('Required property \'rows\' not present in PreviewIngestionFile JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PreviewIngestionFile object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'column_names') and self.column_names is not None:
            _dict['column_names'] = self.column_names
        if hasattr(self, 'column_types') and self.column_types is not None:
            _dict['column_types'] = self.column_types
        if hasattr(self, 'file_name') and self.file_name is not None:
            _dict['file_name'] = self.file_name
        if hasattr(self, 'rows') and self.rows is not None:
            if isinstance(self.rows, dict):
                _dict['rows'] = self.rows
            else:
                _dict['rows'] = self.rows.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PreviewIngestionFile object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PreviewIngestionFile') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PreviewIngestionFile') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class PreviewIngestionFilePrototypeCsvProperty:
    """
    CSV properties of source file(s).

    :param str encoding: (optional) Encoding used in CSV file.
    :param str escape_character: (optional) Escape character of CSV file.
    :param str field_delimiter: (optional) Field delimiter of CSV file.
    :param bool header: (optional) Identify if header exists in CSV file.
    :param str line_delimiter: (optional) Line delimiter of CSV file.
    """

    def __init__(
        self,
        *,
        encoding: Optional[str] = None,
        escape_character: Optional[str] = None,
        field_delimiter: Optional[str] = None,
        header: Optional[bool] = None,
        line_delimiter: Optional[str] = None,
    ) -> None:
        """
        Initialize a PreviewIngestionFilePrototypeCsvProperty object.

        :param str encoding: (optional) Encoding used in CSV file.
        :param str escape_character: (optional) Escape character of CSV file.
        :param str field_delimiter: (optional) Field delimiter of CSV file.
        :param bool header: (optional) Identify if header exists in CSV file.
        :param str line_delimiter: (optional) Line delimiter of CSV file.
        """
        self.encoding = encoding
        self.escape_character = escape_character
        self.field_delimiter = field_delimiter
        self.header = header
        self.line_delimiter = line_delimiter

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PreviewIngestionFilePrototypeCsvProperty':
        """Initialize a PreviewIngestionFilePrototypeCsvProperty object from a json dictionary."""
        args = {}
        if (encoding := _dict.get('encoding')) is not None:
            args['encoding'] = encoding
        if (escape_character := _dict.get('escape_character')) is not None:
            args['escape_character'] = escape_character
        if (field_delimiter := _dict.get('field_delimiter')) is not None:
            args['field_delimiter'] = field_delimiter
        if (header := _dict.get('header')) is not None:
            args['header'] = header
        if (line_delimiter := _dict.get('line_delimiter')) is not None:
            args['line_delimiter'] = line_delimiter
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PreviewIngestionFilePrototypeCsvProperty object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'encoding') and self.encoding is not None:
            _dict['encoding'] = self.encoding
        if hasattr(self, 'escape_character') and self.escape_character is not None:
            _dict['escape_character'] = self.escape_character
        if hasattr(self, 'field_delimiter') and self.field_delimiter is not None:
            _dict['field_delimiter'] = self.field_delimiter
        if hasattr(self, 'header') and self.header is not None:
            _dict['header'] = self.header
        if hasattr(self, 'line_delimiter') and self.line_delimiter is not None:
            _dict['line_delimiter'] = self.line_delimiter
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PreviewIngestionFilePrototypeCsvProperty object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PreviewIngestionFilePrototypeCsvProperty') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PreviewIngestionFilePrototypeCsvProperty') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class PreviewIngestionFileRows:
    """
    First 10 rows of the table.

    :param List[str] row_eight: (optional) Each rows slice.
    :param List[str] row_five: (optional) Each rows slice.
    :param List[str] row_four: (optional) Each rows slice.
    :param List[str] row_nine: (optional) Each rows slice.
    :param List[str] row_one: (optional) Each rows slice.
    :param List[str] row_seven: (optional) Each rows slice.
    :param List[str] row_six: (optional) Each rows slice.
    :param List[str] row_ten: (optional) Each rows slice.
    :param List[str] row_three: (optional) Each rows slice.
    :param List[str] row_two: (optional) Each rows slice.
    """

    def __init__(
        self,
        *,
        row_eight: Optional[List[str]] = None,
        row_five: Optional[List[str]] = None,
        row_four: Optional[List[str]] = None,
        row_nine: Optional[List[str]] = None,
        row_one: Optional[List[str]] = None,
        row_seven: Optional[List[str]] = None,
        row_six: Optional[List[str]] = None,
        row_ten: Optional[List[str]] = None,
        row_three: Optional[List[str]] = None,
        row_two: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a PreviewIngestionFileRows object.

        :param List[str] row_eight: (optional) Each rows slice.
        :param List[str] row_five: (optional) Each rows slice.
        :param List[str] row_four: (optional) Each rows slice.
        :param List[str] row_nine: (optional) Each rows slice.
        :param List[str] row_one: (optional) Each rows slice.
        :param List[str] row_seven: (optional) Each rows slice.
        :param List[str] row_six: (optional) Each rows slice.
        :param List[str] row_ten: (optional) Each rows slice.
        :param List[str] row_three: (optional) Each rows slice.
        :param List[str] row_two: (optional) Each rows slice.
        """
        self.row_eight = row_eight
        self.row_five = row_five
        self.row_four = row_four
        self.row_nine = row_nine
        self.row_one = row_one
        self.row_seven = row_seven
        self.row_six = row_six
        self.row_ten = row_ten
        self.row_three = row_three
        self.row_two = row_two

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PreviewIngestionFileRows':
        """Initialize a PreviewIngestionFileRows object from a json dictionary."""
        args = {}
        if (row_eight := _dict.get('row_eight')) is not None:
            args['row_eight'] = row_eight
        if (row_five := _dict.get('row_five')) is not None:
            args['row_five'] = row_five
        if (row_four := _dict.get('row_four')) is not None:
            args['row_four'] = row_four
        if (row_nine := _dict.get('row_nine')) is not None:
            args['row_nine'] = row_nine
        if (row_one := _dict.get('row_one')) is not None:
            args['row_one'] = row_one
        if (row_seven := _dict.get('row_seven')) is not None:
            args['row_seven'] = row_seven
        if (row_six := _dict.get('row_six')) is not None:
            args['row_six'] = row_six
        if (row_ten := _dict.get('row_ten')) is not None:
            args['row_ten'] = row_ten
        if (row_three := _dict.get('row_three')) is not None:
            args['row_three'] = row_three
        if (row_two := _dict.get('row_two')) is not None:
            args['row_two'] = row_two
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PreviewIngestionFileRows object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'row_eight') and self.row_eight is not None:
            _dict['row_eight'] = self.row_eight
        if hasattr(self, 'row_five') and self.row_five is not None:
            _dict['row_five'] = self.row_five
        if hasattr(self, 'row_four') and self.row_four is not None:
            _dict['row_four'] = self.row_four
        if hasattr(self, 'row_nine') and self.row_nine is not None:
            _dict['row_nine'] = self.row_nine
        if hasattr(self, 'row_one') and self.row_one is not None:
            _dict['row_one'] = self.row_one
        if hasattr(self, 'row_seven') and self.row_seven is not None:
            _dict['row_seven'] = self.row_seven
        if hasattr(self, 'row_six') and self.row_six is not None:
            _dict['row_six'] = self.row_six
        if hasattr(self, 'row_ten') and self.row_ten is not None:
            _dict['row_ten'] = self.row_ten
        if hasattr(self, 'row_three') and self.row_three is not None:
            _dict['row_three'] = self.row_three
        if hasattr(self, 'row_two') and self.row_two is not None:
            _dict['row_two'] = self.row_two
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PreviewIngestionFileRows object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PreviewIngestionFileRows') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PreviewIngestionFileRows') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class RemoveEngineProperties:
    """
    RemoveEngine properties.

    :param PrestissimoEnginePropertiesCatalog catalog: (optional) Catalog settings.
    :param RemoveEnginePropertiesConfiguration configuration: (optional) remove
          engine properties configuration.
    :param RemoveEnginePropertiesPrestissimoOaiGenJvm jvm: (optional) JVM
          properties.
    :param List[str] velox: (optional) velox description.
    """

    def __init__(
        self,
        *,
        catalog: Optional['PrestissimoEnginePropertiesCatalog'] = None,
        configuration: Optional['RemoveEnginePropertiesConfiguration'] = None,
        jvm: Optional['RemoveEnginePropertiesPrestissimoOaiGenJvm'] = None,
        velox: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a RemoveEngineProperties object.

        :param PrestissimoEnginePropertiesCatalog catalog: (optional) Catalog
               settings.
        :param RemoveEnginePropertiesConfiguration configuration: (optional) remove
               engine properties configuration.
        :param RemoveEnginePropertiesPrestissimoOaiGenJvm jvm: (optional) JVM
               properties.
        :param List[str] velox: (optional) velox description.
        """
        self.catalog = catalog
        self.configuration = configuration
        self.jvm = jvm
        self.velox = velox

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RemoveEngineProperties':
        """Initialize a RemoveEngineProperties object from a json dictionary."""
        args = {}
        if (catalog := _dict.get('catalog')) is not None:
            args['catalog'] = PrestissimoEnginePropertiesCatalog.from_dict(catalog)
        if (configuration := _dict.get('configuration')) is not None:
            args['configuration'] = RemoveEnginePropertiesConfiguration.from_dict(configuration)
        if (jvm := _dict.get('jvm')) is not None:
            args['jvm'] = RemoveEnginePropertiesPrestissimoOaiGenJvm.from_dict(jvm)
        if (velox := _dict.get('velox')) is not None:
            args['velox'] = velox
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RemoveEngineProperties object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'catalog') and self.catalog is not None:
            if isinstance(self.catalog, dict):
                _dict['catalog'] = self.catalog
            else:
                _dict['catalog'] = self.catalog.to_dict()
        if hasattr(self, 'configuration') and self.configuration is not None:
            if isinstance(self.configuration, dict):
                _dict['configuration'] = self.configuration
            else:
                _dict['configuration'] = self.configuration.to_dict()
        if hasattr(self, 'jvm') and self.jvm is not None:
            if isinstance(self.jvm, dict):
                _dict['jvm'] = self.jvm
            else:
                _dict['jvm'] = self.jvm.to_dict()
        if hasattr(self, 'velox') and self.velox is not None:
            _dict['velox'] = self.velox
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RemoveEngineProperties object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RemoveEngineProperties') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RemoveEngineProperties') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class RemoveEnginePropertiesConfiguration:
    """
    remove engine properties configuration.

    :param List[str] coordinator: (optional) description for coordinator property.
    :param List[str] worker: (optional) description for worker property.
    """

    def __init__(
        self,
        *,
        coordinator: Optional[List[str]] = None,
        worker: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a RemoveEnginePropertiesConfiguration object.

        :param List[str] coordinator: (optional) description for coordinator
               property.
        :param List[str] worker: (optional) description for worker property.
        """
        self.coordinator = coordinator
        self.worker = worker

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RemoveEnginePropertiesConfiguration':
        """Initialize a RemoveEnginePropertiesConfiguration object from a json dictionary."""
        args = {}
        if (coordinator := _dict.get('coordinator')) is not None:
            args['coordinator'] = coordinator
        if (worker := _dict.get('worker')) is not None:
            args['worker'] = worker
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RemoveEnginePropertiesConfiguration object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'coordinator') and self.coordinator is not None:
            _dict['coordinator'] = self.coordinator
        if hasattr(self, 'worker') and self.worker is not None:
            _dict['worker'] = self.worker
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RemoveEnginePropertiesConfiguration object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RemoveEnginePropertiesConfiguration') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RemoveEnginePropertiesConfiguration') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class RemoveEnginePropertiesOaiGenConfiguration:
    """
    Configuration settings for removing engine properties.

    :param List[str] coordinator: (optional) List of coordinator properties.
    :param List[str] worker: (optional) List of worker properties.
    """

    def __init__(
        self,
        *,
        coordinator: Optional[List[str]] = None,
        worker: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a RemoveEnginePropertiesOaiGenConfiguration object.

        :param List[str] coordinator: (optional) List of coordinator properties.
        :param List[str] worker: (optional) List of worker properties.
        """
        self.coordinator = coordinator
        self.worker = worker

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RemoveEnginePropertiesOaiGenConfiguration':
        """Initialize a RemoveEnginePropertiesOaiGenConfiguration object from a json dictionary."""
        args = {}
        if (coordinator := _dict.get('coordinator')) is not None:
            args['coordinator'] = coordinator
        if (worker := _dict.get('worker')) is not None:
            args['worker'] = worker
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RemoveEnginePropertiesOaiGenConfiguration object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'coordinator') and self.coordinator is not None:
            _dict['coordinator'] = self.coordinator
        if hasattr(self, 'worker') and self.worker is not None:
            _dict['worker'] = self.worker
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RemoveEnginePropertiesOaiGenConfiguration object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RemoveEnginePropertiesOaiGenConfiguration') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RemoveEnginePropertiesOaiGenConfiguration') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class RemoveEnginePropertiesOaiGenJvm:
    """
    JVM properties.

    :param List[str] coordinator: (optional) List of coordinator properties.
    :param List[str] worker: (optional) List of worker properties.
    """

    def __init__(
        self,
        *,
        coordinator: Optional[List[str]] = None,
        worker: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a RemoveEnginePropertiesOaiGenJvm object.

        :param List[str] coordinator: (optional) List of coordinator properties.
        :param List[str] worker: (optional) List of worker properties.
        """
        self.coordinator = coordinator
        self.worker = worker

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RemoveEnginePropertiesOaiGenJvm':
        """Initialize a RemoveEnginePropertiesOaiGenJvm object from a json dictionary."""
        args = {}
        if (coordinator := _dict.get('coordinator')) is not None:
            args['coordinator'] = coordinator
        if (worker := _dict.get('worker')) is not None:
            args['worker'] = worker
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RemoveEnginePropertiesOaiGenJvm object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'coordinator') and self.coordinator is not None:
            _dict['coordinator'] = self.coordinator
        if hasattr(self, 'worker') and self.worker is not None:
            _dict['worker'] = self.worker
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RemoveEnginePropertiesOaiGenJvm object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RemoveEnginePropertiesOaiGenJvm') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RemoveEnginePropertiesOaiGenJvm') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class RemoveEnginePropertiesPrestissimoOaiGenJvm:
    """
    JVM properties.

    :param List[str] coordinator: (optional) List of coordinator properties.
    """

    def __init__(
        self,
        *,
        coordinator: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a RemoveEnginePropertiesPrestissimoOaiGenJvm object.

        :param List[str] coordinator: (optional) List of coordinator properties.
        """
        self.coordinator = coordinator

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RemoveEnginePropertiesPrestissimoOaiGenJvm':
        """Initialize a RemoveEnginePropertiesPrestissimoOaiGenJvm object from a json dictionary."""
        args = {}
        if (coordinator := _dict.get('coordinator')) is not None:
            args['coordinator'] = coordinator
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RemoveEnginePropertiesPrestissimoOaiGenJvm object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'coordinator') and self.coordinator is not None:
            _dict['coordinator'] = self.coordinator
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RemoveEnginePropertiesPrestissimoOaiGenJvm object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RemoveEnginePropertiesPrestissimoOaiGenJvm') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RemoveEnginePropertiesPrestissimoOaiGenJvm') -> bool:
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
        if (response := _dict.get('response')) is not None:
            args['response'] = SuccessResponse.from_dict(response)
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


class ResultExecuteQuery:
    """
    ResultExecuteQuery OK.

    :param List[dict] result: (optional) Query result in JSON format.
    """

    def __init__(
        self,
        *,
        result: Optional[List[dict]] = None,
    ) -> None:
        """
        Initialize a ResultExecuteQuery object.

        :param List[dict] result: (optional) Query result in JSON format.
        """
        self.result = result

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ResultExecuteQuery':
        """Initialize a ResultExecuteQuery object from a json dictionary."""
        args = {}
        if (result := _dict.get('result')) is not None:
            args['result'] = result
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ResultExecuteQuery object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'result') and self.result is not None:
            _dict['result'] = self.result
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ResultExecuteQuery object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ResultExecuteQuery') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ResultExecuteQuery') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ResultPrestissimoExplainStatement:
    """
    ExplainStatement OK.

    :param str result: (optional) Result.
    """

    def __init__(
        self,
        *,
        result: Optional[str] = None,
    ) -> None:
        """
        Initialize a ResultPrestissimoExplainStatement object.

        :param str result: (optional) Result.
        """
        self.result = result

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ResultPrestissimoExplainStatement':
        """Initialize a ResultPrestissimoExplainStatement object from a json dictionary."""
        args = {}
        if (result := _dict.get('result')) is not None:
            args['result'] = result
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ResultPrestissimoExplainStatement object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'result') and self.result is not None:
            _dict['result'] = self.result
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ResultPrestissimoExplainStatement object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ResultPrestissimoExplainStatement') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ResultPrestissimoExplainStatement') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ResultRunPrestissimoExplainAnalyzeStatement:
    """
    explainAnalyzeStatement OK.

    :param str result: (optional) explainAnalyzeStatement result.
    """

    def __init__(
        self,
        *,
        result: Optional[str] = None,
    ) -> None:
        """
        Initialize a ResultRunPrestissimoExplainAnalyzeStatement object.

        :param str result: (optional) explainAnalyzeStatement result.
        """
        self.result = result

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ResultRunPrestissimoExplainAnalyzeStatement':
        """Initialize a ResultRunPrestissimoExplainAnalyzeStatement object from a json dictionary."""
        args = {}
        if (result := _dict.get('result')) is not None:
            args['result'] = result
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ResultRunPrestissimoExplainAnalyzeStatement object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'result') and self.result is not None:
            _dict['result'] = self.result
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ResultRunPrestissimoExplainAnalyzeStatement object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ResultRunPrestissimoExplainAnalyzeStatement') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ResultRunPrestissimoExplainAnalyzeStatement') -> bool:
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
        if (response := _dict.get('response')) is not None:
            args['response'] = SuccessResponse.from_dict(response)
        else:
            raise ValueError('Required property \'response\' not present in RunExplainAnalyzeStatementOKBody JSON')
        if (result := _dict.get('result')) is not None:
            args['result'] = result
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
        if (response := _dict.get('response')) is not None:
            args['response'] = SuccessResponse.from_dict(response)
        else:
            raise ValueError('Required property \'response\' not present in RunExplainStatementOKBody JSON')
        if (result := _dict.get('result')) is not None:
            args['result'] = result
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


class SalIntegration:
    """
    Sal Integration object.

    :param str category_id: (optional) category UUID.
    :param str engine_id: (optional) engine id.
    :param List[ErrorObj] errors: (optional) errors.
    :param str governance_scope_id: (optional) governance scope UUID.
    :param str governance_scope_type: (optional) governance scope type.
    :param str instance_id: (optional) instance_id.
    :param str status: (optional) status of the integration.
    :param str storage_resource_crn: (optional) COS resource CRN.
    :param str storage_type: (optional) COS storage type.
    :param str timestamp: (optional) sal integration creation timestamp.
    :param bool trial_plan: (optional) whether the integration is trial plan.
    :param str username: (optional) user name.
    """

    def __init__(
        self,
        *,
        category_id: Optional[str] = None,
        engine_id: Optional[str] = None,
        errors: Optional[List['ErrorObj']] = None,
        governance_scope_id: Optional[str] = None,
        governance_scope_type: Optional[str] = None,
        instance_id: Optional[str] = None,
        status: Optional[str] = None,
        storage_resource_crn: Optional[str] = None,
        storage_type: Optional[str] = None,
        timestamp: Optional[str] = None,
        trial_plan: Optional[bool] = None,
        username: Optional[str] = None,
    ) -> None:
        """
        Initialize a SalIntegration object.

        :param str category_id: (optional) category UUID.
        :param str engine_id: (optional) engine id.
        :param List[ErrorObj] errors: (optional) errors.
        :param str governance_scope_id: (optional) governance scope UUID.
        :param str governance_scope_type: (optional) governance scope type.
        :param str instance_id: (optional) instance_id.
        :param str status: (optional) status of the integration.
        :param str storage_resource_crn: (optional) COS resource CRN.
        :param str storage_type: (optional) COS storage type.
        :param str timestamp: (optional) sal integration creation timestamp.
        :param bool trial_plan: (optional) whether the integration is trial plan.
        :param str username: (optional) user name.
        """
        self.category_id = category_id
        self.engine_id = engine_id
        self.errors = errors
        self.governance_scope_id = governance_scope_id
        self.governance_scope_type = governance_scope_type
        self.instance_id = instance_id
        self.status = status
        self.storage_resource_crn = storage_resource_crn
        self.storage_type = storage_type
        self.timestamp = timestamp
        self.trial_plan = trial_plan
        self.username = username

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SalIntegration':
        """Initialize a SalIntegration object from a json dictionary."""
        args = {}
        if (category_id := _dict.get('category_id')) is not None:
            args['category_id'] = category_id
        if (engine_id := _dict.get('engine_id')) is not None:
            args['engine_id'] = engine_id
        if (errors := _dict.get('errors')) is not None:
            args['errors'] = [ErrorObj.from_dict(v) for v in errors]
        if (governance_scope_id := _dict.get('governance_scope_id')) is not None:
            args['governance_scope_id'] = governance_scope_id
        if (governance_scope_type := _dict.get('governance_scope_type')) is not None:
            args['governance_scope_type'] = governance_scope_type
        if (instance_id := _dict.get('instance_id')) is not None:
            args['instance_id'] = instance_id
        if (status := _dict.get('status')) is not None:
            args['status'] = status
        if (storage_resource_crn := _dict.get('storage_resource_crn')) is not None:
            args['storage_resource_crn'] = storage_resource_crn
        if (storage_type := _dict.get('storage_type')) is not None:
            args['storage_type'] = storage_type
        if (timestamp := _dict.get('timestamp')) is not None:
            args['timestamp'] = timestamp
        if (trial_plan := _dict.get('trial_plan')) is not None:
            args['trial_plan'] = trial_plan
        if (username := _dict.get('username')) is not None:
            args['username'] = username
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SalIntegration object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'category_id') and self.category_id is not None:
            _dict['category_id'] = self.category_id
        if hasattr(self, 'engine_id') and self.engine_id is not None:
            _dict['engine_id'] = self.engine_id
        if hasattr(self, 'errors') and self.errors is not None:
            errors_list = []
            for v in self.errors:
                if isinstance(v, dict):
                    errors_list.append(v)
                else:
                    errors_list.append(v.to_dict())
            _dict['errors'] = errors_list
        if hasattr(self, 'governance_scope_id') and self.governance_scope_id is not None:
            _dict['governance_scope_id'] = self.governance_scope_id
        if hasattr(self, 'governance_scope_type') and self.governance_scope_type is not None:
            _dict['governance_scope_type'] = self.governance_scope_type
        if hasattr(self, 'instance_id') and self.instance_id is not None:
            _dict['instance_id'] = self.instance_id
        if hasattr(self, 'status') and self.status is not None:
            _dict['status'] = self.status
        if hasattr(self, 'storage_resource_crn') and self.storage_resource_crn is not None:
            _dict['storage_resource_crn'] = self.storage_resource_crn
        if hasattr(self, 'storage_type') and self.storage_type is not None:
            _dict['storage_type'] = self.storage_type
        if hasattr(self, 'timestamp') and self.timestamp is not None:
            _dict['timestamp'] = self.timestamp
        if hasattr(self, 'trial_plan') and self.trial_plan is not None:
            _dict['trial_plan'] = self.trial_plan
        if hasattr(self, 'username') and self.username is not None:
            _dict['username'] = self.username
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SalIntegration object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SalIntegration') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SalIntegration') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SalIntegrationEnrichmentAssets:
    """
    sal integration enrichment assets.

    :param EnrichmentAsset enrichment_asset: (optional) Encrichment asset.
    """

    def __init__(
        self,
        *,
        enrichment_asset: Optional['EnrichmentAsset'] = None,
    ) -> None:
        """
        Initialize a SalIntegrationEnrichmentAssets object.

        :param EnrichmentAsset enrichment_asset: (optional) Encrichment asset.
        """
        self.enrichment_asset = enrichment_asset

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SalIntegrationEnrichmentAssets':
        """Initialize a SalIntegrationEnrichmentAssets object from a json dictionary."""
        args = {}
        if (enrichment_asset := _dict.get('enrichment_asset')) is not None:
            args['enrichment_asset'] = EnrichmentAsset.from_dict(enrichment_asset)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SalIntegrationEnrichmentAssets object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'enrichment_asset') and self.enrichment_asset is not None:
            if isinstance(self.enrichment_asset, dict):
                _dict['enrichment_asset'] = self.enrichment_asset
            else:
                _dict['enrichment_asset'] = self.enrichment_asset.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SalIntegrationEnrichmentAssets object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SalIntegrationEnrichmentAssets') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SalIntegrationEnrichmentAssets') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SalIntegrationEnrichmentDataAsset:
    """
    semantic enrichment data asset.

    :param str asset: (optional) name.
    """

    def __init__(
        self,
        *,
        asset: Optional[str] = None,
    ) -> None:
        """
        Initialize a SalIntegrationEnrichmentDataAsset object.

        :param str asset: (optional) name.
        """
        self.asset = asset

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SalIntegrationEnrichmentDataAsset':
        """Initialize a SalIntegrationEnrichmentDataAsset object from a json dictionary."""
        args = {}
        if (asset := _dict.get('asset')) is not None:
            args['asset'] = asset
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SalIntegrationEnrichmentDataAsset object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'asset') and self.asset is not None:
            _dict['asset'] = self.asset
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SalIntegrationEnrichmentDataAsset object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SalIntegrationEnrichmentDataAsset') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SalIntegrationEnrichmentDataAsset') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SalIntegrationEnrichmentJobRun:
    """
    semantic enrichment job run.

    :param str response: (optional) job run response.
    """

    def __init__(
        self,
        *,
        response: Optional[str] = None,
    ) -> None:
        """
        Initialize a SalIntegrationEnrichmentJobRun object.

        :param str response: (optional) job run response.
        """
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SalIntegrationEnrichmentJobRun':
        """Initialize a SalIntegrationEnrichmentJobRun object from a json dictionary."""
        args = {}
        if (response := _dict.get('response')) is not None:
            args['response'] = response
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SalIntegrationEnrichmentJobRun object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'response') and self.response is not None:
            _dict['response'] = self.response
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SalIntegrationEnrichmentJobRun object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SalIntegrationEnrichmentJobRun') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SalIntegrationEnrichmentJobRun') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SalIntegrationEnrichmentJobRunLogs:
    """
    semantic enrichment job run logs.

    :param List[str] results: (optional) results.
    :param int total_count: (optional) name.
    """

    def __init__(
        self,
        *,
        results: Optional[List[str]] = None,
        total_count: Optional[int] = None,
    ) -> None:
        """
        Initialize a SalIntegrationEnrichmentJobRunLogs object.

        :param List[str] results: (optional) results.
        :param int total_count: (optional) name.
        """
        self.results = results
        self.total_count = total_count

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SalIntegrationEnrichmentJobRunLogs':
        """Initialize a SalIntegrationEnrichmentJobRunLogs object from a json dictionary."""
        args = {}
        if (results := _dict.get('results')) is not None:
            args['results'] = results
        if (total_count := _dict.get('total_count')) is not None:
            args['total_count'] = total_count
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SalIntegrationEnrichmentJobRunLogs object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'results') and self.results is not None:
            _dict['results'] = self.results
        if hasattr(self, 'total_count') and self.total_count is not None:
            _dict['total_count'] = self.total_count
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SalIntegrationEnrichmentJobRunLogs object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SalIntegrationEnrichmentJobRunLogs') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SalIntegrationEnrichmentJobRunLogs') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SalIntegrationEnrichmentJobs:
    """
    Sal Integration Mappings object.

    :param SalIntegrationEnrichmentJobsProperties jobs: (optional) catalog name.
    """

    def __init__(
        self,
        *,
        jobs: Optional['SalIntegrationEnrichmentJobsProperties'] = None,
    ) -> None:
        """
        Initialize a SalIntegrationEnrichmentJobs object.

        :param SalIntegrationEnrichmentJobsProperties jobs: (optional) catalog
               name.
        """
        self.jobs = jobs

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SalIntegrationEnrichmentJobs':
        """Initialize a SalIntegrationEnrichmentJobs object from a json dictionary."""
        args = {}
        if (jobs := _dict.get('jobs')) is not None:
            args['jobs'] = SalIntegrationEnrichmentJobsProperties.from_dict(jobs)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SalIntegrationEnrichmentJobs object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'jobs') and self.jobs is not None:
            if isinstance(self.jobs, dict):
                _dict['jobs'] = self.jobs
            else:
                _dict['jobs'] = self.jobs.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SalIntegrationEnrichmentJobs object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SalIntegrationEnrichmentJobs') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SalIntegrationEnrichmentJobs') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SalIntegrationEnrichmentJobsProperties:
    """
    catalog name.

    :param List[SalIntegrationEnrichmentJobsResultItem] results: (optional) Array of
          result items.
    :param int total_rows: (optional) Total number of rows.
    """

    def __init__(
        self,
        *,
        results: Optional[List['SalIntegrationEnrichmentJobsResultItem']] = None,
        total_rows: Optional[int] = None,
    ) -> None:
        """
        Initialize a SalIntegrationEnrichmentJobsProperties object.

        :param List[SalIntegrationEnrichmentJobsResultItem] results: (optional)
               Array of result items.
        :param int total_rows: (optional) Total number of rows.
        """
        self.results = results
        self.total_rows = total_rows

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SalIntegrationEnrichmentJobsProperties':
        """Initialize a SalIntegrationEnrichmentJobsProperties object from a json dictionary."""
        args = {}
        if (results := _dict.get('results')) is not None:
            args['results'] = [SalIntegrationEnrichmentJobsResultItem.from_dict(v) for v in results]
        if (total_rows := _dict.get('total_rows')) is not None:
            args['total_rows'] = total_rows
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SalIntegrationEnrichmentJobsProperties object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'results') and self.results is not None:
            results_list = []
            for v in self.results:
                if isinstance(v, dict):
                    results_list.append(v)
                else:
                    results_list.append(v.to_dict())
            _dict['results'] = results_list
        if hasattr(self, 'total_rows') and self.total_rows is not None:
            _dict['total_rows'] = self.total_rows
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SalIntegrationEnrichmentJobsProperties object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SalIntegrationEnrichmentJobsProperties') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SalIntegrationEnrichmentJobsProperties') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SalIntegrationEnrichmentJobsResultItem:
    """
    A single result item containing entity and metadata.

    :param SalIntegrationEnrichmentJobsResultItemEntity entity: (optional) Entity
          details including job information.
    :param SalIntegrationEnrichmentJobsResultItemMetadata metadata: (optional)
          Metadata information about the job.
    """

    def __init__(
        self,
        *,
        entity: Optional['SalIntegrationEnrichmentJobsResultItemEntity'] = None,
        metadata: Optional['SalIntegrationEnrichmentJobsResultItemMetadata'] = None,
    ) -> None:
        """
        Initialize a SalIntegrationEnrichmentJobsResultItem object.

        :param SalIntegrationEnrichmentJobsResultItemEntity entity: (optional)
               Entity details including job information.
        :param SalIntegrationEnrichmentJobsResultItemMetadata metadata: (optional)
               Metadata information about the job.
        """
        self.entity = entity
        self.metadata = metadata

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SalIntegrationEnrichmentJobsResultItem':
        """Initialize a SalIntegrationEnrichmentJobsResultItem object from a json dictionary."""
        args = {}
        if (entity := _dict.get('entity')) is not None:
            args['entity'] = SalIntegrationEnrichmentJobsResultItemEntity.from_dict(entity)
        if (metadata := _dict.get('metadata')) is not None:
            args['metadata'] = SalIntegrationEnrichmentJobsResultItemMetadata.from_dict(metadata)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SalIntegrationEnrichmentJobsResultItem object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'entity') and self.entity is not None:
            if isinstance(self.entity, dict):
                _dict['entity'] = self.entity
            else:
                _dict['entity'] = self.entity.to_dict()
        if hasattr(self, 'metadata') and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict['metadata'] = self.metadata
            else:
                _dict['metadata'] = self.metadata.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SalIntegrationEnrichmentJobsResultItem object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SalIntegrationEnrichmentJobsResultItem') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SalIntegrationEnrichmentJobsResultItem') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SalIntegrationEnrichmentJobsResultItemEntity:
    """
    Entity details including job information.

    :param SalIntegrationEnrichmentJobsResultItemEntityJob job: (optional) Details
          about the job.
    """

    def __init__(
        self,
        *,
        job: Optional['SalIntegrationEnrichmentJobsResultItemEntityJob'] = None,
    ) -> None:
        """
        Initialize a SalIntegrationEnrichmentJobsResultItemEntity object.

        :param SalIntegrationEnrichmentJobsResultItemEntityJob job: (optional)
               Details about the job.
        """
        self.job = job

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SalIntegrationEnrichmentJobsResultItemEntity':
        """Initialize a SalIntegrationEnrichmentJobsResultItemEntity object from a json dictionary."""
        args = {}
        if (job := _dict.get('job')) is not None:
            args['job'] = SalIntegrationEnrichmentJobsResultItemEntityJob.from_dict(job)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SalIntegrationEnrichmentJobsResultItemEntity object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'job') and self.job is not None:
            if isinstance(self.job, dict):
                _dict['job'] = self.job
            else:
                _dict['job'] = self.job.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SalIntegrationEnrichmentJobsResultItemEntity object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SalIntegrationEnrichmentJobsResultItemEntity') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SalIntegrationEnrichmentJobsResultItemEntity') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SalIntegrationEnrichmentJobsResultItemEntityJob:
    """
    Details about the job.

    :param str asset_ref: (optional) Reference ID for the asset.
    :param str asset_ref_type: (optional) Type of the asset reference.
    :param SalIntegrationEnrichmentJobsResultItemEntityJobConfiguration
          configuration: (optional) Configuration settings for the job.
    :param bool enable_notifications: (optional) Flag indicating if notifications
          are enabled for the job.
    :param List[str] future_scheduled_runs: (optional) List of future scheduled run
          times.
    :param str last_run_initiator: (optional) Initiator of the last run.
    :param str last_run_status: (optional) Status of the last run.
    :param int last_run_status_timestamp: (optional) Timestamp of the last run
          status.
    :param str last_run_time: (optional) Time of the last run.
    :param str project_name: (optional) Name of the project associated with the job.
    :param str schedule_creator_id: (optional) ID of the creator of the schedule.
    :param str schedule_id: (optional) ID of the schedule.
    :param ScheduleInfo schedule_info: (optional) Information about the schedule.
    :param SalIntegrationEnrichmentJobsResultItemEntityTaskCredentialsSupport
          task_credentials_support: (optional) Credentials support information for the
          task.
    """

    def __init__(
        self,
        *,
        asset_ref: Optional[str] = None,
        asset_ref_type: Optional[str] = None,
        configuration: Optional['SalIntegrationEnrichmentJobsResultItemEntityJobConfiguration'] = None,
        enable_notifications: Optional[bool] = None,
        future_scheduled_runs: Optional[List[str]] = None,
        last_run_initiator: Optional[str] = None,
        last_run_status: Optional[str] = None,
        last_run_status_timestamp: Optional[int] = None,
        last_run_time: Optional[str] = None,
        project_name: Optional[str] = None,
        schedule_creator_id: Optional[str] = None,
        schedule_id: Optional[str] = None,
        schedule_info: Optional['ScheduleInfo'] = None,
        task_credentials_support: Optional['SalIntegrationEnrichmentJobsResultItemEntityTaskCredentialsSupport'] = None,
    ) -> None:
        """
        Initialize a SalIntegrationEnrichmentJobsResultItemEntityJob object.

        :param str asset_ref: (optional) Reference ID for the asset.
        :param str asset_ref_type: (optional) Type of the asset reference.
        :param SalIntegrationEnrichmentJobsResultItemEntityJobConfiguration
               configuration: (optional) Configuration settings for the job.
        :param bool enable_notifications: (optional) Flag indicating if
               notifications are enabled for the job.
        :param List[str] future_scheduled_runs: (optional) List of future scheduled
               run times.
        :param str last_run_initiator: (optional) Initiator of the last run.
        :param str last_run_status: (optional) Status of the last run.
        :param int last_run_status_timestamp: (optional) Timestamp of the last run
               status.
        :param str last_run_time: (optional) Time of the last run.
        :param str project_name: (optional) Name of the project associated with the
               job.
        :param str schedule_creator_id: (optional) ID of the creator of the
               schedule.
        :param str schedule_id: (optional) ID of the schedule.
        :param ScheduleInfo schedule_info: (optional) Information about the
               schedule.
        :param SalIntegrationEnrichmentJobsResultItemEntityTaskCredentialsSupport
               task_credentials_support: (optional) Credentials support information for
               the task.
        """
        self.asset_ref = asset_ref
        self.asset_ref_type = asset_ref_type
        self.configuration = configuration
        self.enable_notifications = enable_notifications
        self.future_scheduled_runs = future_scheduled_runs
        self.last_run_initiator = last_run_initiator
        self.last_run_status = last_run_status
        self.last_run_status_timestamp = last_run_status_timestamp
        self.last_run_time = last_run_time
        self.project_name = project_name
        self.schedule_creator_id = schedule_creator_id
        self.schedule_id = schedule_id
        self.schedule_info = schedule_info
        self.task_credentials_support = task_credentials_support

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SalIntegrationEnrichmentJobsResultItemEntityJob':
        """Initialize a SalIntegrationEnrichmentJobsResultItemEntityJob object from a json dictionary."""
        args = {}
        if (asset_ref := _dict.get('asset_ref')) is not None:
            args['asset_ref'] = asset_ref
        if (asset_ref_type := _dict.get('asset_ref_type')) is not None:
            args['asset_ref_type'] = asset_ref_type
        if (configuration := _dict.get('configuration')) is not None:
            args['configuration'] = SalIntegrationEnrichmentJobsResultItemEntityJobConfiguration.from_dict(configuration)
        if (enable_notifications := _dict.get('enable_notifications')) is not None:
            args['enable_notifications'] = enable_notifications
        if (future_scheduled_runs := _dict.get('future_scheduled_runs')) is not None:
            args['future_scheduled_runs'] = future_scheduled_runs
        if (last_run_initiator := _dict.get('last_run_initiator')) is not None:
            args['last_run_initiator'] = last_run_initiator
        if (last_run_status := _dict.get('last_run_status')) is not None:
            args['last_run_status'] = last_run_status
        if (last_run_status_timestamp := _dict.get('last_run_status_timestamp')) is not None:
            args['last_run_status_timestamp'] = last_run_status_timestamp
        if (last_run_time := _dict.get('last_run_time')) is not None:
            args['last_run_time'] = last_run_time
        if (project_name := _dict.get('project_name')) is not None:
            args['project_name'] = project_name
        if (schedule_creator_id := _dict.get('schedule_creator_id')) is not None:
            args['schedule_creator_id'] = schedule_creator_id
        if (schedule_id := _dict.get('schedule_id')) is not None:
            args['schedule_id'] = schedule_id
        if (schedule_info := _dict.get('schedule_info')) is not None:
            args['schedule_info'] = ScheduleInfo.from_dict(schedule_info)
        if (task_credentials_support := _dict.get('task_credentials_support')) is not None:
            args['task_credentials_support'] = SalIntegrationEnrichmentJobsResultItemEntityTaskCredentialsSupport.from_dict(task_credentials_support)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SalIntegrationEnrichmentJobsResultItemEntityJob object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'asset_ref') and self.asset_ref is not None:
            _dict['asset_ref'] = self.asset_ref
        if hasattr(self, 'asset_ref_type') and self.asset_ref_type is not None:
            _dict['asset_ref_type'] = self.asset_ref_type
        if hasattr(self, 'configuration') and self.configuration is not None:
            if isinstance(self.configuration, dict):
                _dict['configuration'] = self.configuration
            else:
                _dict['configuration'] = self.configuration.to_dict()
        if hasattr(self, 'enable_notifications') and self.enable_notifications is not None:
            _dict['enable_notifications'] = self.enable_notifications
        if hasattr(self, 'future_scheduled_runs') and self.future_scheduled_runs is not None:
            _dict['future_scheduled_runs'] = self.future_scheduled_runs
        if hasattr(self, 'last_run_initiator') and self.last_run_initiator is not None:
            _dict['last_run_initiator'] = self.last_run_initiator
        if hasattr(self, 'last_run_status') and self.last_run_status is not None:
            _dict['last_run_status'] = self.last_run_status
        if hasattr(self, 'last_run_status_timestamp') and self.last_run_status_timestamp is not None:
            _dict['last_run_status_timestamp'] = self.last_run_status_timestamp
        if hasattr(self, 'last_run_time') and self.last_run_time is not None:
            _dict['last_run_time'] = self.last_run_time
        if hasattr(self, 'project_name') and self.project_name is not None:
            _dict['project_name'] = self.project_name
        if hasattr(self, 'schedule_creator_id') and self.schedule_creator_id is not None:
            _dict['schedule_creator_id'] = self.schedule_creator_id
        if hasattr(self, 'schedule_id') and self.schedule_id is not None:
            _dict['schedule_id'] = self.schedule_id
        if hasattr(self, 'schedule_info') and self.schedule_info is not None:
            if isinstance(self.schedule_info, dict):
                _dict['schedule_info'] = self.schedule_info
            else:
                _dict['schedule_info'] = self.schedule_info.to_dict()
        if hasattr(self, 'task_credentials_support') and self.task_credentials_support is not None:
            if isinstance(self.task_credentials_support, dict):
                _dict['task_credentials_support'] = self.task_credentials_support
            else:
                _dict['task_credentials_support'] = self.task_credentials_support.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SalIntegrationEnrichmentJobsResultItemEntityJob object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SalIntegrationEnrichmentJobsResultItemEntityJob') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SalIntegrationEnrichmentJobsResultItemEntityJob') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SalIntegrationEnrichmentJobsResultItemEntityJobConfiguration:
    """
    Configuration settings for the job.

    :param str env_type: (optional) The environment type.
    :param List[str] env_variables: (optional) Environment variables for the job.
    """

    def __init__(
        self,
        *,
        env_type: Optional[str] = None,
        env_variables: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a SalIntegrationEnrichmentJobsResultItemEntityJobConfiguration object.

        :param str env_type: (optional) The environment type.
        :param List[str] env_variables: (optional) Environment variables for the
               job.
        """
        self.env_type = env_type
        self.env_variables = env_variables

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SalIntegrationEnrichmentJobsResultItemEntityJobConfiguration':
        """Initialize a SalIntegrationEnrichmentJobsResultItemEntityJobConfiguration object from a json dictionary."""
        args = {}
        if (env_type := _dict.get('env_type')) is not None:
            args['env_type'] = env_type
        if (env_variables := _dict.get('env_variables')) is not None:
            args['env_variables'] = env_variables
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SalIntegrationEnrichmentJobsResultItemEntityJobConfiguration object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'env_type') and self.env_type is not None:
            _dict['env_type'] = self.env_type
        if hasattr(self, 'env_variables') and self.env_variables is not None:
            _dict['env_variables'] = self.env_variables
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SalIntegrationEnrichmentJobsResultItemEntityJobConfiguration object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SalIntegrationEnrichmentJobsResultItemEntityJobConfiguration') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SalIntegrationEnrichmentJobsResultItemEntityJobConfiguration') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SalIntegrationEnrichmentJobsResultItemEntityTaskCredentialsSupport:
    """
    Credentials support information for the task.

    :param str account_id: (optional) The account ID associated with the task.
    :param bool task_credentials_enabled: (optional) Indicates if task credentials
          are enabled.
    :param str user_id: (optional) The user ID associated with the task.
    """

    def __init__(
        self,
        *,
        account_id: Optional[str] = None,
        task_credentials_enabled: Optional[bool] = None,
        user_id: Optional[str] = None,
    ) -> None:
        """
        Initialize a SalIntegrationEnrichmentJobsResultItemEntityTaskCredentialsSupport object.

        :param str account_id: (optional) The account ID associated with the task.
        :param bool task_credentials_enabled: (optional) Indicates if task
               credentials are enabled.
        :param str user_id: (optional) The user ID associated with the task.
        """
        self.account_id = account_id
        self.task_credentials_enabled = task_credentials_enabled
        self.user_id = user_id

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SalIntegrationEnrichmentJobsResultItemEntityTaskCredentialsSupport':
        """Initialize a SalIntegrationEnrichmentJobsResultItemEntityTaskCredentialsSupport object from a json dictionary."""
        args = {}
        if (account_id := _dict.get('account_id')) is not None:
            args['account_id'] = account_id
        if (task_credentials_enabled := _dict.get('task_credentials_enabled')) is not None:
            args['task_credentials_enabled'] = task_credentials_enabled
        if (user_id := _dict.get('user_id')) is not None:
            args['user_id'] = user_id
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SalIntegrationEnrichmentJobsResultItemEntityTaskCredentialsSupport object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'account_id') and self.account_id is not None:
            _dict['account_id'] = self.account_id
        if hasattr(self, 'task_credentials_enabled') and self.task_credentials_enabled is not None:
            _dict['task_credentials_enabled'] = self.task_credentials_enabled
        if hasattr(self, 'user_id') and self.user_id is not None:
            _dict['user_id'] = self.user_id
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SalIntegrationEnrichmentJobsResultItemEntityTaskCredentialsSupport object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SalIntegrationEnrichmentJobsResultItemEntityTaskCredentialsSupport') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SalIntegrationEnrichmentJobsResultItemEntityTaskCredentialsSupport') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SalIntegrationEnrichmentJobsResultItemMetadata:
    """
    Metadata information about the job.

    :param str asset_id: (optional) The ID of the asset.
    :param str name: (optional) Name of the job.
    :param str owner_id: (optional) ID of the owner of the job.
    :param int version: (optional) Version of the job.
    """

    def __init__(
        self,
        *,
        asset_id: Optional[str] = None,
        name: Optional[str] = None,
        owner_id: Optional[str] = None,
        version: Optional[int] = None,
    ) -> None:
        """
        Initialize a SalIntegrationEnrichmentJobsResultItemMetadata object.

        :param str asset_id: (optional) The ID of the asset.
        :param str name: (optional) Name of the job.
        :param str owner_id: (optional) ID of the owner of the job.
        :param int version: (optional) Version of the job.
        """
        self.asset_id = asset_id
        self.name = name
        self.owner_id = owner_id
        self.version = version

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SalIntegrationEnrichmentJobsResultItemMetadata':
        """Initialize a SalIntegrationEnrichmentJobsResultItemMetadata object from a json dictionary."""
        args = {}
        if (asset_id := _dict.get('asset_id')) is not None:
            args['asset_id'] = asset_id
        if (name := _dict.get('name')) is not None:
            args['name'] = name
        if (owner_id := _dict.get('owner_id')) is not None:
            args['owner_id'] = owner_id
        if (version := _dict.get('version')) is not None:
            args['version'] = version
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SalIntegrationEnrichmentJobsResultItemMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'asset_id') and self.asset_id is not None:
            _dict['asset_id'] = self.asset_id
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'owner_id') and self.owner_id is not None:
            _dict['owner_id'] = self.owner_id
        if hasattr(self, 'version') and self.version is not None:
            _dict['version'] = self.version
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SalIntegrationEnrichmentJobsResultItemMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SalIntegrationEnrichmentJobsResultItemMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SalIntegrationEnrichmentJobsResultItemMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SalIntegrationEnrichmentSettings:
    """
    Sal Integration Enrichment Settings objects.

    :param SalIntegrationEnrichmentSettingsSemanticExpansion semantic_expansion:
          (optional) semantic expansion.
    :param SalIntegrationEnrichmentSettingsTermAssignment term_assignment:
          (optional) semantic expansion.
    """

    def __init__(
        self,
        *,
        semantic_expansion: Optional['SalIntegrationEnrichmentSettingsSemanticExpansion'] = None,
        term_assignment: Optional['SalIntegrationEnrichmentSettingsTermAssignment'] = None,
    ) -> None:
        """
        Initialize a SalIntegrationEnrichmentSettings object.

        :param SalIntegrationEnrichmentSettingsSemanticExpansion
               semantic_expansion: (optional) semantic expansion.
        :param SalIntegrationEnrichmentSettingsTermAssignment term_assignment:
               (optional) semantic expansion.
        """
        self.semantic_expansion = semantic_expansion
        self.term_assignment = term_assignment

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SalIntegrationEnrichmentSettings':
        """Initialize a SalIntegrationEnrichmentSettings object from a json dictionary."""
        args = {}
        if (semantic_expansion := _dict.get('semantic_expansion')) is not None:
            args['semantic_expansion'] = SalIntegrationEnrichmentSettingsSemanticExpansion.from_dict(semantic_expansion)
        if (term_assignment := _dict.get('term_assignment')) is not None:
            args['term_assignment'] = SalIntegrationEnrichmentSettingsTermAssignment.from_dict(term_assignment)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SalIntegrationEnrichmentSettings object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'semantic_expansion') and self.semantic_expansion is not None:
            if isinstance(self.semantic_expansion, dict):
                _dict['semantic_expansion'] = self.semantic_expansion
            else:
                _dict['semantic_expansion'] = self.semantic_expansion.to_dict()
        if hasattr(self, 'term_assignment') and self.term_assignment is not None:
            if isinstance(self.term_assignment, dict):
                _dict['term_assignment'] = self.term_assignment
            else:
                _dict['term_assignment'] = self.term_assignment.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SalIntegrationEnrichmentSettings object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SalIntegrationEnrichmentSettings') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SalIntegrationEnrichmentSettings') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SalIntegrationEnrichmentSettingsSemanticExpansion:
    """
    semantic expansion.

    :param bool description_generation: (optional) description generation.
    :param
          SalIntegrationEnrichmentSettingsSemanticExpansionDescriptionGenerationConfiguration
          description_generation_configuration: (optional) description generation
          configuration.
    :param bool name_expansion: (optional) name expansion.
    :param
          SalIntegrationEnrichmentSettingsSemanticExpansionNameExpansionConfiguration
          name_expansion_configuration: (optional) name expansion configuration.
    """

    def __init__(
        self,
        *,
        description_generation: Optional[bool] = None,
        description_generation_configuration: Optional['SalIntegrationEnrichmentSettingsSemanticExpansionDescriptionGenerationConfiguration'] = None,
        name_expansion: Optional[bool] = None,
        name_expansion_configuration: Optional['SalIntegrationEnrichmentSettingsSemanticExpansionNameExpansionConfiguration'] = None,
    ) -> None:
        """
        Initialize a SalIntegrationEnrichmentSettingsSemanticExpansion object.

        :param bool description_generation: (optional) description generation.
        :param
               SalIntegrationEnrichmentSettingsSemanticExpansionDescriptionGenerationConfiguration
               description_generation_configuration: (optional) description generation
               configuration.
        :param bool name_expansion: (optional) name expansion.
        :param
               SalIntegrationEnrichmentSettingsSemanticExpansionNameExpansionConfiguration
               name_expansion_configuration: (optional) name expansion configuration.
        """
        self.description_generation = description_generation
        self.description_generation_configuration = description_generation_configuration
        self.name_expansion = name_expansion
        self.name_expansion_configuration = name_expansion_configuration

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SalIntegrationEnrichmentSettingsSemanticExpansion':
        """Initialize a SalIntegrationEnrichmentSettingsSemanticExpansion object from a json dictionary."""
        args = {}
        if (description_generation := _dict.get('description_generation')) is not None:
            args['description_generation'] = description_generation
        if (description_generation_configuration := _dict.get('description_generation_configuration')) is not None:
            args['description_generation_configuration'] = SalIntegrationEnrichmentSettingsSemanticExpansionDescriptionGenerationConfiguration.from_dict(description_generation_configuration)
        if (name_expansion := _dict.get('name_expansion')) is not None:
            args['name_expansion'] = name_expansion
        if (name_expansion_configuration := _dict.get('name_expansion_configuration')) is not None:
            args['name_expansion_configuration'] = SalIntegrationEnrichmentSettingsSemanticExpansionNameExpansionConfiguration.from_dict(name_expansion_configuration)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SalIntegrationEnrichmentSettingsSemanticExpansion object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'description_generation') and self.description_generation is not None:
            _dict['description_generation'] = self.description_generation
        if hasattr(self, 'description_generation_configuration') and self.description_generation_configuration is not None:
            if isinstance(self.description_generation_configuration, dict):
                _dict['description_generation_configuration'] = self.description_generation_configuration
            else:
                _dict['description_generation_configuration'] = self.description_generation_configuration.to_dict()
        if hasattr(self, 'name_expansion') and self.name_expansion is not None:
            _dict['name_expansion'] = self.name_expansion
        if hasattr(self, 'name_expansion_configuration') and self.name_expansion_configuration is not None:
            if isinstance(self.name_expansion_configuration, dict):
                _dict['name_expansion_configuration'] = self.name_expansion_configuration
            else:
                _dict['name_expansion_configuration'] = self.name_expansion_configuration.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SalIntegrationEnrichmentSettingsSemanticExpansion object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SalIntegrationEnrichmentSettingsSemanticExpansion') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SalIntegrationEnrichmentSettingsSemanticExpansion') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SalIntegrationEnrichmentSettingsSemanticExpansionDescriptionGenerationConfiguration:
    """
    description generation configuration.

    :param float assignment_threshold: (optional) assignment threshold.
    :param float suggestion_threshold: (optional) suggestion threshold.
    """

    def __init__(
        self,
        *,
        assignment_threshold: Optional[float] = None,
        suggestion_threshold: Optional[float] = None,
    ) -> None:
        """
        Initialize a SalIntegrationEnrichmentSettingsSemanticExpansionDescriptionGenerationConfiguration object.

        :param float assignment_threshold: (optional) assignment threshold.
        :param float suggestion_threshold: (optional) suggestion threshold.
        """
        self.assignment_threshold = assignment_threshold
        self.suggestion_threshold = suggestion_threshold

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SalIntegrationEnrichmentSettingsSemanticExpansionDescriptionGenerationConfiguration':
        """Initialize a SalIntegrationEnrichmentSettingsSemanticExpansionDescriptionGenerationConfiguration object from a json dictionary."""
        args = {}
        if (assignment_threshold := _dict.get('assignment_threshold')) is not None:
            args['assignment_threshold'] = assignment_threshold
        if (suggestion_threshold := _dict.get('suggestion_threshold')) is not None:
            args['suggestion_threshold'] = suggestion_threshold
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SalIntegrationEnrichmentSettingsSemanticExpansionDescriptionGenerationConfiguration object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'assignment_threshold') and self.assignment_threshold is not None:
            _dict['assignment_threshold'] = self.assignment_threshold
        if hasattr(self, 'suggestion_threshold') and self.suggestion_threshold is not None:
            _dict['suggestion_threshold'] = self.suggestion_threshold
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SalIntegrationEnrichmentSettingsSemanticExpansionDescriptionGenerationConfiguration object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SalIntegrationEnrichmentSettingsSemanticExpansionDescriptionGenerationConfiguration') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SalIntegrationEnrichmentSettingsSemanticExpansionDescriptionGenerationConfiguration') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SalIntegrationEnrichmentSettingsSemanticExpansionNameExpansionConfiguration:
    """
    name expansion configuration.

    :param float assignment_threshold: (optional) assignment threshold.
    :param float suggestion_threshold: (optional) suggestion threshold.
    """

    def __init__(
        self,
        *,
        assignment_threshold: Optional[float] = None,
        suggestion_threshold: Optional[float] = None,
    ) -> None:
        """
        Initialize a SalIntegrationEnrichmentSettingsSemanticExpansionNameExpansionConfiguration object.

        :param float assignment_threshold: (optional) assignment threshold.
        :param float suggestion_threshold: (optional) suggestion threshold.
        """
        self.assignment_threshold = assignment_threshold
        self.suggestion_threshold = suggestion_threshold

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SalIntegrationEnrichmentSettingsSemanticExpansionNameExpansionConfiguration':
        """Initialize a SalIntegrationEnrichmentSettingsSemanticExpansionNameExpansionConfiguration object from a json dictionary."""
        args = {}
        if (assignment_threshold := _dict.get('assignment_threshold')) is not None:
            args['assignment_threshold'] = assignment_threshold
        if (suggestion_threshold := _dict.get('suggestion_threshold')) is not None:
            args['suggestion_threshold'] = suggestion_threshold
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SalIntegrationEnrichmentSettingsSemanticExpansionNameExpansionConfiguration object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'assignment_threshold') and self.assignment_threshold is not None:
            _dict['assignment_threshold'] = self.assignment_threshold
        if hasattr(self, 'suggestion_threshold') and self.suggestion_threshold is not None:
            _dict['suggestion_threshold'] = self.suggestion_threshold
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SalIntegrationEnrichmentSettingsSemanticExpansionNameExpansionConfiguration object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SalIntegrationEnrichmentSettingsSemanticExpansionNameExpansionConfiguration') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SalIntegrationEnrichmentSettingsSemanticExpansionNameExpansionConfiguration') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SalIntegrationEnrichmentSettingsTermAssignment:
    """
    semantic expansion.

    :param bool class_based_assignments: (optional) class based assignments.
    :param bool evaluate_negative_assignments: (optional) evaluate negative
          assignments.
    :param bool llm_based_assignments: (optional) llm based assignments.
    :param bool ml_based_assignments_custom: (optional) ml based assignments custom.
    :param bool ml_based_assignments_default: (optional) ml based assignments
          default.
    :param bool name_matching: (optional) name matching.
    :param float term_assignment_threshold: (optional) term assignment threshold.
    :param float term_suggestion_threshold: (optional) term suggestion threshold.
    """

    def __init__(
        self,
        *,
        class_based_assignments: Optional[bool] = None,
        evaluate_negative_assignments: Optional[bool] = None,
        llm_based_assignments: Optional[bool] = None,
        ml_based_assignments_custom: Optional[bool] = None,
        ml_based_assignments_default: Optional[bool] = None,
        name_matching: Optional[bool] = None,
        term_assignment_threshold: Optional[float] = None,
        term_suggestion_threshold: Optional[float] = None,
    ) -> None:
        """
        Initialize a SalIntegrationEnrichmentSettingsTermAssignment object.

        :param bool class_based_assignments: (optional) class based assignments.
        :param bool evaluate_negative_assignments: (optional) evaluate negative
               assignments.
        :param bool llm_based_assignments: (optional) llm based assignments.
        :param bool ml_based_assignments_custom: (optional) ml based assignments
               custom.
        :param bool ml_based_assignments_default: (optional) ml based assignments
               default.
        :param bool name_matching: (optional) name matching.
        :param float term_assignment_threshold: (optional) term assignment
               threshold.
        :param float term_suggestion_threshold: (optional) term suggestion
               threshold.
        """
        self.class_based_assignments = class_based_assignments
        self.evaluate_negative_assignments = evaluate_negative_assignments
        self.llm_based_assignments = llm_based_assignments
        self.ml_based_assignments_custom = ml_based_assignments_custom
        self.ml_based_assignments_default = ml_based_assignments_default
        self.name_matching = name_matching
        self.term_assignment_threshold = term_assignment_threshold
        self.term_suggestion_threshold = term_suggestion_threshold

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SalIntegrationEnrichmentSettingsTermAssignment':
        """Initialize a SalIntegrationEnrichmentSettingsTermAssignment object from a json dictionary."""
        args = {}
        if (class_based_assignments := _dict.get('class_based_assignments')) is not None:
            args['class_based_assignments'] = class_based_assignments
        if (evaluate_negative_assignments := _dict.get('evaluate_negative_assignments')) is not None:
            args['evaluate_negative_assignments'] = evaluate_negative_assignments
        if (llm_based_assignments := _dict.get('llm_based_assignments')) is not None:
            args['llm_based_assignments'] = llm_based_assignments
        if (ml_based_assignments_custom := _dict.get('ml_based_assignments_custom')) is not None:
            args['ml_based_assignments_custom'] = ml_based_assignments_custom
        if (ml_based_assignments_default := _dict.get('ml_based_assignments_default')) is not None:
            args['ml_based_assignments_default'] = ml_based_assignments_default
        if (name_matching := _dict.get('name_matching')) is not None:
            args['name_matching'] = name_matching
        if (term_assignment_threshold := _dict.get('term_assignment_threshold')) is not None:
            args['term_assignment_threshold'] = term_assignment_threshold
        if (term_suggestion_threshold := _dict.get('term_suggestion_threshold')) is not None:
            args['term_suggestion_threshold'] = term_suggestion_threshold
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SalIntegrationEnrichmentSettingsTermAssignment object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'class_based_assignments') and self.class_based_assignments is not None:
            _dict['class_based_assignments'] = self.class_based_assignments
        if hasattr(self, 'evaluate_negative_assignments') and self.evaluate_negative_assignments is not None:
            _dict['evaluate_negative_assignments'] = self.evaluate_negative_assignments
        if hasattr(self, 'llm_based_assignments') and self.llm_based_assignments is not None:
            _dict['llm_based_assignments'] = self.llm_based_assignments
        if hasattr(self, 'ml_based_assignments_custom') and self.ml_based_assignments_custom is not None:
            _dict['ml_based_assignments_custom'] = self.ml_based_assignments_custom
        if hasattr(self, 'ml_based_assignments_default') and self.ml_based_assignments_default is not None:
            _dict['ml_based_assignments_default'] = self.ml_based_assignments_default
        if hasattr(self, 'name_matching') and self.name_matching is not None:
            _dict['name_matching'] = self.name_matching
        if hasattr(self, 'term_assignment_threshold') and self.term_assignment_threshold is not None:
            _dict['term_assignment_threshold'] = self.term_assignment_threshold
        if hasattr(self, 'term_suggestion_threshold') and self.term_suggestion_threshold is not None:
            _dict['term_suggestion_threshold'] = self.term_suggestion_threshold
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SalIntegrationEnrichmentSettingsTermAssignment object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SalIntegrationEnrichmentSettingsTermAssignment') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SalIntegrationEnrichmentSettingsTermAssignment') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SalIntegrationGlossaryTerms:
    """
    Sal integration glossary terms.

    :param GlossaryObject glossary_term: (optional) glossary object.
    """

    def __init__(
        self,
        *,
        glossary_term: Optional['GlossaryObject'] = None,
    ) -> None:
        """
        Initialize a SalIntegrationGlossaryTerms object.

        :param GlossaryObject glossary_term: (optional) glossary object.
        """
        self.glossary_term = glossary_term

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SalIntegrationGlossaryTerms':
        """Initialize a SalIntegrationGlossaryTerms object from a json dictionary."""
        args = {}
        if (glossary_term := _dict.get('glossary_term')) is not None:
            args['glossary_term'] = GlossaryObject.from_dict(glossary_term)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SalIntegrationGlossaryTerms object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'glossary_term') and self.glossary_term is not None:
            if isinstance(self.glossary_term, dict):
                _dict['glossary_term'] = self.glossary_term
            else:
                _dict['glossary_term'] = self.glossary_term.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SalIntegrationGlossaryTerms object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SalIntegrationGlossaryTerms') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SalIntegrationGlossaryTerms') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SalIntegrationMappings:
    """
    Sal Integration Mappings object.

    :param str wkc_catalog_id: (optional) catalog name.
    :param str wkc_project_id: (optional) operation type.
    """

    def __init__(
        self,
        *,
        wkc_catalog_id: Optional[str] = None,
        wkc_project_id: Optional[str] = None,
    ) -> None:
        """
        Initialize a SalIntegrationMappings object.

        :param str wkc_catalog_id: (optional) catalog name.
        :param str wkc_project_id: (optional) operation type.
        """
        self.wkc_catalog_id = wkc_catalog_id
        self.wkc_project_id = wkc_project_id

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SalIntegrationMappings':
        """Initialize a SalIntegrationMappings object from a json dictionary."""
        args = {}
        if (wkc_catalog_id := _dict.get('wkc_catalog_id')) is not None:
            args['wkc_catalog_id'] = wkc_catalog_id
        if (wkc_project_id := _dict.get('wkc_project_id')) is not None:
            args['wkc_project_id'] = wkc_project_id
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SalIntegrationMappings object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'wkc_catalog_id') and self.wkc_catalog_id is not None:
            _dict['wkc_catalog_id'] = self.wkc_catalog_id
        if hasattr(self, 'wkc_project_id') and self.wkc_project_id is not None:
            _dict['wkc_project_id'] = self.wkc_project_id
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SalIntegrationMappings object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SalIntegrationMappings') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SalIntegrationMappings') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SalIntegrationPatch:
    """
    update sal integration.

    :param str op: (optional) op.
    :param str path: (optional) path.
    :param str value: (optional) path.
    """

    def __init__(
        self,
        *,
        op: Optional[str] = None,
        path: Optional[str] = None,
        value: Optional[str] = None,
    ) -> None:
        """
        Initialize a SalIntegrationPatch object.

        :param str op: (optional) op.
        :param str path: (optional) path.
        :param str value: (optional) path.
        """
        self.op = op
        self.path = path
        self.value = value

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SalIntegrationPatch':
        """Initialize a SalIntegrationPatch object from a json dictionary."""
        args = {}
        if (op := _dict.get('op')) is not None:
            args['op'] = op
        if (path := _dict.get('path')) is not None:
            args['path'] = path
        if (value := _dict.get('value')) is not None:
            args['value'] = value
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SalIntegrationPatch object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'op') and self.op is not None:
            _dict['op'] = self.op
        if hasattr(self, 'path') and self.path is not None:
            _dict['path'] = self.path
        if hasattr(self, 'value') and self.value is not None:
            _dict['value'] = self.value
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SalIntegrationPatch object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SalIntegrationPatch') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SalIntegrationPatch') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SalIntegrationUploadGlossary:
    """
    Sal Integration Upload Glossary.

    :param str process_id: (optional) catalog name.
    """

    def __init__(
        self,
        *,
        process_id: Optional[str] = None,
    ) -> None:
        """
        Initialize a SalIntegrationUploadGlossary object.

        :param str process_id: (optional) catalog name.
        """
        self.process_id = process_id

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SalIntegrationUploadGlossary':
        """Initialize a SalIntegrationUploadGlossary object from a json dictionary."""
        args = {}
        if (process_id := _dict.get('process_id')) is not None:
            args['process_id'] = process_id
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SalIntegrationUploadGlossary object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'process_id') and self.process_id is not None:
            _dict['process_id'] = self.process_id
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SalIntegrationUploadGlossary object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SalIntegrationUploadGlossary') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SalIntegrationUploadGlossary') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SalIntegrationUploadGlossaryStatus:
    """
    Sal Integration Upload Glossary Status.

    :param str response: (optional) catalog status.
    """

    def __init__(
        self,
        *,
        response: Optional[str] = None,
    ) -> None:
        """
        Initialize a SalIntegrationUploadGlossaryStatus object.

        :param str response: (optional) catalog status.
        """
        self.response = response

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SalIntegrationUploadGlossaryStatus':
        """Initialize a SalIntegrationUploadGlossaryStatus object from a json dictionary."""
        args = {}
        if (response := _dict.get('response')) is not None:
            args['response'] = response
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SalIntegrationUploadGlossaryStatus object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'response') and self.response is not None:
            _dict['response'] = self.response
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SalIntegrationUploadGlossaryStatus object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SalIntegrationUploadGlossaryStatus') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SalIntegrationUploadGlossaryStatus') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class ScheduleInfo:
    """
    Information about the schedule.

    :param str frequency: (optional) Frequency of schedule execution (e.g., daily,
          weekly, monthly).
    """

    def __init__(
        self,
        *,
        frequency: Optional[str] = None,
    ) -> None:
        """
        Initialize a ScheduleInfo object.

        :param str frequency: (optional) Frequency of schedule execution (e.g.,
               daily, weekly, monthly).
        """
        self.frequency = frequency

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ScheduleInfo':
        """Initialize a ScheduleInfo object from a json dictionary."""
        args = {}
        if (frequency := _dict.get('frequency')) is not None:
            args['frequency'] = frequency
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ScheduleInfo object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'frequency') and self.frequency is not None:
            _dict['frequency'] = self.frequency
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ScheduleInfo object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ScheduleInfo') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ScheduleInfo') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SchemaResponse:
    """
    Summary of the schema response.

    :param str bucket: (optional) The bucket linked to the catalog.
    :param str catalog: (optional) The catalog that this schema is associated to.
    :param str message: (optional) Response message string.
    :param str message_code: (optional) Message code string.
    :param str owner: (optional) Owner of the bucket.
    :param SchemaResponseSummary schema: (optional) Summary of the schema response.
    :param str schema_name: (optional) Name of the schema.
    """

    def __init__(
        self,
        *,
        bucket: Optional[str] = None,
        catalog: Optional[str] = None,
        message: Optional[str] = None,
        message_code: Optional[str] = None,
        owner: Optional[str] = None,
        schema: Optional['SchemaResponseSummary'] = None,
        schema_name: Optional[str] = None,
    ) -> None:
        """
        Initialize a SchemaResponse object.

        :param str bucket: (optional) The bucket linked to the catalog.
        :param str catalog: (optional) The catalog that this schema is associated
               to.
        :param str message: (optional) Response message string.
        :param str message_code: (optional) Message code string.
        :param str owner: (optional) Owner of the bucket.
        :param SchemaResponseSummary schema: (optional) Summary of the schema
               response.
        :param str schema_name: (optional) Name of the schema.
        """
        self.bucket = bucket
        self.catalog = catalog
        self.message = message
        self.message_code = message_code
        self.owner = owner
        self.schema = schema
        self.schema_name = schema_name

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SchemaResponse':
        """Initialize a SchemaResponse object from a json dictionary."""
        args = {}
        if (bucket := _dict.get('bucket')) is not None:
            args['bucket'] = bucket
        if (catalog := _dict.get('catalog')) is not None:
            args['catalog'] = catalog
        if (message := _dict.get('message')) is not None:
            args['message'] = message
        if (message_code := _dict.get('message_code')) is not None:
            args['message_code'] = message_code
        if (owner := _dict.get('owner')) is not None:
            args['owner'] = owner
        if (schema := _dict.get('schema')) is not None:
            args['schema'] = SchemaResponseSummary.from_dict(schema)
        if (schema_name := _dict.get('schema_name')) is not None:
            args['schema_name'] = schema_name
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SchemaResponse object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'bucket') and self.bucket is not None:
            _dict['bucket'] = self.bucket
        if hasattr(self, 'catalog') and self.catalog is not None:
            _dict['catalog'] = self.catalog
        if hasattr(self, 'message') and self.message is not None:
            _dict['message'] = self.message
        if hasattr(self, 'message_code') and self.message_code is not None:
            _dict['message_code'] = self.message_code
        if hasattr(self, 'owner') and self.owner is not None:
            _dict['owner'] = self.owner
        if hasattr(self, 'schema') and self.schema is not None:
            if isinstance(self.schema, dict):
                _dict['schema'] = self.schema
            else:
                _dict['schema'] = self.schema.to_dict()
        if hasattr(self, 'schema_name') and self.schema_name is not None:
            _dict['schema_name'] = self.schema_name
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SchemaResponse object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SchemaResponse') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SchemaResponse') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SchemaResponseCollection:
    """
    Schema response for list all schemas.

    :param str message: (optional) Response message string.
    :param str message_code: (optional) Message code string.
    :param List[SchemaResponseSummary] schemas: (optional) A list of all schemas.
    """

    def __init__(
        self,
        *,
        message: Optional[str] = None,
        message_code: Optional[str] = None,
        schemas: Optional[List['SchemaResponseSummary']] = None,
    ) -> None:
        """
        Initialize a SchemaResponseCollection object.

        :param str message: (optional) Response message string.
        :param str message_code: (optional) Message code string.
        :param List[SchemaResponseSummary] schemas: (optional) A list of all
               schemas.
        """
        self.message = message
        self.message_code = message_code
        self.schemas = schemas

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SchemaResponseCollection':
        """Initialize a SchemaResponseCollection object from a json dictionary."""
        args = {}
        if (message := _dict.get('message')) is not None:
            args['message'] = message
        if (message_code := _dict.get('message_code')) is not None:
            args['message_code'] = message_code
        if (schemas := _dict.get('schemas')) is not None:
            args['schemas'] = [SchemaResponseSummary.from_dict(v) for v in schemas]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SchemaResponseCollection object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'message') and self.message is not None:
            _dict['message'] = self.message
        if hasattr(self, 'message_code') and self.message_code is not None:
            _dict['message_code'] = self.message_code
        if hasattr(self, 'schemas') and self.schemas is not None:
            schemas_list = []
            for v in self.schemas:
                if isinstance(v, dict):
                    schemas_list.append(v)
                else:
                    schemas_list.append(v.to_dict())
            _dict['schemas'] = schemas_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SchemaResponseCollection object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SchemaResponseCollection') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SchemaResponseCollection') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SchemaResponseSummary:
    """
    Summary of the schema response.

    :param str bucket: (optional) The bucket linked to the catalog.
    :param str catalog: (optional) The catalog that this schema is associated to.
    :param str owner: (optional) Owner of the bucket.
    :param str schema_name: (optional) Name of the schema.
    """

    def __init__(
        self,
        *,
        bucket: Optional[str] = None,
        catalog: Optional[str] = None,
        owner: Optional[str] = None,
        schema_name: Optional[str] = None,
    ) -> None:
        """
        Initialize a SchemaResponseSummary object.

        :param str bucket: (optional) The bucket linked to the catalog.
        :param str catalog: (optional) The catalog that this schema is associated
               to.
        :param str owner: (optional) Owner of the bucket.
        :param str schema_name: (optional) Name of the schema.
        """
        self.bucket = bucket
        self.catalog = catalog
        self.owner = owner
        self.schema_name = schema_name

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SchemaResponseSummary':
        """Initialize a SchemaResponseSummary object from a json dictionary."""
        args = {}
        if (bucket := _dict.get('bucket')) is not None:
            args['bucket'] = bucket
        if (catalog := _dict.get('catalog')) is not None:
            args['catalog'] = catalog
        if (owner := _dict.get('owner')) is not None:
            args['owner'] = owner
        if (schema_name := _dict.get('schema_name')) is not None:
            args['schema_name'] = schema_name
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SchemaResponseSummary object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'bucket') and self.bucket is not None:
            _dict['bucket'] = self.bucket
        if hasattr(self, 'catalog') and self.catalog is not None:
            _dict['catalog'] = self.catalog
        if hasattr(self, 'owner') and self.owner is not None:
            _dict['owner'] = self.owner
        if hasattr(self, 'schema_name') and self.schema_name is not None:
            _dict['schema_name'] = self.schema_name
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SchemaResponseSummary object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SchemaResponseSummary') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SchemaResponseSummary') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SparkApplicationConfig:
    """
    Spark applications details configuration.

    :param str spark_sample_config_properpty: (optional)
          spark_sample_config_properpty.
    """

    def __init__(
        self,
        *,
        spark_sample_config_properpty: Optional[str] = None,
    ) -> None:
        """
        Initialize a SparkApplicationConfig object.

        :param str spark_sample_config_properpty: (optional)
               spark_sample_config_properpty.
        """
        self.spark_sample_config_properpty = spark_sample_config_properpty

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SparkApplicationConfig':
        """Initialize a SparkApplicationConfig object from a json dictionary."""
        args = {}
        if (spark_sample_config_properpty := _dict.get('spark_sample_config_properpty')) is not None:
            args['spark_sample_config_properpty'] = spark_sample_config_properpty
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SparkApplicationConfig object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'spark_sample_config_properpty') and self.spark_sample_config_properpty is not None:
            _dict['spark_sample_config_properpty'] = self.spark_sample_config_properpty
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SparkApplicationConfig object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SparkApplicationConfig') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SparkApplicationConfig') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SparkApplicationDetails:
    """
    Application details.

    :param str application: (optional) Application.
    :param List[str] arguments: (optional) List of arguments.
    :param str class_: (optional) Class.
    :param SparkApplicationConfig conf: (optional) Spark applications details
          configuration.
    :param SparkApplicationEnv env: (optional) Spark applications details env
          samples.
    :param str files: (optional) Files.
    :param str jars: (optional) Jars.
    :param str name: (optional) Display name of the spark application.
    :param str packages: (optional) Packages.
    :param str repositories: (optional) Repositories.
    :param str spark_version: (optional) Spark Version.
    :param SparkApplicationDetailsRuntime runtime: (optional) application run time.
    """

    def __init__(
        self,
        *,
        application: Optional[str] = None,
        arguments: Optional[List[str]] = None,
        class_: Optional[str] = None,
        conf: Optional['SparkApplicationConfig'] = None,
        env: Optional['SparkApplicationEnv'] = None,
        files: Optional[str] = None,
        jars: Optional[str] = None,
        name: Optional[str] = None,
        packages: Optional[str] = None,
        repositories: Optional[str] = None,
        spark_version: Optional[str] = None,
        runtime: Optional['SparkApplicationDetailsRuntime'] = None,
    ) -> None:
        """
        Initialize a SparkApplicationDetails object.

        :param str application: (optional) Application.
        :param List[str] arguments: (optional) List of arguments.
        :param str class_: (optional) Class.
        :param SparkApplicationConfig conf: (optional) Spark applications details
               configuration.
        :param SparkApplicationEnv env: (optional) Spark applications details env
               samples.
        :param str files: (optional) Files.
        :param str jars: (optional) Jars.
        :param str name: (optional) Display name of the spark application.
        :param str packages: (optional) Packages.
        :param str repositories: (optional) Repositories.
        :param str spark_version: (optional) Spark Version.
        :param SparkApplicationDetailsRuntime runtime: (optional) application run
               time.
        """
        self.application = application
        self.arguments = arguments
        self.class_ = class_
        self.conf = conf
        self.env = env
        self.files = files
        self.jars = jars
        self.name = name
        self.packages = packages
        self.repositories = repositories
        self.spark_version = spark_version
        self.runtime = runtime

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SparkApplicationDetails':
        """Initialize a SparkApplicationDetails object from a json dictionary."""
        args = {}
        if (application := _dict.get('application')) is not None:
            args['application'] = application
        if (arguments := _dict.get('arguments')) is not None:
            args['arguments'] = arguments
        if (class_ := _dict.get('class')) is not None:
            args['class_'] = class_
        if (conf := _dict.get('conf')) is not None:
            args['conf'] = SparkApplicationConfig.from_dict(conf)
        if (env := _dict.get('env')) is not None:
            args['env'] = SparkApplicationEnv.from_dict(env)
        if (files := _dict.get('files')) is not None:
            args['files'] = files
        if (jars := _dict.get('jars')) is not None:
            args['jars'] = jars
        if (name := _dict.get('name')) is not None:
            args['name'] = name
        if (packages := _dict.get('packages')) is not None:
            args['packages'] = packages
        if (repositories := _dict.get('repositories')) is not None:
            args['repositories'] = repositories
        if (spark_version := _dict.get('spark_version')) is not None:
            args['spark_version'] = spark_version
        if (runtime := _dict.get('runtime')) is not None:
            args['runtime'] = SparkApplicationDetailsRuntime.from_dict(runtime)
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
        if hasattr(self, 'class_') and self.class_ is not None:
            _dict['class'] = self.class_
        if hasattr(self, 'conf') and self.conf is not None:
            if isinstance(self.conf, dict):
                _dict['conf'] = self.conf
            else:
                _dict['conf'] = self.conf.to_dict()
        if hasattr(self, 'env') and self.env is not None:
            if isinstance(self.env, dict):
                _dict['env'] = self.env
            else:
                _dict['env'] = self.env.to_dict()
        if hasattr(self, 'files') and self.files is not None:
            _dict['files'] = self.files
        if hasattr(self, 'jars') and self.jars is not None:
            _dict['jars'] = self.jars
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'packages') and self.packages is not None:
            _dict['packages'] = self.packages
        if hasattr(self, 'repositories') and self.repositories is not None:
            _dict['repositories'] = self.repositories
        if hasattr(self, 'spark_version') and self.spark_version is not None:
            _dict['spark_version'] = self.spark_version
        if hasattr(self, 'runtime') and self.runtime is not None:
            if isinstance(self.runtime, dict):
                _dict['runtime'] = self.runtime
            else:
                _dict['runtime'] = self.runtime.to_dict()
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


class SparkApplicationDetailsRuntime:
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
        Initialize a SparkApplicationDetailsRuntime object.

        :param str spark_version: (optional) Spark Version.
        """
        self.spark_version = spark_version

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SparkApplicationDetailsRuntime':
        """Initialize a SparkApplicationDetailsRuntime object from a json dictionary."""
        args = {}
        if (spark_version := _dict.get('spark_version')) is not None:
            args['spark_version'] = spark_version
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SparkApplicationDetailsRuntime object from a json dictionary."""
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
        """Return a `str` version of this SparkApplicationDetailsRuntime object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SparkApplicationDetailsRuntime') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SparkApplicationDetailsRuntime') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SparkApplicationEnv:
    """
    Spark applications details env samples.

    :param str sample_env_key: (optional) sample.
    """

    def __init__(
        self,
        *,
        sample_env_key: Optional[str] = None,
    ) -> None:
        """
        Initialize a SparkApplicationEnv object.

        :param str sample_env_key: (optional) sample.
        """
        self.sample_env_key = sample_env_key

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SparkApplicationEnv':
        """Initialize a SparkApplicationEnv object from a json dictionary."""
        args = {}
        if (sample_env_key := _dict.get('sample_env_key')) is not None:
            args['sample_env_key'] = sample_env_key
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SparkApplicationEnv object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'sample_env_key') and self.sample_env_key is not None:
            _dict['sample_env_key'] = self.sample_env_key
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SparkApplicationEnv object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SparkApplicationEnv') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SparkApplicationEnv') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SparkDefaultConfig:
    """
    Spark Default Config details.

    :param str config1: (optional) config1.
    :param str config2: (optional) config2.
    """

    def __init__(
        self,
        *,
        config1: Optional[str] = None,
        config2: Optional[str] = None,
    ) -> None:
        """
        Initialize a SparkDefaultConfig object.

        :param str config1: (optional) config1.
        :param str config2: (optional) config2.
        """
        self.config1 = config1
        self.config2 = config2

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SparkDefaultConfig':
        """Initialize a SparkDefaultConfig object from a json dictionary."""
        args = {}
        if (config1 := _dict.get('config1')) is not None:
            args['config1'] = config1
        if (config2 := _dict.get('config2')) is not None:
            args['config2'] = config2
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SparkDefaultConfig object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'config1') and self.config1 is not None:
            _dict['config1'] = self.config1
        if hasattr(self, 'config2') and self.config2 is not None:
            _dict['config2'] = self.config2
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SparkDefaultConfig object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SparkDefaultConfig') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SparkDefaultConfig') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SparkEndpoints:
    """
    Application Endpoints.

    :param str applications_api: (optional) Application API.
    :param str history_server_endpoint: (optional) History server endpoint.
    :param str spark_access_endpoint: (optional) Spark kernel endpoint.
    :param str spark_jobs_v4_endpoint: (optional) Spark jobs V4 endpoint.
    :param str spark_kernel_endpoint: (optional) Spark kernel endpoint.
    :param str view_history_server: (optional) View history server.
    :param str wxd_application_endpoint: (optional) Wxd application endpoint.
    :param str wxd_engine_endpoint: (optional) Wxd engine endpoint.
    :param str wxd_history_server_endpoint: (optional) Wxd history_server endpoint.
    :param str wxd_history_server_ui_endpoint: (optional) Wxd history_server
          endpoint.
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
        wxd_engine_endpoint: Optional[str] = None,
        wxd_history_server_endpoint: Optional[str] = None,
        wxd_history_server_ui_endpoint: Optional[str] = None,
    ) -> None:
        """
        Initialize a SparkEndpoints object.

        :param str applications_api: (optional) Application API.
        :param str history_server_endpoint: (optional) History server endpoint.
        :param str spark_access_endpoint: (optional) Spark kernel endpoint.
        :param str spark_jobs_v4_endpoint: (optional) Spark jobs V4 endpoint.
        :param str spark_kernel_endpoint: (optional) Spark kernel endpoint.
        :param str view_history_server: (optional) View history server.
        :param str wxd_application_endpoint: (optional) Wxd application endpoint.
        :param str wxd_engine_endpoint: (optional) Wxd engine endpoint.
        :param str wxd_history_server_endpoint: (optional) Wxd history_server
               endpoint.
        :param str wxd_history_server_ui_endpoint: (optional) Wxd history_server
               endpoint.
        """
        self.applications_api = applications_api
        self.history_server_endpoint = history_server_endpoint
        self.spark_access_endpoint = spark_access_endpoint
        self.spark_jobs_v4_endpoint = spark_jobs_v4_endpoint
        self.spark_kernel_endpoint = spark_kernel_endpoint
        self.view_history_server = view_history_server
        self.wxd_application_endpoint = wxd_application_endpoint
        self.wxd_engine_endpoint = wxd_engine_endpoint
        self.wxd_history_server_endpoint = wxd_history_server_endpoint
        self.wxd_history_server_ui_endpoint = wxd_history_server_ui_endpoint

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SparkEndpoints':
        """Initialize a SparkEndpoints object from a json dictionary."""
        args = {}
        if (applications_api := _dict.get('applications_api')) is not None:
            args['applications_api'] = applications_api
        if (history_server_endpoint := _dict.get('history_server_endpoint')) is not None:
            args['history_server_endpoint'] = history_server_endpoint
        if (spark_access_endpoint := _dict.get('spark_access_endpoint')) is not None:
            args['spark_access_endpoint'] = spark_access_endpoint
        if (spark_jobs_v4_endpoint := _dict.get('spark_jobs_v4_endpoint')) is not None:
            args['spark_jobs_v4_endpoint'] = spark_jobs_v4_endpoint
        if (spark_kernel_endpoint := _dict.get('spark_kernel_endpoint')) is not None:
            args['spark_kernel_endpoint'] = spark_kernel_endpoint
        if (view_history_server := _dict.get('view_history_server')) is not None:
            args['view_history_server'] = view_history_server
        if (wxd_application_endpoint := _dict.get('wxd_application_endpoint')) is not None:
            args['wxd_application_endpoint'] = wxd_application_endpoint
        if (wxd_engine_endpoint := _dict.get('wxd_engine_endpoint')) is not None:
            args['wxd_engine_endpoint'] = wxd_engine_endpoint
        if (wxd_history_server_endpoint := _dict.get('wxd_history_server_endpoint')) is not None:
            args['wxd_history_server_endpoint'] = wxd_history_server_endpoint
        if (wxd_history_server_ui_endpoint := _dict.get('wxd_history_server_ui_endpoint')) is not None:
            args['wxd_history_server_ui_endpoint'] = wxd_history_server_ui_endpoint
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SparkEndpoints object from a json dictionary."""
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
        if hasattr(self, 'wxd_engine_endpoint') and self.wxd_engine_endpoint is not None:
            _dict['wxd_engine_endpoint'] = self.wxd_engine_endpoint
        if hasattr(self, 'wxd_history_server_endpoint') and self.wxd_history_server_endpoint is not None:
            _dict['wxd_history_server_endpoint'] = self.wxd_history_server_endpoint
        if hasattr(self, 'wxd_history_server_ui_endpoint') and self.wxd_history_server_ui_endpoint is not None:
            _dict['wxd_history_server_ui_endpoint'] = self.wxd_history_server_ui_endpoint
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SparkEndpoints object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SparkEndpoints') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SparkEndpoints') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SparkEngine:
    """
    EngineDetail.

    :param List[str] actions: (optional) Actions.
    :param List[str] associated_catalogs: (optional) Associated catalogs.
    :param str build_version: (optional) watsonx.data build version.
    :param str created_by: (optional) Created user name.
    :param int created_on: (optional) Created time in epoch format.
    :param str description: (optional) Engine description.
    :param SparkEngineDetails engine_details: (optional) External engine details.
    :param str engine_display_name: (optional) Engine display name.
    :param str engine_id: (optional) Engine programmatic name.
    :param str origin: (optional) Origin - created or registered.
    :param str status: (optional) Engine status.
    :param List[str] tags: (optional) Tags.
    :param str type: (optional) Type like spark, netezza,..
    """

    def __init__(
        self,
        *,
        actions: Optional[List[str]] = None,
        associated_catalogs: Optional[List[str]] = None,
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
        :param List[str] associated_catalogs: (optional) Associated catalogs.
        :param str build_version: (optional) watsonx.data build version.
        :param str created_by: (optional) Created user name.
        :param int created_on: (optional) Created time in epoch format.
        :param str description: (optional) Engine description.
        :param SparkEngineDetails engine_details: (optional) External engine
               details.
        :param str engine_display_name: (optional) Engine display name.
        :param str engine_id: (optional) Engine programmatic name.
        :param str origin: (optional) Origin - created or registered.
        :param str status: (optional) Engine status.
        :param List[str] tags: (optional) Tags.
        :param str type: (optional) Type like spark, netezza,..
        """
        self.actions = actions
        self.associated_catalogs = associated_catalogs
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
        if (actions := _dict.get('actions')) is not None:
            args['actions'] = actions
        if (associated_catalogs := _dict.get('associated_catalogs')) is not None:
            args['associated_catalogs'] = associated_catalogs
        if (build_version := _dict.get('build_version')) is not None:
            args['build_version'] = build_version
        if (created_by := _dict.get('created_by')) is not None:
            args['created_by'] = created_by
        if (created_on := _dict.get('created_on')) is not None:
            args['created_on'] = created_on
        if (description := _dict.get('description')) is not None:
            args['description'] = description
        if (engine_details := _dict.get('engine_details')) is not None:
            args['engine_details'] = SparkEngineDetails.from_dict(engine_details)
        if (engine_display_name := _dict.get('engine_display_name')) is not None:
            args['engine_display_name'] = engine_display_name
        if (engine_id := _dict.get('engine_id')) is not None:
            args['engine_id'] = engine_id
        if (origin := _dict.get('origin')) is not None:
            args['origin'] = origin
        if (status := _dict.get('status')) is not None:
            args['status'] = status
        if (tags := _dict.get('tags')) is not None:
            args['tags'] = tags
        if (type := _dict.get('type')) is not None:
            args['type'] = type
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
        if hasattr(self, 'associated_catalogs') and self.associated_catalogs is not None:
            _dict['associated_catalogs'] = self.associated_catalogs
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

    class OriginEnum(str, Enum):
        """
        Origin - created or registered.
        """

        EXTERNAL = 'external'
        DISCOVER = 'discover'
        NATIVE = 'native'


    class TypeEnum(str, Enum):
        """
        Type like spark, netezza,..
        """

        SPARK = 'spark'



class SparkEngineApplicationStatus:
    """
    Engine Application Status.

    :param SparkApplicationDetails application_details: (optional) Application
          details.
    :param str application_id: (optional) Application ID.
    :param str auto_termination_time: (optional) Auto Termination Time.
    :param str creation_time: (optional) Creation time.
    :param str deploy_mode: (optional) Deployment mode.
    :param str end_time: (optional) End Time.
    :param str failed_time: (optional) Failed time.
    :param str finish_time: (optional) Finish time.
    :param str id: (optional) Application ID.
    :param str job_endpoint: (optional) Job endpoint.
    :param str return_code: (optional) Return code.
    :param SparkEngineApplicationStatusRuntime runtime: (optional) application run
          time.
    :param str service_instance_id: (optional) Service Instance ID for POST.
    :param str spark_application_id: (optional) Spark application ID.
    :param str spark_application_name: (optional) Spark application name.
    :param str spark_version: (optional) Spark Version.
    :param str start_time: (optional) Start time.
    :param str state: (optional) Application state.
    :param List[SparkEngineApplicationStatusStateDetailsItems] state_details:
          (optional) Application state details.
    :param str submission_time: (optional) Application submission time.
    :param str template_id: (optional) Template ID.
    :param str type: (optional) Engine Type.
    :param List[SparkVolumeDetails] volumes: (optional) Spark application volumes to
          mount.
    :param str wxd_application_ui_endpoint: (optional) Wxd history_server endpoint.
    """

    def __init__(
        self,
        *,
        application_details: Optional['SparkApplicationDetails'] = None,
        application_id: Optional[str] = None,
        auto_termination_time: Optional[str] = None,
        creation_time: Optional[str] = None,
        deploy_mode: Optional[str] = None,
        end_time: Optional[str] = None,
        failed_time: Optional[str] = None,
        finish_time: Optional[str] = None,
        id: Optional[str] = None,
        job_endpoint: Optional[str] = None,
        return_code: Optional[str] = None,
        runtime: Optional['SparkEngineApplicationStatusRuntime'] = None,
        service_instance_id: Optional[str] = None,
        spark_application_id: Optional[str] = None,
        spark_application_name: Optional[str] = None,
        spark_version: Optional[str] = None,
        start_time: Optional[str] = None,
        state: Optional[str] = None,
        state_details: Optional[List['SparkEngineApplicationStatusStateDetailsItems']] = None,
        submission_time: Optional[str] = None,
        template_id: Optional[str] = None,
        type: Optional[str] = None,
        volumes: Optional[List['SparkVolumeDetails']] = None,
        wxd_application_ui_endpoint: Optional[str] = None,
    ) -> None:
        """
        Initialize a SparkEngineApplicationStatus object.

        :param SparkApplicationDetails application_details: (optional) Application
               details.
        :param str application_id: (optional) Application ID.
        :param str auto_termination_time: (optional) Auto Termination Time.
        :param str creation_time: (optional) Creation time.
        :param str deploy_mode: (optional) Deployment mode.
        :param str end_time: (optional) End Time.
        :param str failed_time: (optional) Failed time.
        :param str finish_time: (optional) Finish time.
        :param str id: (optional) Application ID.
        :param str job_endpoint: (optional) Job endpoint.
        :param str return_code: (optional) Return code.
        :param SparkEngineApplicationStatusRuntime runtime: (optional) application
               run time.
        :param str service_instance_id: (optional) Service Instance ID for POST.
        :param str spark_application_id: (optional) Spark application ID.
        :param str spark_application_name: (optional) Spark application name.
        :param str spark_version: (optional) Spark Version.
        :param str start_time: (optional) Start time.
        :param str state: (optional) Application state.
        :param List[SparkEngineApplicationStatusStateDetailsItems] state_details:
               (optional) Application state details.
        :param str submission_time: (optional) Application submission time.
        :param str template_id: (optional) Template ID.
        :param str type: (optional) Engine Type.
        :param List[SparkVolumeDetails] volumes: (optional) Spark application
               volumes to mount.
        :param str wxd_application_ui_endpoint: (optional) Wxd history_server
               endpoint.
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
        self.job_endpoint = job_endpoint
        self.return_code = return_code
        self.runtime = runtime
        self.service_instance_id = service_instance_id
        self.spark_application_id = spark_application_id
        self.spark_application_name = spark_application_name
        self.spark_version = spark_version
        self.start_time = start_time
        self.state = state
        self.state_details = state_details
        self.submission_time = submission_time
        self.template_id = template_id
        self.type = type
        self.volumes = volumes
        self.wxd_application_ui_endpoint = wxd_application_ui_endpoint

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SparkEngineApplicationStatus':
        """Initialize a SparkEngineApplicationStatus object from a json dictionary."""
        args = {}
        if (application_details := _dict.get('application_details')) is not None:
            args['application_details'] = SparkApplicationDetails.from_dict(application_details)
        if (application_id := _dict.get('application_id')) is not None:
            args['application_id'] = application_id
        if (auto_termination_time := _dict.get('auto_termination_time')) is not None:
            args['auto_termination_time'] = auto_termination_time
        if (creation_time := _dict.get('creation_time')) is not None:
            args['creation_time'] = creation_time
        if (deploy_mode := _dict.get('deploy_mode')) is not None:
            args['deploy_mode'] = deploy_mode
        if (end_time := _dict.get('end_time')) is not None:
            args['end_time'] = end_time
        if (failed_time := _dict.get('failed_time')) is not None:
            args['failed_time'] = failed_time
        if (finish_time := _dict.get('finish_time')) is not None:
            args['finish_time'] = finish_time
        if (id := _dict.get('id')) is not None:
            args['id'] = id
        if (job_endpoint := _dict.get('job_endpoint')) is not None:
            args['job_endpoint'] = job_endpoint
        if (return_code := _dict.get('return_code')) is not None:
            args['return_code'] = return_code
        if (runtime := _dict.get('runtime')) is not None:
            args['runtime'] = SparkEngineApplicationStatusRuntime.from_dict(runtime)
        if (service_instance_id := _dict.get('service_instance_id')) is not None:
            args['service_instance_id'] = service_instance_id
        if (spark_application_id := _dict.get('spark_application_id')) is not None:
            args['spark_application_id'] = spark_application_id
        if (spark_application_name := _dict.get('spark_application_name')) is not None:
            args['spark_application_name'] = spark_application_name
        if (spark_version := _dict.get('spark_version')) is not None:
            args['spark_version'] = spark_version
        if (start_time := _dict.get('start_time')) is not None:
            args['start_time'] = start_time
        if (state := _dict.get('state')) is not None:
            args['state'] = state
        if (state_details := _dict.get('state_details')) is not None:
            args['state_details'] = [SparkEngineApplicationStatusStateDetailsItems.from_dict(v) for v in state_details]
        if (submission_time := _dict.get('submission_time')) is not None:
            args['submission_time'] = submission_time
        if (template_id := _dict.get('template_id')) is not None:
            args['template_id'] = template_id
        if (type := _dict.get('type')) is not None:
            args['type'] = type
        if (volumes := _dict.get('volumes')) is not None:
            args['volumes'] = [SparkVolumeDetails.from_dict(v) for v in volumes]
        if (wxd_application_ui_endpoint := _dict.get('wxd_application_ui_endpoint')) is not None:
            args['wxd_application_ui_endpoint'] = wxd_application_ui_endpoint
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
        if hasattr(self, 'job_endpoint') and self.job_endpoint is not None:
            _dict['job_endpoint'] = self.job_endpoint
        if hasattr(self, 'return_code') and self.return_code is not None:
            _dict['return_code'] = self.return_code
        if hasattr(self, 'runtime') and self.runtime is not None:
            if isinstance(self.runtime, dict):
                _dict['runtime'] = self.runtime
            else:
                _dict['runtime'] = self.runtime.to_dict()
        if hasattr(self, 'service_instance_id') and self.service_instance_id is not None:
            _dict['service_instance_id'] = self.service_instance_id
        if hasattr(self, 'spark_application_id') and self.spark_application_id is not None:
            _dict['spark_application_id'] = self.spark_application_id
        if hasattr(self, 'spark_application_name') and self.spark_application_name is not None:
            _dict['spark_application_name'] = self.spark_application_name
        if hasattr(self, 'spark_version') and self.spark_version is not None:
            _dict['spark_version'] = self.spark_version
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
        if hasattr(self, 'type') and self.type is not None:
            _dict['type'] = self.type
        if hasattr(self, 'volumes') and self.volumes is not None:
            volumes_list = []
            for v in self.volumes:
                if isinstance(v, dict):
                    volumes_list.append(v)
                else:
                    volumes_list.append(v.to_dict())
            _dict['volumes'] = volumes_list
        if hasattr(self, 'wxd_application_ui_endpoint') and self.wxd_application_ui_endpoint is not None:
            _dict['wxd_application_ui_endpoint'] = self.wxd_application_ui_endpoint
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

    class TypeEnum(str, Enum):
        """
        Engine Type.
        """

        IAE = 'iae'
        EMR = 'emr'



class SparkEngineApplicationStatusCollection:
    """
    Engine Application Detail.

    :param List[SparkEngineApplicationStatus] applications: (optional) Application
          body.
    """

    def __init__(
        self,
        *,
        applications: Optional[List['SparkEngineApplicationStatus']] = None,
    ) -> None:
        """
        Initialize a SparkEngineApplicationStatusCollection object.

        :param List[SparkEngineApplicationStatus] applications: (optional)
               Application body.
        """
        self.applications = applications

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SparkEngineApplicationStatusCollection':
        """Initialize a SparkEngineApplicationStatusCollection object from a json dictionary."""
        args = {}
        if (applications := _dict.get('applications')) is not None:
            args['applications'] = [SparkEngineApplicationStatus.from_dict(v) for v in applications]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SparkEngineApplicationStatusCollection object from a json dictionary."""
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
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SparkEngineApplicationStatusCollection object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SparkEngineApplicationStatusCollection') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SparkEngineApplicationStatusCollection') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SparkEngineApplicationStatusRuntime:
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
        Initialize a SparkEngineApplicationStatusRuntime object.

        :param str spark_version: (optional) Spark Version.
        """
        self.spark_version = spark_version

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SparkEngineApplicationStatusRuntime':
        """Initialize a SparkEngineApplicationStatusRuntime object from a json dictionary."""
        args = {}
        if (spark_version := _dict.get('spark_version')) is not None:
            args['spark_version'] = spark_version
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SparkEngineApplicationStatusRuntime object from a json dictionary."""
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
        """Return a `str` version of this SparkEngineApplicationStatusRuntime object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SparkEngineApplicationStatusRuntime') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SparkEngineApplicationStatusRuntime') -> bool:
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
        if (code := _dict.get('code')) is not None:
            args['code'] = code
        if (message := _dict.get('message')) is not None:
            args['message'] = message
        if (type := _dict.get('type')) is not None:
            args['type'] = type
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


class SparkEngineCollection:
    """
    List spark engines.

    :param List[SparkEngine] spark_engines: (optional) List spark engines.
    """

    def __init__(
        self,
        *,
        spark_engines: Optional[List['SparkEngine']] = None,
    ) -> None:
        """
        Initialize a SparkEngineCollection object.

        :param List[SparkEngine] spark_engines: (optional) List spark engines.
        """
        self.spark_engines = spark_engines

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SparkEngineCollection':
        """Initialize a SparkEngineCollection object from a json dictionary."""
        args = {}
        if (spark_engines := _dict.get('spark_engines')) is not None:
            args['spark_engines'] = [SparkEngine.from_dict(v) for v in spark_engines]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SparkEngineCollection object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
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
        """Return a `str` version of this SparkEngineCollection object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SparkEngineCollection') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SparkEngineCollection') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SparkEngineDetails:
    """
    External engine details.

    :param str api_key: (optional) api key to work with the saas IAE instance.
    :param str connection_string: (optional) External engine connection string.
    :param SparkDefaultConfig default_config: (optional) Spark Default Config
          details.
    :param str default_version: (optional) The default spark version for the native
          engine.
    :param SparkEndpoints endpoints: (optional) Application Endpoints.
    :param str engine_home_bucket_display_name: (optional) Default bucket for spark.
    :param str engine_home_bucket_name: (optional) Default bucket for spark.
    :param str engine_home_path: (optional) Path for spark.
    :param str engine_home_volume: (optional) Default volume for spark.
    :param str engine_home_volume_id: (optional) Default volume for spark.
    :param str engine_home_volume_name: (optional) Name of the volume.
    :param str engine_home_volume_storage_class: (optional) Storage class of the
          volume.
    :param str engine_home_volume_storage_size: (optional) Storage size of the
          volume.
    :param str engine_sub_type: (optional) spark engine sub type.
    :param str instance_id: (optional) Instance to access the instance.
    :param str managed_by: (optional) How is the spark instance managed.
    :param SparkScaleConfig scale_config: (optional) Spark instance scale
          configuration.
    """

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        connection_string: Optional[str] = None,
        default_config: Optional['SparkDefaultConfig'] = None,
        default_version: Optional[str] = None,
        endpoints: Optional['SparkEndpoints'] = None,
        engine_home_bucket_display_name: Optional[str] = None,
        engine_home_bucket_name: Optional[str] = None,
        engine_home_path: Optional[str] = None,
        engine_home_volume: Optional[str] = None,
        engine_home_volume_id: Optional[str] = None,
        engine_home_volume_name: Optional[str] = None,
        engine_home_volume_storage_class: Optional[str] = None,
        engine_home_volume_storage_size: Optional[str] = None,
        engine_sub_type: Optional[str] = None,
        instance_id: Optional[str] = None,
        managed_by: Optional[str] = None,
        scale_config: Optional['SparkScaleConfig'] = None,
    ) -> None:
        """
        Initialize a SparkEngineDetails object.

        :param str api_key: (optional) api key to work with the saas IAE instance.
        :param str connection_string: (optional) External engine connection string.
        :param SparkDefaultConfig default_config: (optional) Spark Default Config
               details.
        :param str default_version: (optional) The default spark version for the
               native engine.
        :param SparkEndpoints endpoints: (optional) Application Endpoints.
        :param str engine_home_bucket_display_name: (optional) Default bucket for
               spark.
        :param str engine_home_bucket_name: (optional) Default bucket for spark.
        :param str engine_home_path: (optional) Path for spark.
        :param str engine_home_volume: (optional) Default volume for spark.
        :param str engine_home_volume_id: (optional) Default volume for spark.
        :param str engine_home_volume_name: (optional) Name of the volume.
        :param str engine_home_volume_storage_class: (optional) Storage class of
               the volume.
        :param str engine_home_volume_storage_size: (optional) Storage size of the
               volume.
        :param str engine_sub_type: (optional) spark engine sub type.
        :param str instance_id: (optional) Instance to access the instance.
        :param str managed_by: (optional) How is the spark instance managed.
        :param SparkScaleConfig scale_config: (optional) Spark instance scale
               configuration.
        """
        self.api_key = api_key
        self.connection_string = connection_string
        self.default_config = default_config
        self.default_version = default_version
        self.endpoints = endpoints
        self.engine_home_bucket_display_name = engine_home_bucket_display_name
        self.engine_home_bucket_name = engine_home_bucket_name
        self.engine_home_path = engine_home_path
        self.engine_home_volume = engine_home_volume
        self.engine_home_volume_id = engine_home_volume_id
        self.engine_home_volume_name = engine_home_volume_name
        self.engine_home_volume_storage_class = engine_home_volume_storage_class
        self.engine_home_volume_storage_size = engine_home_volume_storage_size
        self.engine_sub_type = engine_sub_type
        self.instance_id = instance_id
        self.managed_by = managed_by
        self.scale_config = scale_config

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SparkEngineDetails':
        """Initialize a SparkEngineDetails object from a json dictionary."""
        args = {}
        if (api_key := _dict.get('api_key')) is not None:
            args['api_key'] = api_key
        if (connection_string := _dict.get('connection_string')) is not None:
            args['connection_string'] = connection_string
        if (default_config := _dict.get('default_config')) is not None:
            args['default_config'] = SparkDefaultConfig.from_dict(default_config)
        if (default_version := _dict.get('default_version')) is not None:
            args['default_version'] = default_version
        if (endpoints := _dict.get('endpoints')) is not None:
            args['endpoints'] = SparkEndpoints.from_dict(endpoints)
        if (engine_home_bucket_display_name := _dict.get('engine_home_bucket_display_name')) is not None:
            args['engine_home_bucket_display_name'] = engine_home_bucket_display_name
        if (engine_home_bucket_name := _dict.get('engine_home_bucket_name')) is not None:
            args['engine_home_bucket_name'] = engine_home_bucket_name
        if (engine_home_path := _dict.get('engine_home_path')) is not None:
            args['engine_home_path'] = engine_home_path
        if (engine_home_volume := _dict.get('engine_home_volume')) is not None:
            args['engine_home_volume'] = engine_home_volume
        if (engine_home_volume_id := _dict.get('engine_home_volume_id')) is not None:
            args['engine_home_volume_id'] = engine_home_volume_id
        if (engine_home_volume_name := _dict.get('engine_home_volume_name')) is not None:
            args['engine_home_volume_name'] = engine_home_volume_name
        if (engine_home_volume_storage_class := _dict.get('engine_home_volume_storage_class')) is not None:
            args['engine_home_volume_storage_class'] = engine_home_volume_storage_class
        if (engine_home_volume_storage_size := _dict.get('engine_home_volume_storage_size')) is not None:
            args['engine_home_volume_storage_size'] = engine_home_volume_storage_size
        if (engine_sub_type := _dict.get('engine_sub_type')) is not None:
            args['engine_sub_type'] = engine_sub_type
        if (instance_id := _dict.get('instance_id')) is not None:
            args['instance_id'] = instance_id
        if (managed_by := _dict.get('managed_by')) is not None:
            args['managed_by'] = managed_by
        if (scale_config := _dict.get('scale_config')) is not None:
            args['scale_config'] = SparkScaleConfig.from_dict(scale_config)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SparkEngineDetails object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'api_key') and self.api_key is not None:
            _dict['api_key'] = self.api_key
        if hasattr(self, 'connection_string') and self.connection_string is not None:
            _dict['connection_string'] = self.connection_string
        if hasattr(self, 'default_config') and self.default_config is not None:
            if isinstance(self.default_config, dict):
                _dict['default_config'] = self.default_config
            else:
                _dict['default_config'] = self.default_config.to_dict()
        if hasattr(self, 'default_version') and self.default_version is not None:
            _dict['default_version'] = self.default_version
        if hasattr(self, 'endpoints') and self.endpoints is not None:
            if isinstance(self.endpoints, dict):
                _dict['endpoints'] = self.endpoints
            else:
                _dict['endpoints'] = self.endpoints.to_dict()
        if hasattr(self, 'engine_home_bucket_display_name') and self.engine_home_bucket_display_name is not None:
            _dict['engine_home_bucket_display_name'] = self.engine_home_bucket_display_name
        if hasattr(self, 'engine_home_bucket_name') and self.engine_home_bucket_name is not None:
            _dict['engine_home_bucket_name'] = self.engine_home_bucket_name
        if hasattr(self, 'engine_home_path') and self.engine_home_path is not None:
            _dict['engine_home_path'] = self.engine_home_path
        if hasattr(self, 'engine_home_volume') and self.engine_home_volume is not None:
            _dict['engine_home_volume'] = self.engine_home_volume
        if hasattr(self, 'engine_home_volume_id') and self.engine_home_volume_id is not None:
            _dict['engine_home_volume_id'] = self.engine_home_volume_id
        if hasattr(self, 'engine_home_volume_name') and self.engine_home_volume_name is not None:
            _dict['engine_home_volume_name'] = self.engine_home_volume_name
        if hasattr(self, 'engine_home_volume_storage_class') and self.engine_home_volume_storage_class is not None:
            _dict['engine_home_volume_storage_class'] = self.engine_home_volume_storage_class
        if hasattr(self, 'engine_home_volume_storage_size') and self.engine_home_volume_storage_size is not None:
            _dict['engine_home_volume_storage_size'] = self.engine_home_volume_storage_size
        if hasattr(self, 'engine_sub_type') and self.engine_sub_type is not None:
            _dict['engine_sub_type'] = self.engine_sub_type
        if hasattr(self, 'instance_id') and self.instance_id is not None:
            _dict['instance_id'] = self.instance_id
        if hasattr(self, 'managed_by') and self.managed_by is not None:
            _dict['managed_by'] = self.managed_by
        if hasattr(self, 'scale_config') and self.scale_config is not None:
            if isinstance(self.scale_config, dict):
                _dict['scale_config'] = self.scale_config
            else:
                _dict['scale_config'] = self.scale_config.to_dict()
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


class SparkEngineDetailsPrototype:
    """
    Node details.

    :param str api_key: (optional) api key to work with the saas IAE instance.
    :param str connection_string: (optional) External engine connection string.
    :param SparkDefaultConfig default_config: (optional) Spark Default Config
          details.
    :param str default_version: (optional) The default spark version for the native
          engine.
    :param str engine_home_bucket_display_name: (optional) Default bucket name for
          spark.
    :param str engine_home_bucket_name: (optional) Default bucket for spark.
    :param str engine_home_path: (optional) Path for spark.
    :param str engine_home_volume_id: (optional) Default volume for spark.
    :param str engine_home_volume_name: (optional) Name of the volume.
    :param str engine_home_volume_storage_class: (optional) Storage class of the
          volume.
    :param str engine_home_volume_storage_size: (optional) Storage size of the
          volume.
    :param str instance_id: (optional) Instance to access the instance.
    :param str engine_sub_type: (optional) spark engine sub type.
    :param str managed_by: (optional) How is the spark instance managed.
    :param SparkScaleConfig scale_config: (optional) Spark instance scale
          configuration.
    """

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        connection_string: Optional[str] = None,
        default_config: Optional['SparkDefaultConfig'] = None,
        default_version: Optional[str] = None,
        engine_home_bucket_display_name: Optional[str] = None,
        engine_home_bucket_name: Optional[str] = None,
        engine_home_path: Optional[str] = None,
        engine_home_volume_id: Optional[str] = None,
        engine_home_volume_name: Optional[str] = None,
        engine_home_volume_storage_class: Optional[str] = None,
        engine_home_volume_storage_size: Optional[str] = None,
        instance_id: Optional[str] = None,
        engine_sub_type: Optional[str] = None,
        managed_by: Optional[str] = None,
        scale_config: Optional['SparkScaleConfig'] = None,
    ) -> None:
        """
        Initialize a SparkEngineDetailsPrototype object.

        :param str api_key: (optional) api key to work with the saas IAE instance.
        :param str connection_string: (optional) External engine connection string.
        :param SparkDefaultConfig default_config: (optional) Spark Default Config
               details.
        :param str default_version: (optional) The default spark version for the
               native engine.
        :param str engine_home_bucket_display_name: (optional) Default bucket name
               for spark.
        :param str engine_home_bucket_name: (optional) Default bucket for spark.
        :param str engine_home_path: (optional) Path for spark.
        :param str engine_home_volume_id: (optional) Default volume for spark.
        :param str engine_home_volume_name: (optional) Name of the volume.
        :param str engine_home_volume_storage_class: (optional) Storage class of
               the volume.
        :param str engine_home_volume_storage_size: (optional) Storage size of the
               volume.
        :param str instance_id: (optional) Instance to access the instance.
        :param str engine_sub_type: (optional) spark engine sub type.
        :param str managed_by: (optional) How is the spark instance managed.
        :param SparkScaleConfig scale_config: (optional) Spark instance scale
               configuration.
        """
        self.api_key = api_key
        self.connection_string = connection_string
        self.default_config = default_config
        self.default_version = default_version
        self.engine_home_bucket_display_name = engine_home_bucket_display_name
        self.engine_home_bucket_name = engine_home_bucket_name
        self.engine_home_path = engine_home_path
        self.engine_home_volume_id = engine_home_volume_id
        self.engine_home_volume_name = engine_home_volume_name
        self.engine_home_volume_storage_class = engine_home_volume_storage_class
        self.engine_home_volume_storage_size = engine_home_volume_storage_size
        self.instance_id = instance_id
        self.engine_sub_type = engine_sub_type
        self.managed_by = managed_by
        self.scale_config = scale_config

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SparkEngineDetailsPrototype':
        """Initialize a SparkEngineDetailsPrototype object from a json dictionary."""
        args = {}
        if (api_key := _dict.get('api_key')) is not None:
            args['api_key'] = api_key
        if (connection_string := _dict.get('connection_string')) is not None:
            args['connection_string'] = connection_string
        if (default_config := _dict.get('default_config')) is not None:
            args['default_config'] = SparkDefaultConfig.from_dict(default_config)
        if (default_version := _dict.get('default_version')) is not None:
            args['default_version'] = default_version
        if (engine_home_bucket_display_name := _dict.get('engine_home_bucket_display_name')) is not None:
            args['engine_home_bucket_display_name'] = engine_home_bucket_display_name
        if (engine_home_bucket_name := _dict.get('engine_home_bucket_name')) is not None:
            args['engine_home_bucket_name'] = engine_home_bucket_name
        if (engine_home_path := _dict.get('engine_home_path')) is not None:
            args['engine_home_path'] = engine_home_path
        if (engine_home_volume_id := _dict.get('engine_home_volume_id')) is not None:
            args['engine_home_volume_id'] = engine_home_volume_id
        if (engine_home_volume_name := _dict.get('engine_home_volume_name')) is not None:
            args['engine_home_volume_name'] = engine_home_volume_name
        if (engine_home_volume_storage_class := _dict.get('engine_home_volume_storage_class')) is not None:
            args['engine_home_volume_storage_class'] = engine_home_volume_storage_class
        if (engine_home_volume_storage_size := _dict.get('engine_home_volume_storage_size')) is not None:
            args['engine_home_volume_storage_size'] = engine_home_volume_storage_size
        if (instance_id := _dict.get('instance_id')) is not None:
            args['instance_id'] = instance_id
        if (engine_sub_type := _dict.get('engine_sub_type')) is not None:
            args['engine_sub_type'] = engine_sub_type
        if (managed_by := _dict.get('managed_by')) is not None:
            args['managed_by'] = managed_by
        if (scale_config := _dict.get('scale_config')) is not None:
            args['scale_config'] = SparkScaleConfig.from_dict(scale_config)
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
        if hasattr(self, 'default_config') and self.default_config is not None:
            if isinstance(self.default_config, dict):
                _dict['default_config'] = self.default_config
            else:
                _dict['default_config'] = self.default_config.to_dict()
        if hasattr(self, 'default_version') and self.default_version is not None:
            _dict['default_version'] = self.default_version
        if hasattr(self, 'engine_home_bucket_display_name') and self.engine_home_bucket_display_name is not None:
            _dict['engine_home_bucket_display_name'] = self.engine_home_bucket_display_name
        if hasattr(self, 'engine_home_bucket_name') and self.engine_home_bucket_name is not None:
            _dict['engine_home_bucket_name'] = self.engine_home_bucket_name
        if hasattr(self, 'engine_home_path') and self.engine_home_path is not None:
            _dict['engine_home_path'] = self.engine_home_path
        if hasattr(self, 'engine_home_volume_id') and self.engine_home_volume_id is not None:
            _dict['engine_home_volume_id'] = self.engine_home_volume_id
        if hasattr(self, 'engine_home_volume_name') and self.engine_home_volume_name is not None:
            _dict['engine_home_volume_name'] = self.engine_home_volume_name
        if hasattr(self, 'engine_home_volume_storage_class') and self.engine_home_volume_storage_class is not None:
            _dict['engine_home_volume_storage_class'] = self.engine_home_volume_storage_class
        if hasattr(self, 'engine_home_volume_storage_size') and self.engine_home_volume_storage_size is not None:
            _dict['engine_home_volume_storage_size'] = self.engine_home_volume_storage_size
        if hasattr(self, 'instance_id') and self.instance_id is not None:
            _dict['instance_id'] = self.instance_id
        if hasattr(self, 'engine_sub_type') and self.engine_sub_type is not None:
            _dict['engine_sub_type'] = self.engine_sub_type
        if hasattr(self, 'managed_by') and self.managed_by is not None:
            _dict['managed_by'] = self.managed_by
        if hasattr(self, 'scale_config') and self.scale_config is not None:
            if isinstance(self.scale_config, dict):
                _dict['scale_config'] = self.scale_config
            else:
                _dict['scale_config'] = self.scale_config.to_dict()
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


class SparkEngineResourceLimit:
    """
    Native spark engine resource quota.

    :param str cores: (optional) CPU.
    :param str memory: (optional) Memory in GiB.
    """

    def __init__(
        self,
        *,
        cores: Optional[str] = None,
        memory: Optional[str] = None,
    ) -> None:
        """
        Initialize a SparkEngineResourceLimit object.

        :param str cores: (optional) CPU.
        :param str memory: (optional) Memory in GiB.
        """
        self.cores = cores
        self.memory = memory

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SparkEngineResourceLimit':
        """Initialize a SparkEngineResourceLimit object from a json dictionary."""
        args = {}
        if (cores := _dict.get('cores')) is not None:
            args['cores'] = cores
        if (memory := _dict.get('memory')) is not None:
            args['memory'] = memory
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SparkEngineResourceLimit object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'cores') and self.cores is not None:
            _dict['cores'] = self.cores
        if hasattr(self, 'memory') and self.memory is not None:
            _dict['memory'] = self.memory
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SparkEngineResourceLimit object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SparkEngineResourceLimit') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SparkEngineResourceLimit') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SparkHistoryServer:
    """
    Native spark history server.

    :param str auto_termination_time: (optional) History server start time.
    :param str cores: (optional) History server cores.
    :param str memory: (optional) History server memory.
    :param str start_time: (optional) History server start time.
    :param str state: (optional) History server state.
    """

    def __init__(
        self,
        *,
        auto_termination_time: Optional[str] = None,
        cores: Optional[str] = None,
        memory: Optional[str] = None,
        start_time: Optional[str] = None,
        state: Optional[str] = None,
    ) -> None:
        """
        Initialize a SparkHistoryServer object.

        :param str auto_termination_time: (optional) History server start time.
        :param str cores: (optional) History server cores.
        :param str memory: (optional) History server memory.
        :param str start_time: (optional) History server start time.
        :param str state: (optional) History server state.
        """
        self.auto_termination_time = auto_termination_time
        self.cores = cores
        self.memory = memory
        self.start_time = start_time
        self.state = state

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SparkHistoryServer':
        """Initialize a SparkHistoryServer object from a json dictionary."""
        args = {}
        if (auto_termination_time := _dict.get('auto_termination_time')) is not None:
            args['auto_termination_time'] = auto_termination_time
        if (cores := _dict.get('cores')) is not None:
            args['cores'] = cores
        if (memory := _dict.get('memory')) is not None:
            args['memory'] = memory
        if (start_time := _dict.get('start_time')) is not None:
            args['start_time'] = start_time
        if (state := _dict.get('state')) is not None:
            args['state'] = state
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SparkHistoryServer object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'auto_termination_time') and self.auto_termination_time is not None:
            _dict['auto_termination_time'] = self.auto_termination_time
        if hasattr(self, 'cores') and self.cores is not None:
            _dict['cores'] = self.cores
        if hasattr(self, 'memory') and self.memory is not None:
            _dict['memory'] = self.memory
        if hasattr(self, 'start_time') and self.start_time is not None:
            _dict['start_time'] = self.start_time
        if hasattr(self, 'state') and self.state is not None:
            _dict['state'] = self.state
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SparkHistoryServer object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SparkHistoryServer') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SparkHistoryServer') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SparkScaleConfig:
    """
    Spark instance scale configuration.

    :param bool auto_scale_enabled: (optional) Enable/disable autoscaling.
    :param int current_number_of_nodes: (optional) Current node count.
    :param int maximum_number_of_nodes: (optional) Maximum node count.
    :param int minimum_number_of_nodes: (optional) Minimum node count.
    :param str node_type: (optional) Spark instance node type.
    :param int number_of_nodes: (optional) Node count.
    """

    def __init__(
        self,
        *,
        auto_scale_enabled: Optional[bool] = None,
        current_number_of_nodes: Optional[int] = None,
        maximum_number_of_nodes: Optional[int] = None,
        minimum_number_of_nodes: Optional[int] = None,
        node_type: Optional[str] = None,
        number_of_nodes: Optional[int] = None,
    ) -> None:
        """
        Initialize a SparkScaleConfig object.

        :param bool auto_scale_enabled: (optional) Enable/disable autoscaling.
        :param int current_number_of_nodes: (optional) Current node count.
        :param int maximum_number_of_nodes: (optional) Maximum node count.
        :param int minimum_number_of_nodes: (optional) Minimum node count.
        :param str node_type: (optional) Spark instance node type.
        :param int number_of_nodes: (optional) Node count.
        """
        self.auto_scale_enabled = auto_scale_enabled
        self.current_number_of_nodes = current_number_of_nodes
        self.maximum_number_of_nodes = maximum_number_of_nodes
        self.minimum_number_of_nodes = minimum_number_of_nodes
        self.node_type = node_type
        self.number_of_nodes = number_of_nodes

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SparkScaleConfig':
        """Initialize a SparkScaleConfig object from a json dictionary."""
        args = {}
        if (auto_scale_enabled := _dict.get('auto_scale_enabled')) is not None:
            args['auto_scale_enabled'] = auto_scale_enabled
        if (current_number_of_nodes := _dict.get('current_number_of_nodes')) is not None:
            args['current_number_of_nodes'] = current_number_of_nodes
        if (maximum_number_of_nodes := _dict.get('maximum_number_of_nodes')) is not None:
            args['maximum_number_of_nodes'] = maximum_number_of_nodes
        if (minimum_number_of_nodes := _dict.get('minimum_number_of_nodes')) is not None:
            args['minimum_number_of_nodes'] = minimum_number_of_nodes
        if (node_type := _dict.get('node_type')) is not None:
            args['node_type'] = node_type
        if (number_of_nodes := _dict.get('number_of_nodes')) is not None:
            args['number_of_nodes'] = number_of_nodes
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SparkScaleConfig object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'auto_scale_enabled') and self.auto_scale_enabled is not None:
            _dict['auto_scale_enabled'] = self.auto_scale_enabled
        if hasattr(self, 'current_number_of_nodes') and self.current_number_of_nodes is not None:
            _dict['current_number_of_nodes'] = self.current_number_of_nodes
        if hasattr(self, 'maximum_number_of_nodes') and self.maximum_number_of_nodes is not None:
            _dict['maximum_number_of_nodes'] = self.maximum_number_of_nodes
        if hasattr(self, 'minimum_number_of_nodes') and self.minimum_number_of_nodes is not None:
            _dict['minimum_number_of_nodes'] = self.minimum_number_of_nodes
        if hasattr(self, 'node_type') and self.node_type is not None:
            _dict['node_type'] = self.node_type
        if hasattr(self, 'number_of_nodes') and self.number_of_nodes is not None:
            _dict['number_of_nodes'] = self.number_of_nodes
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SparkScaleConfig object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SparkScaleConfig') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SparkScaleConfig') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SparkVolumeDetails:
    """
    Spark application volume.

    :param str mount_path: (optional) Path in the spark cluster for the mounted
          volume.
    :param str name: (optional) volume name.
    :param bool read_only: (optional) Read only flag.
    :param str source_sub_path: (optional) Path in the volume to be mounted.
    """

    def __init__(
        self,
        *,
        mount_path: Optional[str] = None,
        name: Optional[str] = None,
        read_only: Optional[bool] = None,
        source_sub_path: Optional[str] = None,
    ) -> None:
        """
        Initialize a SparkVolumeDetails object.

        :param str mount_path: (optional) Path in the spark cluster for the mounted
               volume.
        :param str name: (optional) volume name.
        :param bool read_only: (optional) Read only flag.
        :param str source_sub_path: (optional) Path in the volume to be mounted.
        """
        self.mount_path = mount_path
        self.name = name
        self.read_only = read_only
        self.source_sub_path = source_sub_path

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SparkVolumeDetails':
        """Initialize a SparkVolumeDetails object from a json dictionary."""
        args = {}
        if (mount_path := _dict.get('mount_path')) is not None:
            args['mount_path'] = mount_path
        if (name := _dict.get('name')) is not None:
            args['name'] = name
        if (read_only := _dict.get('read_only')) is not None:
            args['read_only'] = read_only
        if (source_sub_path := _dict.get('source_sub_path')) is not None:
            args['source_sub_path'] = source_sub_path
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SparkVolumeDetails object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'mount_path') and self.mount_path is not None:
            _dict['mount_path'] = self.mount_path
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'read_only') and self.read_only is not None:
            _dict['read_only'] = self.read_only
        if hasattr(self, 'source_sub_path') and self.source_sub_path is not None:
            _dict['source_sub_path'] = self.source_sub_path
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SparkVolumeDetails object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SparkVolumeDetails') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SparkVolumeDetails') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class StorageDetails:
    """
    storage details.

    :param str access_key: (optional) Access key ID, encrypted during bucket
          registration.
    :param str application_id: (optional) Application Id for bucket registration.
    :param str auth_mode: Auth mode types.
    :param str container_name: actual container name.
    :param str directory_id: (optional) Directory Id for bucket registration.
    :param str endpoint: ADLS endpoint.
    :param str sas_token: (optional) sas token, encrypted during bucket
          registration.
    :param str secret_key: (optional) Secret access key, encrypted during bucket
          registration.
    :param str storage_account_name: actual storage name.
    """

    def __init__(
        self,
        auth_mode: str,
        container_name: str,
        endpoint: str,
        storage_account_name: str,
        *,
        access_key: Optional[str] = None,
        application_id: Optional[str] = None,
        directory_id: Optional[str] = None,
        sas_token: Optional[str] = None,
        secret_key: Optional[str] = None,
    ) -> None:
        """
        Initialize a StorageDetails object.

        :param str auth_mode: Auth mode types.
        :param str container_name: actual container name.
        :param str endpoint: ADLS endpoint.
        :param str storage_account_name: actual storage name.
        :param str access_key: (optional) Access key ID, encrypted during bucket
               registration.
        :param str application_id: (optional) Application Id for bucket
               registration.
        :param str directory_id: (optional) Directory Id for bucket registration.
        :param str sas_token: (optional) sas token, encrypted during bucket
               registration.
        :param str secret_key: (optional) Secret access key, encrypted during
               bucket registration.
        """
        self.access_key = access_key
        self.application_id = application_id
        self.auth_mode = auth_mode
        self.container_name = container_name
        self.directory_id = directory_id
        self.endpoint = endpoint
        self.sas_token = sas_token
        self.secret_key = secret_key
        self.storage_account_name = storage_account_name

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'StorageDetails':
        """Initialize a StorageDetails object from a json dictionary."""
        args = {}
        if (access_key := _dict.get('access_key')) is not None:
            args['access_key'] = access_key
        if (application_id := _dict.get('application_id')) is not None:
            args['application_id'] = application_id
        if (auth_mode := _dict.get('auth_mode')) is not None:
            args['auth_mode'] = auth_mode
        else:
            raise ValueError('Required property \'auth_mode\' not present in StorageDetails JSON')
        if (container_name := _dict.get('container_name')) is not None:
            args['container_name'] = container_name
        else:
            raise ValueError('Required property \'container_name\' not present in StorageDetails JSON')
        if (directory_id := _dict.get('directory_id')) is not None:
            args['directory_id'] = directory_id
        if (endpoint := _dict.get('endpoint')) is not None:
            args['endpoint'] = endpoint
        else:
            raise ValueError('Required property \'endpoint\' not present in StorageDetails JSON')
        if (sas_token := _dict.get('sas_token')) is not None:
            args['sas_token'] = sas_token
        if (secret_key := _dict.get('secret_key')) is not None:
            args['secret_key'] = secret_key
        if (storage_account_name := _dict.get('storage_account_name')) is not None:
            args['storage_account_name'] = storage_account_name
        else:
            raise ValueError('Required property \'storage_account_name\' not present in StorageDetails JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a StorageDetails object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'access_key') and self.access_key is not None:
            _dict['access_key'] = self.access_key
        if hasattr(self, 'application_id') and self.application_id is not None:
            _dict['application_id'] = self.application_id
        if hasattr(self, 'auth_mode') and self.auth_mode is not None:
            _dict['auth_mode'] = self.auth_mode
        if hasattr(self, 'container_name') and self.container_name is not None:
            _dict['container_name'] = self.container_name
        if hasattr(self, 'directory_id') and self.directory_id is not None:
            _dict['directory_id'] = self.directory_id
        if hasattr(self, 'endpoint') and self.endpoint is not None:
            _dict['endpoint'] = self.endpoint
        if hasattr(self, 'sas_token') and self.sas_token is not None:
            _dict['sas_token'] = self.sas_token
        if hasattr(self, 'secret_key') and self.secret_key is not None:
            _dict['secret_key'] = self.secret_key
        if hasattr(self, 'storage_account_name') and self.storage_account_name is not None:
            _dict['storage_account_name'] = self.storage_account_name
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this StorageDetails object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'StorageDetails') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'StorageDetails') -> bool:
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
        if (message := _dict.get('message')) is not None:
            args['message'] = message
        if (message_code := _dict.get('message_code')) is not None:
            args['message_code'] = message_code
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


class SyncCatalogs:
    """
    catalogs definition.

    :param bool auto_add_new_tables: (optional) Auto add new table.
    :param bool sync_iceberg_md: (optional) Sync iceberg metadata.
    """

    def __init__(
        self,
        *,
        auto_add_new_tables: Optional[bool] = None,
        sync_iceberg_md: Optional[bool] = None,
    ) -> None:
        """
        Initialize a SyncCatalogs object.

        :param bool auto_add_new_tables: (optional) Auto add new table.
        :param bool sync_iceberg_md: (optional) Sync iceberg metadata.
        """
        self.auto_add_new_tables = auto_add_new_tables
        self.sync_iceberg_md = sync_iceberg_md

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SyncCatalogs':
        """Initialize a SyncCatalogs object from a json dictionary."""
        args = {}
        if (auto_add_new_tables := _dict.get('auto_add_new_tables')) is not None:
            args['auto_add_new_tables'] = auto_add_new_tables
        if (sync_iceberg_md := _dict.get('sync_iceberg_md')) is not None:
            args['sync_iceberg_md'] = sync_iceberg_md
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SyncCatalogs object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'auto_add_new_tables') and self.auto_add_new_tables is not None:
            _dict['auto_add_new_tables'] = self.auto_add_new_tables
        if hasattr(self, 'sync_iceberg_md') and self.sync_iceberg_md is not None:
            _dict['sync_iceberg_md'] = self.sync_iceberg_md
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SyncCatalogs object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SyncCatalogs') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SyncCatalogs') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class Table:
    """
    GetColumns OK.

    :param List[Column] columns: (optional) Columns.
    :param str table_name: (optional) Table name.
    """

    def __init__(
        self,
        *,
        columns: Optional[List['Column']] = None,
        table_name: Optional[str] = None,
    ) -> None:
        """
        Initialize a Table object.

        :param List[Column] columns: (optional) Columns.
        :param str table_name: (optional) Table name.
        """
        self.columns = columns
        self.table_name = table_name

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'Table':
        """Initialize a Table object from a json dictionary."""
        args = {}
        if (columns := _dict.get('columns')) is not None:
            args['columns'] = [Column.from_dict(v) for v in columns]
        if (table_name := _dict.get('table_name')) is not None:
            args['table_name'] = table_name
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a Table object from a json dictionary."""
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
        if hasattr(self, 'table_name') and self.table_name is not None:
            _dict['table_name'] = self.table_name
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this Table object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'Table') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'Table') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class TableCollection:
    """
    tables list.

    :param List[str] tables: (optional) List of the tables present in the schema.
    """

    def __init__(
        self,
        *,
        tables: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a TableCollection object.

        :param List[str] tables: (optional) List of the tables present in the
               schema.
        """
        self.tables = tables

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'TableCollection':
        """Initialize a TableCollection object from a json dictionary."""
        args = {}
        if (tables := _dict.get('tables')) is not None:
            args['tables'] = tables
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a TableCollection object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'tables') and self.tables is not None:
            _dict['tables'] = self.tables
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this TableCollection object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'TableCollection') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'TableCollection') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class TableColumDetail:
    """
    TableColumDetail.

    :param str bucket: (optional) Bucket linked to the catalog.
    :param str catalog: (optional) Catalog that this table belongs to.
    :param List[TableColumDetailColumnsItems] columns: (optional) List of all column
          information about the table.
    :param str owner: (optional) Name of the user who created the table.
    :param str schema: (optional) Schema that this table belongs to.
    :param str table: (optional) Name of the table.
    """

    def __init__(
        self,
        *,
        bucket: Optional[str] = None,
        catalog: Optional[str] = None,
        columns: Optional[List['TableColumDetailColumnsItems']] = None,
        owner: Optional[str] = None,
        schema: Optional[str] = None,
        table: Optional[str] = None,
    ) -> None:
        """
        Initialize a TableColumDetail object.

        :param str bucket: (optional) Bucket linked to the catalog.
        :param str catalog: (optional) Catalog that this table belongs to.
        :param List[TableColumDetailColumnsItems] columns: (optional) List of all
               column information about the table.
        :param str owner: (optional) Name of the user who created the table.
        :param str schema: (optional) Schema that this table belongs to.
        :param str table: (optional) Name of the table.
        """
        self.bucket = bucket
        self.catalog = catalog
        self.columns = columns
        self.owner = owner
        self.schema = schema
        self.table = table

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'TableColumDetail':
        """Initialize a TableColumDetail object from a json dictionary."""
        args = {}
        if (bucket := _dict.get('bucket')) is not None:
            args['bucket'] = bucket
        if (catalog := _dict.get('catalog')) is not None:
            args['catalog'] = catalog
        if (columns := _dict.get('columns')) is not None:
            args['columns'] = [TableColumDetailColumnsItems.from_dict(v) for v in columns]
        if (owner := _dict.get('owner')) is not None:
            args['owner'] = owner
        if (schema := _dict.get('schema')) is not None:
            args['schema'] = schema
        if (table := _dict.get('table')) is not None:
            args['table'] = table
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a TableColumDetail object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'bucket') and self.bucket is not None:
            _dict['bucket'] = self.bucket
        if hasattr(self, 'catalog') and self.catalog is not None:
            _dict['catalog'] = self.catalog
        if hasattr(self, 'columns') and self.columns is not None:
            columns_list = []
            for v in self.columns:
                if isinstance(v, dict):
                    columns_list.append(v)
                else:
                    columns_list.append(v.to_dict())
            _dict['columns'] = columns_list
        if hasattr(self, 'owner') and self.owner is not None:
            _dict['owner'] = self.owner
        if hasattr(self, 'schema') and self.schema is not None:
            _dict['schema'] = self.schema
        if hasattr(self, 'table') and self.table is not None:
            _dict['table'] = self.table
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this TableColumDetail object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'TableColumDetail') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'TableColumDetail') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class TableColumDetailColumnsItems:
    """
    TableColumDetailColumnsItems.

    :param str column: (optional) Name of the column.
    :param int index: (optional) column idx_integer.
    :param str type: (optional) data type for the column.
    """

    def __init__(
        self,
        *,
        column: Optional[str] = None,
        index: Optional[int] = None,
        type: Optional[str] = None,
    ) -> None:
        """
        Initialize a TableColumDetailColumnsItems object.

        :param str column: (optional) Name of the column.
        :param int index: (optional) column idx_integer.
        :param str type: (optional) data type for the column.
        """
        self.column = column
        self.index = index
        self.type = type

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'TableColumDetailColumnsItems':
        """Initialize a TableColumDetailColumnsItems object from a json dictionary."""
        args = {}
        if (column := _dict.get('column')) is not None:
            args['column'] = column
        if (index := _dict.get('index')) is not None:
            args['index'] = index
        if (type := _dict.get('type')) is not None:
            args['type'] = type
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a TableColumDetailColumnsItems object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'column') and self.column is not None:
            _dict['column'] = self.column
        if hasattr(self, 'index') and self.index is not None:
            _dict['index'] = self.index
        if hasattr(self, 'type') and self.type is not None:
            _dict['type'] = self.type
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this TableColumDetailColumnsItems object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'TableColumDetailColumnsItems') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'TableColumDetailColumnsItems') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class TablePatch:
    """
    UpdateTable body.

    :param str table_name: (optional) New table name.
    """

    def __init__(
        self,
        *,
        table_name: Optional[str] = None,
    ) -> None:
        """
        Initialize a TablePatch object.

        :param str table_name: (optional) New table name.
        """
        self.table_name = table_name

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'TablePatch':
        """Initialize a TablePatch object from a json dictionary."""
        args = {}
        if (table_name := _dict.get('table_name')) is not None:
            args['table_name'] = table_name
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a TablePatch object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'table_name') and self.table_name is not None:
            _dict['table_name'] = self.table_name
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this TablePatch object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'TablePatch') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'TablePatch') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class TableResponse:
    """
    Table response.

    :param str message: (optional) Response message string.
    :param str message_code: (optional) Message code string.
    :param List[TableColumDetail] tables: (optional) A list of all tables.
    """

    def __init__(
        self,
        *,
        message: Optional[str] = None,
        message_code: Optional[str] = None,
        tables: Optional[List['TableColumDetail']] = None,
    ) -> None:
        """
        Initialize a TableResponse object.

        :param str message: (optional) Response message string.
        :param str message_code: (optional) Message code string.
        :param List[TableColumDetail] tables: (optional) A list of all tables.
        """
        self.message = message
        self.message_code = message_code
        self.tables = tables

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'TableResponse':
        """Initialize a TableResponse object from a json dictionary."""
        args = {}
        if (message := _dict.get('message')) is not None:
            args['message'] = message
        if (message_code := _dict.get('message_code')) is not None:
            args['message_code'] = message_code
        if (tables := _dict.get('tables')) is not None:
            args['tables'] = [TableColumDetail.from_dict(v) for v in tables]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a TableResponse object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'message') and self.message is not None:
            _dict['message'] = self.message
        if hasattr(self, 'message_code') and self.message_code is not None:
            _dict['message_code'] = self.message_code
        if hasattr(self, 'tables') and self.tables is not None:
            tables_list = []
            for v in self.tables:
                if isinstance(v, dict):
                    tables_list.append(v)
                else:
                    tables_list.append(v.to_dict())
            _dict['tables'] = tables_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this TableResponse object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'TableResponse') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'TableResponse') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class TableResponseCollection:
    """
    Table response collection.

    :param str message: (optional) Response message string.
    :param str message_code: (optional) Message code string.
    :param List[TableResponse] tables: (optional) A list of all tables.
    """

    def __init__(
        self,
        *,
        message: Optional[str] = None,
        message_code: Optional[str] = None,
        tables: Optional[List['TableResponse']] = None,
    ) -> None:
        """
        Initialize a TableResponseCollection object.

        :param str message: (optional) Response message string.
        :param str message_code: (optional) Message code string.
        :param List[TableResponse] tables: (optional) A list of all tables.
        """
        self.message = message
        self.message_code = message_code
        self.tables = tables

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'TableResponseCollection':
        """Initialize a TableResponseCollection object from a json dictionary."""
        args = {}
        if (message := _dict.get('message')) is not None:
            args['message'] = message
        if (message_code := _dict.get('message_code')) is not None:
            args['message_code'] = message_code
        if (tables := _dict.get('tables')) is not None:
            args['tables'] = [TableResponse.from_dict(v) for v in tables]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a TableResponseCollection object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'message') and self.message is not None:
            _dict['message'] = self.message
        if hasattr(self, 'message_code') and self.message_code is not None:
            _dict['message_code'] = self.message_code
        if hasattr(self, 'tables') and self.tables is not None:
            tables_list = []
            for v in self.tables:
                if isinstance(v, dict):
                    tables_list.append(v)
                else:
                    tables_list.append(v.to_dict())
            _dict['tables'] = tables_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this TableResponseCollection object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'TableResponseCollection') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'TableResponseCollection') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class TableSnapshot:
    """
    TableSnapshot.

    :param str added_data_files: (optional) Added data files.
    :param str added_files_size: (optional) Added files size.
    :param str added_records: (optional) Added records.
    :param str changed_partition_count: (optional) Changed partition count.
    :param str committed_at: (optional) Committed at.
    :param str operation: (optional) Operation.
    :param str snapshot_id: (optional) Snapshot id.
    :param str total_data_files: (optional) Total data files.
    :param str total_delete_files: (optional) Total delete files.
    :param str total_equality_deletes: (optional) Total equality deletes.
    :param str total_position_deletes: (optional) Total position deletes.
    :param str total_records: (optional) Total records.
    """

    def __init__(
        self,
        *,
        added_data_files: Optional[str] = None,
        added_files_size: Optional[str] = None,
        added_records: Optional[str] = None,
        changed_partition_count: Optional[str] = None,
        committed_at: Optional[str] = None,
        operation: Optional[str] = None,
        snapshot_id: Optional[str] = None,
        total_data_files: Optional[str] = None,
        total_delete_files: Optional[str] = None,
        total_equality_deletes: Optional[str] = None,
        total_position_deletes: Optional[str] = None,
        total_records: Optional[str] = None,
    ) -> None:
        """
        Initialize a TableSnapshot object.

        :param str added_data_files: (optional) Added data files.
        :param str added_files_size: (optional) Added files size.
        :param str added_records: (optional) Added records.
        :param str changed_partition_count: (optional) Changed partition count.
        :param str committed_at: (optional) Committed at.
        :param str operation: (optional) Operation.
        :param str snapshot_id: (optional) Snapshot id.
        :param str total_data_files: (optional) Total data files.
        :param str total_delete_files: (optional) Total delete files.
        :param str total_equality_deletes: (optional) Total equality deletes.
        :param str total_position_deletes: (optional) Total position deletes.
        :param str total_records: (optional) Total records.
        """
        self.added_data_files = added_data_files
        self.added_files_size = added_files_size
        self.added_records = added_records
        self.changed_partition_count = changed_partition_count
        self.committed_at = committed_at
        self.operation = operation
        self.snapshot_id = snapshot_id
        self.total_data_files = total_data_files
        self.total_delete_files = total_delete_files
        self.total_equality_deletes = total_equality_deletes
        self.total_position_deletes = total_position_deletes
        self.total_records = total_records

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'TableSnapshot':
        """Initialize a TableSnapshot object from a json dictionary."""
        args = {}
        if (added_data_files := _dict.get('added_data_files')) is not None:
            args['added_data_files'] = added_data_files
        if (added_files_size := _dict.get('added_files_size')) is not None:
            args['added_files_size'] = added_files_size
        if (added_records := _dict.get('added_records')) is not None:
            args['added_records'] = added_records
        if (changed_partition_count := _dict.get('changed_partition_count')) is not None:
            args['changed_partition_count'] = changed_partition_count
        if (committed_at := _dict.get('committed_at')) is not None:
            args['committed_at'] = committed_at
        if (operation := _dict.get('operation')) is not None:
            args['operation'] = operation
        if (snapshot_id := _dict.get('snapshot_id')) is not None:
            args['snapshot_id'] = snapshot_id
        if (total_data_files := _dict.get('total_data_files')) is not None:
            args['total_data_files'] = total_data_files
        if (total_delete_files := _dict.get('total_delete_files')) is not None:
            args['total_delete_files'] = total_delete_files
        if (total_equality_deletes := _dict.get('total_equality_deletes')) is not None:
            args['total_equality_deletes'] = total_equality_deletes
        if (total_position_deletes := _dict.get('total_position_deletes')) is not None:
            args['total_position_deletes'] = total_position_deletes
        if (total_records := _dict.get('total_records')) is not None:
            args['total_records'] = total_records
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a TableSnapshot object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'added_data_files') and self.added_data_files is not None:
            _dict['added_data_files'] = self.added_data_files
        if hasattr(self, 'added_files_size') and self.added_files_size is not None:
            _dict['added_files_size'] = self.added_files_size
        if hasattr(self, 'added_records') and self.added_records is not None:
            _dict['added_records'] = self.added_records
        if hasattr(self, 'changed_partition_count') and self.changed_partition_count is not None:
            _dict['changed_partition_count'] = self.changed_partition_count
        if hasattr(self, 'committed_at') and self.committed_at is not None:
            _dict['committed_at'] = self.committed_at
        if hasattr(self, 'operation') and self.operation is not None:
            _dict['operation'] = self.operation
        if hasattr(self, 'snapshot_id') and self.snapshot_id is not None:
            _dict['snapshot_id'] = self.snapshot_id
        if hasattr(self, 'total_data_files') and self.total_data_files is not None:
            _dict['total_data_files'] = self.total_data_files
        if hasattr(self, 'total_delete_files') and self.total_delete_files is not None:
            _dict['total_delete_files'] = self.total_delete_files
        if hasattr(self, 'total_equality_deletes') and self.total_equality_deletes is not None:
            _dict['total_equality_deletes'] = self.total_equality_deletes
        if hasattr(self, 'total_position_deletes') and self.total_position_deletes is not None:
            _dict['total_position_deletes'] = self.total_position_deletes
        if hasattr(self, 'total_records') and self.total_records is not None:
            _dict['total_records'] = self.total_records
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


class TableSnapshotCollection:
    """
    TableSnapshot OK.

    :param List[TableSnapshot] snapshots: (optional) Snapshots.
    """

    def __init__(
        self,
        *,
        snapshots: Optional[List['TableSnapshot']] = None,
    ) -> None:
        """
        Initialize a TableSnapshotCollection object.

        :param List[TableSnapshot] snapshots: (optional) Snapshots.
        """
        self.snapshots = snapshots

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'TableSnapshotCollection':
        """Initialize a TableSnapshotCollection object from a json dictionary."""
        args = {}
        if (snapshots := _dict.get('snapshots')) is not None:
            args['snapshots'] = [TableSnapshot.from_dict(v) for v in snapshots]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a TableSnapshotCollection object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
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
        """Return a `str` version of this TableSnapshotCollection object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'TableSnapshotCollection') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'TableSnapshotCollection') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class UpdateSparkEngineBody:
    """
    UpdateEngine body.

    :param str description: (optional) Modified description.
    :param UpdateSparkEngineBodyEngineDetails engine_details: (optional) Engine
          details.
    :param str engine_display_name: (optional) Engine display name.
    :param List[str] tags: (optional) Tags.
    """

    def __init__(
        self,
        *,
        description: Optional[str] = None,
        engine_details: Optional['UpdateSparkEngineBodyEngineDetails'] = None,
        engine_display_name: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a UpdateSparkEngineBody object.

        :param str description: (optional) Modified description.
        :param UpdateSparkEngineBodyEngineDetails engine_details: (optional) Engine
               details.
        :param str engine_display_name: (optional) Engine display name.
        :param List[str] tags: (optional) Tags.
        """
        self.description = description
        self.engine_details = engine_details
        self.engine_display_name = engine_display_name
        self.tags = tags

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'UpdateSparkEngineBody':
        """Initialize a UpdateSparkEngineBody object from a json dictionary."""
        args = {}
        if (description := _dict.get('description')) is not None:
            args['description'] = description
        if (engine_details := _dict.get('engine_details')) is not None:
            args['engine_details'] = UpdateSparkEngineBodyEngineDetails.from_dict(engine_details)
        if (engine_display_name := _dict.get('engine_display_name')) is not None:
            args['engine_display_name'] = engine_display_name
        if (tags := _dict.get('tags')) is not None:
            args['tags'] = tags
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a UpdateSparkEngineBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'engine_details') and self.engine_details is not None:
            if isinstance(self.engine_details, dict):
                _dict['engine_details'] = self.engine_details
            else:
                _dict['engine_details'] = self.engine_details.to_dict()
        if hasattr(self, 'engine_display_name') and self.engine_display_name is not None:
            _dict['engine_display_name'] = self.engine_display_name
        if hasattr(self, 'tags') and self.tags is not None:
            _dict['tags'] = self.tags
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this UpdateSparkEngineBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'UpdateSparkEngineBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'UpdateSparkEngineBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class UpdateSparkEngineBodyEngineDetails:
    """
    Engine details.

    :param dict default_config: (optional) Dynamic dict.
    :param str default_version: (optional) The default spark version for the native
          engine.
    :param str engine_home_bucket_name: (optional) Default bucket for spark.
    :param bool resource_limit_enabled: (optional) Resource limit enabled flag.
    :param SparkEngineResourceLimit resource_limits: (optional) Native spark engine
          resource quota.
    """

    def __init__(
        self,
        *,
        default_config: Optional[dict] = None,
        default_version: Optional[str] = None,
        engine_home_bucket_name: Optional[str] = None,
        resource_limit_enabled: Optional[bool] = None,
        resource_limits: Optional['SparkEngineResourceLimit'] = None,
    ) -> None:
        """
        Initialize a UpdateSparkEngineBodyEngineDetails object.

        :param dict default_config: (optional) Dynamic dict.
        :param str default_version: (optional) The default spark version for the
               native engine.
        :param str engine_home_bucket_name: (optional) Default bucket for spark.
        :param bool resource_limit_enabled: (optional) Resource limit enabled flag.
        :param SparkEngineResourceLimit resource_limits: (optional) Native spark
               engine resource quota.
        """
        self.default_config = default_config
        self.default_version = default_version
        self.engine_home_bucket_name = engine_home_bucket_name
        self.resource_limit_enabled = resource_limit_enabled
        self.resource_limits = resource_limits

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'UpdateSparkEngineBodyEngineDetails':
        """Initialize a UpdateSparkEngineBodyEngineDetails object from a json dictionary."""
        args = {}
        if (default_config := _dict.get('default_config')) is not None:
            args['default_config'] = default_config
        if (default_version := _dict.get('default_version')) is not None:
            args['default_version'] = default_version
        if (engine_home_bucket_name := _dict.get('engine_home_bucket_name')) is not None:
            args['engine_home_bucket_name'] = engine_home_bucket_name
        if (resource_limit_enabled := _dict.get('resource_limit_enabled')) is not None:
            args['resource_limit_enabled'] = resource_limit_enabled
        if (resource_limits := _dict.get('resource_limits')) is not None:
            args['resource_limits'] = SparkEngineResourceLimit.from_dict(resource_limits)
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a UpdateSparkEngineBodyEngineDetails object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'default_config') and self.default_config is not None:
            _dict['default_config'] = self.default_config
        if hasattr(self, 'default_version') and self.default_version is not None:
            _dict['default_version'] = self.default_version
        if hasattr(self, 'engine_home_bucket_name') and self.engine_home_bucket_name is not None:
            _dict['engine_home_bucket_name'] = self.engine_home_bucket_name
        if hasattr(self, 'resource_limit_enabled') and self.resource_limit_enabled is not None:
            _dict['resource_limit_enabled'] = self.resource_limit_enabled
        if hasattr(self, 'resource_limits') and self.resource_limits is not None:
            if isinstance(self.resource_limits, dict):
                _dict['resource_limits'] = self.resource_limits
            else:
                _dict['resource_limits'] = self.resource_limits.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this UpdateSparkEngineBodyEngineDetails object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'UpdateSparkEngineBodyEngineDetails') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'UpdateSparkEngineBodyEngineDetails') -> bool:
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
        if (response := _dict.get('response')) is not None:
            args['response'] = SuccessResponse.from_dict(response)
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

##############################################################################
# Pagers
##############################################################################


class IngestionJobsPager:
    """
    IngestionJobsPager can be used to simplify the use of the "list_ingestion_jobs" method.
    """

    def __init__(
        self,
        *,
        client: WatsonxDataV2,
        auth_instance_id: str,
        jobs_per_page: int = None,
    ) -> None:
        """
        Initialize a IngestionJobsPager object.
        :param str auth_instance_id: watsonx.data instance ID.
        :param int jobs_per_page: (optional) Number of requested ingestion jobs.
        """
        self._has_next = True
        self._client = client
        self._page_context = {'next': None}
        self._auth_instance_id = auth_instance_id
        self._jobs_per_page = jobs_per_page

    def has_next(self) -> bool:
        """
        Returns true if there are potentially more results to be retrieved.
        """
        return self._has_next

    def get_next(self) -> List[dict]:
        """
        Returns the next page of results.
        :return: A List[dict], where each element is a dict that represents an instance of IngestionJob.
        :rtype: List[dict]
        """
        if not self.has_next():
            raise StopIteration(message='No more results available')

        result = self._client.list_ingestion_jobs(
            auth_instance_id=self._auth_instance_id,
            jobs_per_page=self._jobs_per_page,
            start=self._page_context.get('next'),
        ).get_result()

        next = None
        next_page_link = result.get('next')
        if next_page_link is not None:
            next = get_query_param(next_page_link.get('href'), 'start')
        self._page_context['next'] = next
        if next is None:
            self._has_next = False

        return result.get('ingestion_jobs')

    def get_all(self) -> List[dict]:
        """
        Returns all results by invoking get_next() repeatedly
        until all pages of results have been retrieved.
        :return: A List[dict], where each element is a dict that represents an instance of IngestionJob.
        :rtype: List[dict]
        """
        results = []
        while self.has_next():
            next_page = self.get_next()
            results.extend(next_page)
        return results
