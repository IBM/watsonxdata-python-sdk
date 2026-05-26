# -*- coding: utf-8 -*-
# (C) Copyright IBM Corp. 2025.
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

"""
Integration Tests for WatsonxDataV2
"""

from ibm_cloud_sdk_core import *
import io
import os
import pytest
from ibm_watsonxdata.watsonx_data_v2 import *

# Config file name
config_file = 'watsonx_data_v2.env'


class TestWatsonxDataV2:
    """
    Integration Test Class for WatsonxDataV2
    """

    @classmethod
    def setup_class(cls):
        if os.path.exists(config_file):
            os.environ['IBM_CREDENTIALS_FILE'] = config_file

            cls.watsonx_data_service = WatsonxDataV2.new_instance(
            )
            assert cls.watsonx_data_service is not None

            cls.config = read_external_sources(WatsonxDataV2.DEFAULT_SERVICE_NAME)
            assert cls.config is not None

            cls.watsonx_data_service.enable_retries()

        print('Setup complete.')

    needscredentials = pytest.mark.skipif(
        not os.path.exists(config_file), reason="External configuration not available, skipping..."
    )

    @needscredentials
    def test_list_bucket_registrations(self):
        response = self.watsonx_data_service.list_bucket_registrations(
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        bucket_registration_collection = response.get_result()
        assert bucket_registration_collection is not None

    @needscredentials
    def test_create_bucket_registration(self):
        # Construct a dict representation of a BucketCatalog model
        bucket_catalog_model = {
            'base_path': '/abc/def',
            'catalog_name': 'sampleCatalog',
            'catalog_tags': ['catalog_tag_1', 'catalog_tag_2'],
            'catalog_type': 'iceberg',
        }
        # Construct a dict representation of a BucketDetails model
        bucket_details_model = {
            'access_key': 'b9cbf248ea5c4c96947e64407108559j',
            'bucket_name': 'sample-bucket',
            'endpoint': 'https://s3.<region>.cloud-object-storage.appdomain.cloud/',
            'key_file': 'key_file',
            'provider': 'ibm_cos',
            'region': 'us-south',
            'secret_key': '13b4045cac1a0be54c9fjbe53cb22df5fn397cd2c45b66c87',
        }
        # Construct a dict representation of a StorageDetails model
        storage_details_model = {
            'access_key': '<access_key>',
            'application_id': '<application_id>',
            'auth_mode': '<account_key/sas/service_principle>',
            'container_name': 'sample-container',
            'directory_id': '<directory_id>',
            'endpoint': 'abfss://<container_name>@<storage_account_name>.dfs.core.windows.net/',
            'sas_token': '<sas_token>',
            'secret_key': 'secret_key',
            'storage_account_name': 'sample-storage',
        }

        response = self.watsonx_data_service.create_bucket_registration(
            bucket_type='ibm_cos',
            description='COS bucket for customer data',
            managed_by='ibm',
            associated_catalog=bucket_catalog_model,
            bucket_details=bucket_details_model,
            bucket_display_name='sample-bucket-displayname',
            region='us-south',
            storage_details=storage_details_model,
            tags=['bucket-tag1', 'bucket-tag2'],
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        bucket_registration = response.get_result()
        assert bucket_registration is not None

    @needscredentials
    def test_get_bucket_registration(self):
        response = self.watsonx_data_service.get_bucket_registration(
            bucket_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        bucket_registration = response.get_result()
        assert bucket_registration is not None

    @needscredentials
    def test_update_bucket_registration(self):
        # Construct a dict representation of a BucketDetails model
        bucket_details_model = {
            'access_key': 'b9cbf248ea5c4c96947e64407108559j',
            'bucket_name': 'sample-bucket',
            'endpoint': 'https://s3.<region>.cloud-object-storage.appdomain.cloud/',
            'key_file': 'key_file',
            'provider': 'ibm_cos',
            'region': 'us-south',
            'secret_key': '13b4045cac1a0be54c9fjbe53cb22df5fn397cd2c45b66c87',
        }
        # Construct a dict representation of a BucketRegistrationPatch model
        bucket_registration_patch_model = {
            'bucket_details': bucket_details_model,
            'bucket_display_name': 'sample-bucket-displayname',
            'description': 'COS bucket for customer data',
            'tags': ['testbucket', 'userbucket'],
        }

        response = self.watsonx_data_service.update_bucket_registration(
            bucket_id='testString',
            body=bucket_registration_patch_model,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        bucket_registration = response.get_result()
        assert bucket_registration is not None

    @needscredentials
    def test_create_activate_bucket(self):
        response = self.watsonx_data_service.create_activate_bucket(
            bucket_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        create_activate_bucket_created_body = response.get_result()
        assert create_activate_bucket_created_body is not None

    @needscredentials
    def test_add_bucket_catalog(self):
        response = self.watsonx_data_service.add_bucket_catalog(
            bucket_id='testString',
            base_path='/abc/def',
            catalog_name='sampleCatalog',
            catalog_tags=['catalog_tag_1', 'catalog_tag_2'],
            catalog_type='iceberg',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_list_bucket_objects(self):
        response = self.watsonx_data_service.list_bucket_objects(
            bucket_id='testString',
            auth_instance_id='testString',
            path='testString',
        )

        assert response.get_status_code() == 200
        bucket_registration_object_collection = response.get_result()
        assert bucket_registration_object_collection is not None

    @needscredentials
    def test_get_bucket_object_properties(self):
        # Construct a dict representation of a Path model
        path_model = {
            'path': 'string',
        }

        response = self.watsonx_data_service.get_bucket_object_properties(
            bucket_id='testString',
            paths=[path_model],
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        bucket_object_properties = response.get_result()
        assert bucket_object_properties is not None

    @needscredentials
    def test_create_hdfs_storage(self):
        response = self.watsonx_data_service.create_hdfs_storage(
            bucket_display_name='testString',
            bucket_type='testString',
            hms_thrift_uri='testString',
            hms_thrift_port=1,
            core_site='testString',
            hdfs_site='testString',
            kerberos='testString',
            catalog_name='testString',
            catalog_type='testString',
            krb5_config='testString',
            hive_keytab=io.BytesIO(b'This is a mock file.').getvalue(),
            hive_keytab_content_type='testString',
            hdfs_keytab=io.BytesIO(b'This is a mock file.').getvalue(),
            hdfs_keytab_content_type='testString',
            hive_server_principal='testString',
            hive_client_principal='testString',
            hdfs_principal='testString',
            description='testString',
            created_on='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        hdfs_storage_registration = response.get_result()
        assert hdfs_storage_registration is not None

    @needscredentials
    def test_list_database_registrations(self):
        response = self.watsonx_data_service.list_database_registrations(
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        database_registration_collection = response.get_result()
        assert database_registration_collection is not None

    @needscredentials
    def test_create_database_registration(self):
        # Construct a dict representation of a DatabaseCatalog model
        database_catalog_model = {
            'catalog_name': 'sampleCatalog',
            'catalog_tags': ['catalog_tag_1', 'catalog_tag_2'],
            'catalog_type': 'iceberg',
        }
        # Construct a dict representation of a DatabaseDetails model
        database_details_model = {
            'authentication_type': 'LDAP',
            'broker_authentication_password': 'samplepassword',
            'broker_authentication_type': 'PASSWORD',
            'broker_authentication_user': 'sampleuser',
            'certificate': 'contents of a pem/crt file',
            'certificate_extension': 'pem/crt',
            'connection_method': 'basic, apikey',
            'connection_mode': 'service_name',
            'connection_mode_value': 'orclpdb',
            'connection_type': 'JDBC, Arrow flight',
            'controller_authentication_password': 'samplepassword',
            'controller_authentication_type': 'PASSWORD',
            'controller_authentication_user': 'sampleuser',
            'cpd_hostname': 'samplecpdhostname',
            'credentials_key': 'eyJ0eXBlIjoic2VydmljZV9hY2NvdW50IiwicHJvamVjdF9pZCI6ImNvbm9wcy1iaWdxdWVyeSIsInByaXZhdGVfa2V5X2lkIjoiMGY3......',
            'database_name': 'new_database',
            'hostname': 'db2@<hostname>.com',
            'hostname_in_certificate': 'samplehostname',
            'hosts': 'abc.com:1234,xyz.com:4321',
            'informix_server': 'ol_informix1410',
            'password': 'samplepassword',
            'port': 4553,
            'project_id': 'conops-bigquery',
            'sasl': True,
            'service_api_key': 'sampleapikey',
            'service_hostname': 'api.dataplatform.dev.cloud.ibm.com',
            'service_password': 'samplepassword',
            'service_port': 443,
            'service_ssl': True,
            'service_token_url': 'sampletoakenurl',
            'service_username': 'sampleusername',
            'ssl': True,
            'tables': 'kafka_table_name',
            'username': 'sampleuser',
            'validate_server_certificate': True,
            'verify_host_name': True,
        }
        # Construct a dict representation of a DatabaseRegistrationPrototypeDatabasePropertiesItems model
        database_registration_prototype_database_properties_items_model = {
            'encrypt': True,
            'key': 'abc',
            'value': 'xyz',
        }

        response = self.watsonx_data_service.create_database_registration(
            database_display_name='new_database',
            database_type='db2',
            associated_catalog=database_catalog_model,
            created_on='1686792721',
            database_details=database_details_model,
            database_properties=[database_registration_prototype_database_properties_items_model],
            description='db2 extenal database description',
            tags=['testdatabase', 'userdatabase'],
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        database_registration = response.get_result()
        assert database_registration is not None

    @needscredentials
    def test_get_database(self):
        response = self.watsonx_data_service.get_database(
            database_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        database_registration = response.get_result()
        assert database_registration is not None

    @needscredentials
    def test_update_database(self):
        # Construct a dict representation of a DatabaseRegistrationPatchDatabaseDetails model
        database_registration_patch_database_details_model = {
            'password': 'samplepassword',
            'username': 'sampleuser',
        }
        # Construct a dict representation of a DatabaseRegistrationPatchTopicsItems model
        database_registration_patch_topics_items_model = {
            'created_on': '1686792721',
            'file_contents': 'sample file contents',
            'file_name': 'sample file name',
            'topic_name': 'customer',
        }
        # Construct a dict representation of a DatabaseRegistrationPatch model
        database_registration_patch_model = {
            'database_details': database_registration_patch_database_details_model,
            'database_display_name': 'new_database',
            'description': 'External database description',
            'tags': ['testdatabase', 'userdatabase'],
            'topics': [database_registration_patch_topics_items_model],
        }

        response = self.watsonx_data_service.update_database(
            database_id='testString',
            body=database_registration_patch_model,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        database_registration = response.get_result()
        assert database_registration is not None

    @needscredentials
    def test_list_driver_registration(self):
        response = self.watsonx_data_service.list_driver_registration(
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        driver_registration_collection = response.get_result()
        assert driver_registration_collection is not None

    @needscredentials
    def test_create_driver_registration(self):
        response = self.watsonx_data_service.create_driver_registration(
            driver=io.BytesIO(b'This is a mock file.').getvalue(),
            driver_name='testString',
            connection_type='testString',
            driver_content_type='testString',
            version='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        driver_registration = response.get_result()
        assert driver_registration is not None

    @needscredentials
    def test_update_driver_engines(self):
        # Construct a dict representation of a DriverRegistrationEnginePrototype model
        driver_registration_engine_prototype_model = {
            'engines': ['testString'],
        }

        response = self.watsonx_data_service.update_driver_engines(
            driver_id='testString',
            body=driver_registration_engine_prototype_model,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        driver_registration_engine = response.get_result()
        assert driver_registration_engine is not None

    @needscredentials
    def test_list_other_engines(self):
        response = self.watsonx_data_service.list_other_engines(
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        other_engine_collection = response.get_result()
        assert other_engine_collection is not None

    @needscredentials
    def test_create_other_engine(self):
        # Construct a dict representation of a OtherEngineDetailsBody model
        other_engine_details_body_model = {
            'connection_string': '1.2.3.4',
            'engine_type': 'netezza',
        }

        response = self.watsonx_data_service.create_other_engine(
            engine_details=other_engine_details_body_model,
            engine_display_name='sampleEngine01',
            description='external engine description',
            origin='external',
            tags=['tag1', 'tag2'],
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        other_engine = response.get_result()
        assert other_engine is not None

    @needscredentials
    def test_list_all_integrations(self):
        response = self.watsonx_data_service.list_all_integrations(
            auth_instance_id='testString',
            secret='testString',
            service_type='testString',
            state=['testString'],
        )

        assert response.get_status_code() == 200
        integration_collection = response.get_result()
        assert integration_collection is not None

    @needscredentials
    def test_create_integration(self):
        response = self.watsonx_data_service.create_integration(
            access_token='testString',
            apikey='testString',
            cross_account_integration=True,
            enable_data_policy_within_wxd=False,
            ikc_user_account_id='testString',
            password='password',
            resource='resource_name',
            service_type='ranger',
            storage_catalogs=['testString'],
            url='http://abcd.efgh.com:9876/',
            username='username',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        integration = response.get_result()
        assert integration is not None

    @needscredentials
    def test_get_integrations(self):
        response = self.watsonx_data_service.get_integrations(
            integration_id='testString',
            auth_instance_id='testString',
            secret='testString',
        )

        assert response.get_status_code() == 200
        integration = response.get_result()
        assert integration is not None

    @needscredentials
    def test_update_integration(self):
        # Construct a dict representation of a IntegrationPatch model
        integration_patch_model = {
            'access_token': 'uiOO90kklop',
            'apikey': 'apikey',
            'cross_account_integration': False,
            'enable_data_policy_within_wxd': True,
            'ikc_user_account_id': 'abcdefghijklmnopqrstuvwxyz',
            'password': 'password',
            'resource': 'resource_name',
            'state': 'active',
            'storage_catalogs': ['iceberg_data', 'hive_data'],
            'url': 'http://abcd.efgh.com:9876/',
            'username': 'username',
        }

        response = self.watsonx_data_service.update_integration(
            integration_id='testString',
            integration_patch=integration_patch_model,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        integration = response.get_result()
        assert integration is not None

    @needscredentials
    def test_list_db2_engines(self):
        response = self.watsonx_data_service.list_db2_engines(
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        db2_engine_collection = response.get_result()
        assert db2_engine_collection is not None

    @needscredentials
    def test_create_db2_engine(self):
        # Construct a dict representation of a Db2EngineDetailsBody model
        db2_engine_details_body_model = {
            'connection_string': '1.2.3.4',
        }

        response = self.watsonx_data_service.create_db2_engine(
            origin='external',
            description='db2 engine description',
            engine_details=db2_engine_details_body_model,
            engine_display_name='sampleEngine',
            tags=['tag1', 'tag2'],
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        db2_engine = response.get_result()
        assert db2_engine is not None

    @needscredentials
    def test_update_db2_engine(self):
        # Construct a dict representation of a Db2EnginePatch model
        db2_engine_patch_model = {
            'description': 'db2 engine updated description',
            'engine_display_name': 'sampleEngine',
            'tags': ['tag1', 'tag2'],
        }

        response = self.watsonx_data_service.update_db2_engine(
            engine_id='testString',
            body=db2_engine_patch_model,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        db2_engine = response.get_result()
        assert db2_engine is not None

    @needscredentials
    def test_list_netezza_engines(self):
        response = self.watsonx_data_service.list_netezza_engines(
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        netezza_engine_collection = response.get_result()
        assert netezza_engine_collection is not None

    @needscredentials
    def test_create_netezza_engine(self):
        # Construct a dict representation of a NetezzaEngineDetailsBody model
        netezza_engine_details_body_model = {
            'connection_string': '1.2.3.4',
        }

        response = self.watsonx_data_service.create_netezza_engine(
            origin='external',
            description='netezza engine description',
            engine_details=netezza_engine_details_body_model,
            engine_display_name='sampleEngine',
            tags=['tag1', 'tag2'],
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        netezza_engine = response.get_result()
        assert netezza_engine is not None

    @needscredentials
    def test_update_netezza_engine(self):
        # Construct a dict representation of a NetezzaEnginePatch model
        netezza_engine_patch_model = {
            'description': 'netezza engine updated description',
            'engine_display_name': 'sampleEngine',
            'tags': ['tag1', 'tag2'],
        }

        response = self.watsonx_data_service.update_netezza_engine(
            engine_id='testString',
            body=netezza_engine_patch_model,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        netezza_engine = response.get_result()
        assert netezza_engine is not None

    @needscredentials
    def test_create_execute_query(self):
        response = self.watsonx_data_service.create_execute_query(
            engine_id='testString',
            sql_string='select expenses from expenditure',
            catalog_name='sampleCatalog',
            schema_name='SampleSchema1',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        execute_query_created_body = response.get_result()
        assert execute_query_created_body is not None

    @needscredentials
    def test_list_instance_details(self):
        response = self.watsonx_data_service.list_instance_details(
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        watsonx_instance_details_collection = response.get_result()
        assert watsonx_instance_details_collection is not None

    @needscredentials
    def test_list_instance_service_details(self):
        response = self.watsonx_data_service.list_instance_service_details(
            target='testString',
            internal_host=False,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        engines_services_details = response.get_result()
        assert engines_services_details is not None

    @needscredentials
    def test_get_services_details(self):
        response = self.watsonx_data_service.get_services_details(
            target='testString',
            engine_or_service_type='testString',
            internal_host=False,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        services_details = response.get_result()
        assert services_details is not None

    @needscredentials
    def test_get_service_detail(self):
        response = self.watsonx_data_service.get_service_detail(
            target='testString',
            engine_or_service_type='testString',
            id='testString',
            database='testString',
            internal_host=False,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        connection_properties_details = response.get_result()
        assert connection_properties_details is not None

    @needscredentials
    def test_list_prestissimo_engines(self):
        response = self.watsonx_data_service.list_prestissimo_engines(
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        prestissimo_engine_collection = response.get_result()
        assert prestissimo_engine_collection is not None

    @needscredentials
    def test_create_prestissimo_engine(self):
        # Construct a dict representation of a PrestissimoNodeDescriptionBody model
        prestissimo_node_description_body_model = {
            'node_type': 'worker',
            'quantity': 38,
        }
        # Construct a dict representation of a PrestissimoEndpoints model
        prestissimo_endpoints_model = {
            'applications_api': '$HOST/v4/analytics_engines/c7b3fccf-badb-46b0-b1ef-9b3154424021/spark_applications/<application_id>',
            'history_server_endpoint': '$HOST/v2/spark/v3/instances/c7b3fccf-badb-46b0-b1ef-9b3154424021/spark_history_server',
            'spark_access_endpoint': '$HOST/analytics-engine/details/spark-<instance_id>',
            'spark_jobs_v4_endpoint': '$HOST/v4/analytics_engines/c7b3fccf-badb-46b0-b1ef-9b3154424021/spark_applications',
            'spark_kernel_endpoint': '$HOST/v4/analytics_engines/c7b3fccf-badb-46b0-b1ef-9b3154424021/jkg/api/kernels',
            'view_history_server': 'testString',
            'wxd_application_endpoint': '$HOST/v1/1698311655308796/engines/spark817/applications',
        }
        # Construct a dict representation of a PrestissimoEngineDetails model
        prestissimo_engine_details_model = {
            'api_key': '<api_key>',
            'connection_string': '1.2.3.4',
            'coordinator': prestissimo_node_description_body_model,
            'endpoints': prestissimo_endpoints_model,
            'instance_id': 'instance_id',
            'managed_by': 'fully/self',
            'metastore_host': '1.2.3.4',
            'size_config': 'starter',
            'worker': prestissimo_node_description_body_model,
        }

        response = self.watsonx_data_service.create_prestissimo_engine(
            origin='native',
            associated_catalogs=['hive_data'],
            description='prestissimo engine description',
            engine_details=prestissimo_engine_details_model,
            engine_display_name='sampleEngine',
            region='us-south',
            tags=['tag1', 'tag2'],
            version='1.2.3',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        prestissimo_engine = response.get_result()
        assert prestissimo_engine is not None

    @needscredentials
    def test_get_prestissimo_engine(self):
        response = self.watsonx_data_service.get_prestissimo_engine(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        prestissimo_engine = response.get_result()
        assert prestissimo_engine is not None

    @needscredentials
    def test_update_prestissimo_engine(self):
        # Construct a dict representation of a EnginePropertiesCatalog model
        engine_properties_catalog_model = {
            'coordinator': {'key1': 'testString'},
            'worker': {'key1': 'testString'},
        }
        # Construct a dict representation of a PrestissimoPropertiesCatalog model
        prestissimo_properties_catalog_model = {
            'catalog_name': engine_properties_catalog_model,
        }
        # Construct a dict representation of a PrestissimoNodeDescriptionBody model
        prestissimo_node_description_body_model = {
            'node_type': 'worker',
            'quantity': 38,
        }
        # Construct a dict representation of a EnginePropertiesOaiGenConfiguration model
        engine_properties_oai_gen_configuration_model = {
            'coordinator': prestissimo_node_description_body_model,
            'worker': prestissimo_node_description_body_model,
        }
        # Construct a dict representation of a PrestissimoEnginePropertiesVelox model
        prestissimo_engine_properties_velox_model = {
            'velox_property': ['testString'],
        }
        # Construct a dict representation of a PrestissimoEnginePropertiesOaiGen1Jvm model
        prestissimo_engine_properties_oai_gen1_jvm_model = {
            'coordinator': {'key1': 'testString'},
        }
        # Construct a dict representation of a PrestissimoEngineEngineProperties model
        prestissimo_engine_engine_properties_model = {
            'catalog': prestissimo_properties_catalog_model,
            'configuration': engine_properties_oai_gen_configuration_model,
            'velox': prestissimo_engine_properties_velox_model,
            'jvm': prestissimo_engine_properties_oai_gen1_jvm_model,
        }
        # Construct a dict representation of a PrestissimoEnginePropertiesCatalog model
        prestissimo_engine_properties_catalog_model = {
            'catalog_name': ['testString'],
        }
        # Construct a dict representation of a RemoveEnginePropertiesConfiguration model
        remove_engine_properties_configuration_model = {
            'coordinator': ['testString'],
            'worker': ['testString'],
        }
        # Construct a dict representation of a RemoveEnginePropertiesPrestissimoOaiGenJvm model
        remove_engine_properties_prestissimo_oai_gen_jvm_model = {
            'coordinator': ['testString'],
        }
        # Construct a dict representation of a RemoveEngineProperties model
        remove_engine_properties_model = {
            'catalog': prestissimo_engine_properties_catalog_model,
            'configuration': remove_engine_properties_configuration_model,
            'jvm': remove_engine_properties_prestissimo_oai_gen_jvm_model,
            'velox': ['testString'],
        }
        # Construct a dict representation of a PrestissimoEnginePatch model
        prestissimo_engine_patch_model = {
            'description': 'updated description for prestissimo engine',
            'engine_display_name': 'sampleEngine',
            'engine_properties': prestissimo_engine_engine_properties_model,
            'engine_restart': 'force',
            'remove_engine_properties': remove_engine_properties_model,
            'tags': ['tag1', 'tag2'],
        }

        response = self.watsonx_data_service.update_prestissimo_engine(
            engine_id='testString',
            body=prestissimo_engine_patch_model,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        prestissimo_engine = response.get_result()
        assert prestissimo_engine is not None

    @needscredentials
    def test_list_prestissimo_engine_catalogs(self):
        response = self.watsonx_data_service.list_prestissimo_engine_catalogs(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        catalog_collection = response.get_result()
        assert catalog_collection is not None

    @needscredentials
    def test_create_prestissimo_engine_catalogs(self):
        response = self.watsonx_data_service.create_prestissimo_engine_catalogs(
            engine_id='testString',
            catalog_name='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        catalog = response.get_result()
        assert catalog is not None

    @needscredentials
    def test_get_prestissimo_engine_catalog(self):
        response = self.watsonx_data_service.get_prestissimo_engine_catalog(
            engine_id='testString',
            catalog_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        catalog = response.get_result()
        assert catalog is not None

    @needscredentials
    def test_pause_prestissimo_engine(self):
        response = self.watsonx_data_service.pause_prestissimo_engine(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_run_prestissimo_explain_statement(self):
        response = self.watsonx_data_service.run_prestissimo_explain_statement(
            engine_id='testString',
            statement='show schemas in catalog_name',
            format='json',
            type='io',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        result_prestissimo_explain_statement = response.get_result()
        assert result_prestissimo_explain_statement is not None

    @needscredentials
    def test_run_prestissimo_explain_analyze_statement(self):
        response = self.watsonx_data_service.run_prestissimo_explain_analyze_statement(
            engine_id='testString',
            statement='show schemas in catalog_name',
            verbose=True,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        result_run_prestissimo_explain_analyze_statement = response.get_result()
        assert result_run_prestissimo_explain_analyze_statement is not None

    @needscredentials
    def test_restart_prestissimo_engine(self):
        response = self.watsonx_data_service.restart_prestissimo_engine(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_resume_prestissimo_engine(self):
        response = self.watsonx_data_service.resume_prestissimo_engine(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_scale_prestissimo_engine(self):
        # Construct a dict representation of a PrestissimoNodeDescriptionBody model
        prestissimo_node_description_body_model = {
            'node_type': 'worker',
            'quantity': 38,
        }

        response = self.watsonx_data_service.scale_prestissimo_engine(
            engine_id='testString',
            coordinator=prestissimo_node_description_body_model,
            worker=prestissimo_node_description_body_model,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 202
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_list_presto_engines(self):
        response = self.watsonx_data_service.list_presto_engines(
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        presto_engine_collection = response.get_result()
        assert presto_engine_collection is not None

    @needscredentials
    def test_create_presto_engine(self):
        # Construct a dict representation of a NodeDescriptionBody model
        node_description_body_model = {
            'node_type': 'worker',
            'quantity': 38,
        }
        # Construct a dict representation of a EngineDetailsBody model
        engine_details_body_model = {
            'api_key': '<api_key>',
            'connection_string': '1.2.3.4',
            'coordinator': node_description_body_model,
            'instance_id': 'instance_id',
            'managed_by': 'fully/self',
            'size_config': 'starter',
            'worker': node_description_body_model,
        }

        response = self.watsonx_data_service.create_presto_engine(
            origin='native',
            associated_catalogs=['iceberg-data', 'hive-data'],
            description='presto engine for running sql queries',
            engine_details=engine_details_body_model,
            engine_display_name='sampleEngine',
            region='us-south',
            tags=['tag1', 'tag2'],
            version='1.2.3',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        presto_engine = response.get_result()
        assert presto_engine is not None

    @needscredentials
    def test_get_presto_engine(self):
        response = self.watsonx_data_service.get_presto_engine(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        presto_engine = response.get_result()
        assert presto_engine is not None

    @needscredentials
    def test_update_presto_engine(self):
        # Construct a dict representation of a EnginePropertiesCatalog model
        engine_properties_catalog_model = {
            'coordinator': {'key1': 'testString'},
            'worker': {'key1': 'testString'},
        }
        # Construct a dict representation of a PrestoEnginePropertiesCatalog model
        presto_engine_properties_catalog_model = {
            'catalog_name': engine_properties_catalog_model,
        }
        # Construct a dict representation of a EnginePropertiesOaiGen1Configuration model
        engine_properties_oai_gen1_configuration_model = {
            'coordinator': {'key1': 'testString'},
            'worker': {'key1': 'testString'},
        }
        # Construct a dict representation of a PrestoEnginePropertiesEventListener model
        presto_engine_properties_event_listener_model = {
            'event_listener_property': 'testString',
        }
        # Construct a dict representation of a PrestoEnginePropertiesGlobal model
        presto_engine_properties_global_model = {
            'global_property': 'enable-mixed-case-support:true',
        }
        # Construct a dict representation of a EnginePropertiesOaiGen1Jvm model
        engine_properties_oai_gen1_jvm_model = {
            'coordinator': {'key1': 'testString'},
            'worker': {'key1': 'testString'},
        }
        # Construct a dict representation of a PrestoEnginePropertiesJMX model
        presto_engine_properties_jmx_model = {
            'global_property': 'watsonx_data_presto_cluster_memory_manager_cluster_memory_bytes:presto.memory<name=ClusterMemoryManager><>ClusterMemoryBytes',
        }
        # Construct a dict representation of a EnginePropertiesLogConfiguration model
        engine_properties_log_configuration_model = {
            'coordinator': {'key1': 'testString'},
            'worker': {'key1': 'testString'},
        }
        # Construct a dict representation of a PrestoEngineEngineProperties model
        presto_engine_engine_properties_model = {
            'catalog': presto_engine_properties_catalog_model,
            'configuration': engine_properties_oai_gen1_configuration_model,
            'event_listener': presto_engine_properties_event_listener_model,
            'global': presto_engine_properties_global_model,
            'jvm': engine_properties_oai_gen1_jvm_model,
            'jmx_exporter_config': presto_engine_properties_jmx_model,
            'log_config': engine_properties_log_configuration_model,
        }
        # Construct a dict representation of a RemoveEnginePropertiesOaiGenConfiguration model
        remove_engine_properties_oai_gen_configuration_model = {
            'coordinator': ['testString'],
            'worker': ['testString'],
        }
        # Construct a dict representation of a RemoveEnginePropertiesOaiGenJvm model
        remove_engine_properties_oai_gen_jvm_model = {
            'coordinator': ['testString'],
            'worker': ['testString'],
        }
        # Construct a dict representation of a RemoveEnginePropertiesLogConfig model
        remove_engine_properties_log_config_model = {
            'coordinator': ['testString'],
            'worker': ['testString'],
        }
        # Construct a dict representation of a PrestoEnginePatchRemoveEngineProperties model
        presto_engine_patch_remove_engine_properties_model = {
            'catalog': presto_engine_properties_catalog_model,
            'configuration': remove_engine_properties_oai_gen_configuration_model,
            'jvm': remove_engine_properties_oai_gen_jvm_model,
            'event_listener': ['testString'],
            'global': ['testString'],
            'jmx_exporter_config': ['testString'],
            'log_config': remove_engine_properties_log_config_model,
        }
        # Construct a dict representation of a PrestoEnginePatch model
        presto_engine_patch_model = {
            'description': 'updated description for presto engine',
            'engine_display_name': 'sampleEngine',
            'engine_properties': presto_engine_engine_properties_model,
            'engine_restart': 'force',
            'remove_engine_properties': presto_engine_patch_remove_engine_properties_model,
            'tags': ['tag1', 'tag2'],
        }

        response = self.watsonx_data_service.update_presto_engine(
            engine_id='testString',
            body=presto_engine_patch_model,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        presto_engine = response.get_result()
        assert presto_engine is not None

    @needscredentials
    def test_list_presto_engine_catalogs(self):
        response = self.watsonx_data_service.list_presto_engine_catalogs(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        catalog_collection = response.get_result()
        assert catalog_collection is not None

    @needscredentials
    def test_create_presto_engine_catalogs(self):
        response = self.watsonx_data_service.create_presto_engine_catalogs(
            engine_id='testString',
            catalog_name='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        catalog = response.get_result()
        assert catalog is not None

    @needscredentials
    def test_get_presto_engine_catalog(self):
        response = self.watsonx_data_service.get_presto_engine_catalog(
            engine_id='testString',
            catalog_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        catalog = response.get_result()
        assert catalog is not None

    @needscredentials
    def test_pause_presto_engine(self):
        response = self.watsonx_data_service.pause_presto_engine(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        create_engine_pause_created_body = response.get_result()
        assert create_engine_pause_created_body is not None

    @needscredentials
    def test_run_explain_statement(self):
        response = self.watsonx_data_service.run_explain_statement(
            engine_id='testString',
            statement='show schemas in catalog_name',
            format='json',
            type='io',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        run_explain_statement_ok_body = response.get_result()
        assert run_explain_statement_ok_body is not None

    @needscredentials
    def test_run_explain_analyze_statement(self):
        response = self.watsonx_data_service.run_explain_analyze_statement(
            engine_id='testString',
            statement='show schemas in catalog_name',
            verbose=True,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        run_explain_analyze_statement_ok_body = response.get_result()
        assert run_explain_analyze_statement_ok_body is not None

    @needscredentials
    def test_restart_presto_engine(self):
        response = self.watsonx_data_service.restart_presto_engine(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        create_engine_restart_created_body = response.get_result()
        assert create_engine_restart_created_body is not None

    @needscredentials
    def test_resume_presto_engine(self):
        response = self.watsonx_data_service.resume_presto_engine(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        create_engine_resume_created_body = response.get_result()
        assert create_engine_resume_created_body is not None

    @needscredentials
    def test_scale_presto_engine(self):
        # Construct a dict representation of a NodeDescription model
        node_description_model = {
            'node_type': 'starter',
            'quantity': 38,
        }

        response = self.watsonx_data_service.scale_presto_engine(
            engine_id='testString',
            coordinator=node_description_model,
            worker=node_description_model,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 202
        create_engine_scale_created_body = response.get_result()
        assert create_engine_scale_created_body is not None

    @needscredentials
    def test_get_sal_integration(self):
        response = self.watsonx_data_service.get_sal_integration(
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        sal_integration = response.get_result()
        assert sal_integration is not None

    @needscredentials
    def test_create_sal_integration(self):
        response = self.watsonx_data_service.create_sal_integration(
            apikey='12efd3raq',
            engine_id='presto-01',
            storage_resource_crn='crn:v1:staging:public:cloud-object-storage:global:a/a7026b374f39f570d20984c1ac6ecf63:5778e94f-c8c7-46a8-9878-d5eeadb51161',
            storage_type='bmcos_object_storage',
            trial_plan=True,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        sal_integration = response.get_result()
        assert sal_integration is not None

    @needscredentials
    def test_update_sal_integration(self):
        # Construct a dict representation of a SalIntegrationPatch model
        sal_integration_patch_model = {
            'op': 'add',
            'path': 'storage',
            'value': 'new-apikey',
        }

        response = self.watsonx_data_service.update_sal_integration(
            body=sal_integration_patch_model,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        sal_integration = response.get_result()
        assert sal_integration is not None

    @needscredentials
    def test_create_sal_integration_enrichment(self):
        # Construct a dict representation of a EnrichmentObj model
        enrichment_obj_model = {
            'catalog': 'iceberg_data',
            'operation': 'create',
            'schema': 'testString',
            'tables': ['testString'],
        }

        response = self.watsonx_data_service.create_sal_integration_enrichment(
            enrichment_prototype=enrichment_obj_model,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_get_sal_integration_enrichment_assets(self):
        response = self.watsonx_data_service.get_sal_integration_enrichment_assets(
            project_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        sal_integration_enrichment_assets = response.get_result()
        assert sal_integration_enrichment_assets is not None

    @needscredentials
    def test_get_sal_integration_enrichment_data_asset(self):
        response = self.watsonx_data_service.get_sal_integration_enrichment_data_asset(
            project_id='testString',
            asset_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        sal_integration_enrichment_data_asset = response.get_result()
        assert sal_integration_enrichment_data_asset is not None

    @needscredentials
    def test_get_sal_integration_enrichment_job_run_logs(self):
        response = self.watsonx_data_service.get_sal_integration_enrichment_job_run_logs(
            job_id='testString',
            job_run_id='testString',
            project_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        sal_integration_enrichment_job_run_logs = response.get_result()
        assert sal_integration_enrichment_job_run_logs is not None

    @needscredentials
    def test_get_sal_integration_enrichment_job_runs(self):
        response = self.watsonx_data_service.get_sal_integration_enrichment_job_runs(
            job_id='testString',
            project_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        sal_integration_enrichment_job_run = response.get_result()
        assert sal_integration_enrichment_job_run is not None

    @needscredentials
    def test_get_sal_integration_enrichment_jobs(self):
        response = self.watsonx_data_service.get_sal_integration_enrichment_jobs(
            wkc_project_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        sal_integration_enrichment_jobs = response.get_result()
        assert sal_integration_enrichment_jobs is not None

    @needscredentials
    def test_get_sal_integration_glossary_terms(self):
        response = self.watsonx_data_service.get_sal_integration_glossary_terms(
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        sal_integration_glossary_terms = response.get_result()
        assert sal_integration_glossary_terms is not None

    @needscredentials
    def test_get_sal_integration_mappings(self):
        response = self.watsonx_data_service.get_sal_integration_mappings(
            catalog_name='testString',
            schema_name='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        sal_integration_mappings = response.get_result()
        assert sal_integration_mappings is not None

    @needscredentials
    def test_get_sal_integration_enrichment_global_settings(self):
        response = self.watsonx_data_service.get_sal_integration_enrichment_global_settings(
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        sal_integration_enrichment_settings = response.get_result()
        assert sal_integration_enrichment_settings is not None

    @needscredentials
    def test_create_sal_integration_enrichment_global_settings(self):
        # Construct a dict representation of a SalIntegrationEnrichmentSettingsSemanticExpansionDescriptionGenerationConfiguration model
        sal_integration_enrichment_settings_semantic_expansion_description_generation_configuration_model = {
            'assignment_threshold': 0.14,
            'suggestion_threshold': 0.9,
        }
        # Construct a dict representation of a SalIntegrationEnrichmentSettingsSemanticExpansionNameExpansionConfiguration model
        sal_integration_enrichment_settings_semantic_expansion_name_expansion_configuration_model = {
            'assignment_threshold': 0.1,
            'suggestion_threshold': 0.1,
        }
        # Construct a dict representation of a SalIntegrationEnrichmentSettingsSemanticExpansion model
        sal_integration_enrichment_settings_semantic_expansion_model = {
            'description_generation': True,
            'description_generation_configuration': sal_integration_enrichment_settings_semantic_expansion_description_generation_configuration_model,
            'name_expansion': True,
            'name_expansion_configuration': sal_integration_enrichment_settings_semantic_expansion_name_expansion_configuration_model,
        }
        # Construct a dict representation of a SalIntegrationEnrichmentSettingsTermAssignment model
        sal_integration_enrichment_settings_term_assignment_model = {
            'class_based_assignments': False,
            'evaluate_negative_assignments': False,
            'llm_based_assignments': False,
            'ml_based_assignments_custom': False,
            'ml_based_assignments_default': False,
            'name_matching': False,
            'term_assignment_threshold': 0.3,
            'term_suggestion_threshold': 0.4,
        }

        response = self.watsonx_data_service.create_sal_integration_enrichment_global_settings(
            semantic_expansion=sal_integration_enrichment_settings_semantic_expansion_model,
            term_assignment=sal_integration_enrichment_settings_term_assignment_model,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        sal_integration_enrichment_settings = response.get_result()
        assert sal_integration_enrichment_settings is not None

    @needscredentials
    def test_get_sal_integration_enrichment_settings(self):
        response = self.watsonx_data_service.get_sal_integration_enrichment_settings(
            project_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        sal_integration_enrichment_settings = response.get_result()
        assert sal_integration_enrichment_settings is not None

    @needscredentials
    def test_create_sal_integration_enrichment_settings(self):
        # Construct a dict representation of a SalIntegrationEnrichmentSettingsSemanticExpansionDescriptionGenerationConfiguration model
        sal_integration_enrichment_settings_semantic_expansion_description_generation_configuration_model = {
            'assignment_threshold': 0.14,
            'suggestion_threshold': 0.9,
        }
        # Construct a dict representation of a SalIntegrationEnrichmentSettingsSemanticExpansionNameExpansionConfiguration model
        sal_integration_enrichment_settings_semantic_expansion_name_expansion_configuration_model = {
            'assignment_threshold': 0.1,
            'suggestion_threshold': 0.1,
        }
        # Construct a dict representation of a SalIntegrationEnrichmentSettingsSemanticExpansion model
        sal_integration_enrichment_settings_semantic_expansion_model = {
            'description_generation': True,
            'description_generation_configuration': sal_integration_enrichment_settings_semantic_expansion_description_generation_configuration_model,
            'name_expansion': True,
            'name_expansion_configuration': sal_integration_enrichment_settings_semantic_expansion_name_expansion_configuration_model,
        }
        # Construct a dict representation of a SalIntegrationEnrichmentSettingsTermAssignment model
        sal_integration_enrichment_settings_term_assignment_model = {
            'class_based_assignments': False,
            'evaluate_negative_assignments': False,
            'llm_based_assignments': False,
            'ml_based_assignments_custom': False,
            'ml_based_assignments_default': False,
            'name_matching': False,
            'term_assignment_threshold': 0.3,
            'term_suggestion_threshold': 0.4,
        }

        response = self.watsonx_data_service.create_sal_integration_enrichment_settings(
            semantic_expansion=sal_integration_enrichment_settings_semantic_expansion_model,
            term_assignment=sal_integration_enrichment_settings_term_assignment_model,
            project_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_create_sal_integration_upload_glossary(self):
        response = self.watsonx_data_service.create_sal_integration_upload_glossary(
            replace_option='all',
            glossary_csv=io.BytesIO(b'This is a mock file.').getvalue(),
            glossary_csv_content_type='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        sal_integration_upload_glossary = response.get_result()
        assert sal_integration_upload_glossary is not None

    @needscredentials
    def test_get_sal_integration_upload_glossary_status(self):
        response = self.watsonx_data_service.get_sal_integration_upload_glossary_status(
            process_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        sal_integration_upload_glossary_status = response.get_result()
        assert sal_integration_upload_glossary_status is not None

    @needscredentials
    def test_list_spark_engines(self):
        response = self.watsonx_data_service.list_spark_engines(
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        spark_engine_collection = response.get_result()
        assert spark_engine_collection is not None

    @needscredentials
    def test_create_spark_engine(self):
        # Construct a dict representation of a SparkDefaultConfig model
        spark_default_config_model = {
            'config1': 'testString',
            'config2': 'testString',
        }
        # Construct a dict representation of a SparkScaleConfig model
        spark_scale_config_model = {
            'auto_scale_enabled': True,
            'current_number_of_nodes': 2,
            'maximum_number_of_nodes': 5,
            'minimum_number_of_nodes': 1,
            'node_type': 'small',
            'number_of_nodes': 5,
        }
        # Construct a dict representation of a SparkEngineDetailsPrototype model
        spark_engine_details_prototype_model = {
            'api_key': 'apikey',
            'connection_string': '1.2.3.4',
            'default_config': spark_default_config_model,
            'default_version': '3.3',
            'engine_home_bucket_display_name': 'test-spark-bucket',
            'engine_home_bucket_name': '4fec0f8b-888a-4c16-8f38-250c8499e6ce-customer',
            'engine_home_path': 'spark/spark1234',
            'engine_home_volume_id': '1704979825978585',
            'engine_home_volume_name': 'my-volume',
            'engine_home_volume_storage_class': 'nfs-client',
            'engine_home_volume_storage_size': '5Gi',
            'engine_sub_type': 'java/cpp',
            'instance_id': 'spark-id',
            'managed_by': 'fully/self',
            'scale_config': spark_scale_config_model,
        }

        response = self.watsonx_data_service.create_spark_engine(
            origin='native',
            associated_catalogs=['iceberg-data'],
            description='testString',
            engine_details=spark_engine_details_prototype_model,
            engine_display_name='test-native',
            status='testString',
            tags=['testString'],
            type='spark',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 202
        spark_engine = response.get_result()
        assert spark_engine is not None

    @needscredentials
    def test_get_spark_engine(self):
        response = self.watsonx_data_service.get_spark_engine(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        spark_engine = response.get_result()
        assert spark_engine is not None

    @needscredentials
    def test_update_spark_engine(self):
        # Construct a dict representation of a SparkEngineResourceLimit model
        spark_engine_resource_limit_model = {
            'cores': '1',
            'memory': '4G',
        }
        # Construct a dict representation of a UpdateSparkEngineBodyEngineDetails model
        update_spark_engine_body_engine_details_model = {
            'default_config': {'config1': 'value1', 'config2': 'value2'},
            'default_version': '3.4',
            'engine_home_bucket_name': 'test-spark-bucket',
            'resource_limit_enabled': True,
            'resource_limits': spark_engine_resource_limit_model,
        }
        # Construct a dict representation of a UpdateSparkEngineBody model
        update_spark_engine_body_model = {
            'description': 'Updated Description',
            'engine_details': update_spark_engine_body_engine_details_model,
            'engine_display_name': 'Updated Display Name',
            'tags': ['tag1', 'tag2'],
        }

        response = self.watsonx_data_service.update_spark_engine(
            engine_id='testString',
            body=update_spark_engine_body_model,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        spark_engine = response.get_result()
        assert spark_engine is not None

    @needscredentials
    def test_list_spark_engine_applications(self):
        response = self.watsonx_data_service.list_spark_engine_applications(
            engine_id='testString',
            auth_instance_id='testString',
            state=['testString'],
        )

        assert response.get_status_code() == 200
        spark_engine_application_status_collection = response.get_result()
        assert spark_engine_application_status_collection is not None

    @needscredentials
    def test_create_spark_engine_application(self):
        # Construct a dict representation of a SparkApplicationConfig model
        spark_application_config_model = {
            'spark_sample_config_properpty': 'testString',
        }
        # Construct a dict representation of a SparkApplicationEnv model
        spark_application_env_model = {
            'sample_env_key': 'testString',
        }
        # Construct a dict representation of a SparkApplicationDetails model
        spark_application_details_model = {
            'application': '/opt/ibm/spark/examples/src/main/python/wordcount.py',
            'arguments': ['/opt/ibm/spark/examples/src/main/resources/people.txt'],
            'class': 'org.apache.spark.examples.SparkPi',
            'conf': spark_application_config_model,
            'env': spark_application_env_model,
            'files': 's3://mybucket/myfile.txt',
            'jars': 'testString',
            'name': 'SparkApplicaton1',
            'packages': 'org.apache.spark:example_1.2.3',
            'repositories': 'https://repo1.maven.org/maven2/',
            'spark_version': '3.3',
        }
        # Construct a dict representation of a SparkVolumeDetails model
        spark_volume_details_model = {
            'mount_path': '/mount/path',
            'name': 'my-volume',
            'read_only': True,
            'source_sub_path': '/source/path',
        }

        response = self.watsonx_data_service.create_spark_engine_application(
            engine_id='testString',
            application_details=spark_application_details_model,
            job_endpoint='testString',
            service_instance_id='testString',
            type='iae',
            volumes=[spark_volume_details_model],
            auth_instance_id='testString',
            state=['testString'],
        )

        assert response.get_status_code() == 201
        spark_engine_application_status = response.get_result()
        assert spark_engine_application_status is not None

    @needscredentials
    def test_get_spark_engine_application_status(self):
        response = self.watsonx_data_service.get_spark_engine_application_status(
            engine_id='testString',
            application_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        spark_engine_application_status = response.get_result()
        assert spark_engine_application_status is not None

    @needscredentials
    def test_list_spark_engine_catalogs(self):
        response = self.watsonx_data_service.list_spark_engine_catalogs(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        catalog_collection = response.get_result()
        assert catalog_collection is not None

    @needscredentials
    def test_create_spark_engine_catalogs(self):
        response = self.watsonx_data_service.create_spark_engine_catalogs(
            engine_id='testString',
            catalog_name='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        catalog = response.get_result()
        assert catalog is not None

    @needscredentials
    def test_get_spark_engine_catalog(self):
        response = self.watsonx_data_service.get_spark_engine_catalog(
            engine_id='testString',
            catalog_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        catalog = response.get_result()
        assert catalog is not None

    @needscredentials
    def test_get_spark_engine_history_server(self):
        response = self.watsonx_data_service.get_spark_engine_history_server(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        spark_history_server = response.get_result()
        assert spark_history_server is not None

    @needscredentials
    def test_start_spark_engine_history_server(self):
        response = self.watsonx_data_service.start_spark_engine_history_server(
            engine_id='testString',
            cores='1',
            memory='4G',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        spark_history_server = response.get_result()
        assert spark_history_server is not None

    @needscredentials
    def test_pause_spark_engine(self):
        response = self.watsonx_data_service.pause_spark_engine(
            engine_id='testString',
            force=True,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_resume_spark_engine(self):
        response = self.watsonx_data_service.resume_spark_engine(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_scale_spark_engine(self):
        response = self.watsonx_data_service.scale_spark_engine(
            engine_id='testString',
            number_of_nodes=2,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 202
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_list_spark_versions(self):
        response = self.watsonx_data_service.list_spark_versions(
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        list_spark_versions_ok_body = response.get_result()
        assert list_spark_versions_ok_body is not None

    @needscredentials
    def test_list_catalogs(self):
        response = self.watsonx_data_service.list_catalogs(
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        catalog_collection = response.get_result()
        assert catalog_collection is not None

    @needscredentials
    def test_get_catalog(self):
        response = self.watsonx_data_service.get_catalog(
            catalog_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        catalog = response.get_result()
        assert catalog is not None

    @needscredentials
    def test_list_schemas(self):
        response = self.watsonx_data_service.list_schemas(
            engine_id='testString',
            catalog_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        list_schemas_ok_body = response.get_result()
        assert list_schemas_ok_body is not None

    @needscredentials
    def test_create_schema(self):
        response = self.watsonx_data_service.create_schema(
            engine_id='testString',
            catalog_id='testString',
            custom_path='sample-path',
            schema_name='SampleSchema1',
            bucket_name='sample-bucket',
            hostname='db2@hostname.com',
            port=4553,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        create_schema_created_body = response.get_result()
        assert create_schema_created_body is not None

    @needscredentials
    def test_list_tables(self):
        response = self.watsonx_data_service.list_tables(
            catalog_id='testString',
            schema_id='testString',
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        table_collection = response.get_result()
        assert table_collection is not None

    @needscredentials
    def test_get_table(self):
        response = self.watsonx_data_service.get_table(
            catalog_id='testString',
            schema_id='testString',
            table_id='testString',
            engine_id='testString',
            type='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        table = response.get_result()
        assert table is not None

    @needscredentials
    def test_update_table(self):
        # Construct a dict representation of a TablePatch model
        table_patch_model = {
            'table_name': 'updated_table_name',
        }

        response = self.watsonx_data_service.update_table(
            catalog_id='testString',
            schema_id='testString',
            table_id='testString',
            engine_id='testString',
            body=table_patch_model,
            type='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        table = response.get_result()
        assert table is not None

    @needscredentials
    def test_list_columns(self):
        response = self.watsonx_data_service.list_columns(
            engine_id='testString',
            catalog_id='testString',
            schema_id='testString',
            table_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        column_collection = response.get_result()
        assert column_collection is not None

    @needscredentials
    def test_create_columns(self):
        # Construct a dict representation of a Column model
        column_model = {
            'column_name': 'expenses',
            'comment': 'expenses column',
            'extra': 'varchar',
            'length': '30',
            'scale': '2',
            'precision': '10',
            'type': 'varchar',
        }

        response = self.watsonx_data_service.create_columns(
            engine_id='testString',
            catalog_id='testString',
            schema_id='testString',
            table_id='testString',
            columns=[column_model],
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        column_collection = response.get_result()
        assert column_collection is not None

    @needscredentials
    def test_update_column(self):
        # Construct a dict representation of a ColumnPatch model
        column_patch_model = {
            'column_name': 'expenses',
        }

        response = self.watsonx_data_service.update_column(
            engine_id='testString',
            catalog_id='testString',
            schema_id='testString',
            table_id='testString',
            column_id='testString',
            body=column_patch_model,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        column = response.get_result()
        assert column is not None

    @needscredentials
    def test_list_table_snapshots(self):
        response = self.watsonx_data_service.list_table_snapshots(
            engine_id='testString',
            catalog_id='testString',
            schema_id='testString',
            table_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        table_snapshot_collection = response.get_result()
        assert table_snapshot_collection is not None

    @needscredentials
    def test_rollback_table(self):
        response = self.watsonx_data_service.rollback_table(
            engine_id='testString',
            catalog_id='testString',
            schema_id='testString',
            table_id='testString',
            snapshot_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        replace_snapshot_created_body = response.get_result()
        assert replace_snapshot_created_body is not None

    @needscredentials
    def test_update_sync_catalog(self):
        # Construct a dict representation of a SyncCatalogs model
        sync_catalogs_model = {
            'auto_add_new_tables': True,
            'sync_iceberg_md': True,
        }

        response = self.watsonx_data_service.update_sync_catalog(
            catalog_id='testString',
            body=sync_catalogs_model,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        update_sync_catalog_ok_body = response.get_result()
        assert update_sync_catalog_ok_body is not None

    @needscredentials
    def test_list_milvus_services(self):
        response = self.watsonx_data_service.list_milvus_services(
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        milvus_service_collection = response.get_result()
        assert milvus_service_collection is not None

    @needscredentials
    def test_create_milvus_service(self):
        response = self.watsonx_data_service.create_milvus_service(
            bucket_name='Sample bucket name',
            origin='native',
            root_path='Sample path',
            service_display_name='sampleService',
            bucket_type='Sample bucket type',
            description='milvus service for running sql queries',
            tags=['tag1', 'tag2'],
            tshirt_size='small',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        milvus_service = response.get_result()
        assert milvus_service is not None

    @needscredentials
    def test_get_milvus_service(self):
        response = self.watsonx_data_service.get_milvus_service(
            service_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        milvus_service = response.get_result()
        assert milvus_service is not None

    @needscredentials
    def test_update_milvus_service(self):
        # Construct a dict representation of a MilvusServicePatch model
        milvus_service_patch_model = {
            'description': 'updated description for milvus service',
            'service_display_name': 'sampleService',
            'tags': ['tag1', 'tag2'],
        }

        response = self.watsonx_data_service.update_milvus_service(
            service_id='testString',
            body=milvus_service_patch_model,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        milvus_service = response.get_result()
        assert milvus_service is not None

    @needscredentials
    def test_update_milvus_service_bucket(self):
        # Construct a dict representation of a MilvusServiceBucketPatch model
        milvus_service_bucket_patch_model = {
            'bucket_name': 'Sample bucket name',
            'managed_by': 'customer',
            'root_path': 'Sample path',
            'tshirt_size': 'small',
        }

        response = self.watsonx_data_service.update_milvus_service_bucket(
            service_id='testString',
            body=milvus_service_bucket_patch_model,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        milvus_service = response.get_result()
        assert milvus_service is not None

    @needscredentials
    def test_list_milvus_service_databases(self):
        response = self.watsonx_data_service.list_milvus_service_databases(
            service_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        milvus_service_databases = response.get_result()
        assert milvus_service_databases is not None

    @needscredentials
    def test_list_milvus_database_collections(self):
        response = self.watsonx_data_service.list_milvus_database_collections(
            service_id='testString',
            database_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        milvus_database_collections = response.get_result()
        assert milvus_database_collections is not None

    @needscredentials
    def test_create_milvus_service_pause(self):
        response = self.watsonx_data_service.create_milvus_service_pause(
            service_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_create_milvus_service_resume(self):
        response = self.watsonx_data_service.create_milvus_service_resume(
            service_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_create_milvus_service_scale(self):
        response = self.watsonx_data_service.create_milvus_service_scale(
            service_id='testString',
            tshirt_size='small',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_list_ingestion_jobs(self):
        response = self.watsonx_data_service.list_ingestion_jobs(
            auth_instance_id='testString',
            start='1',
            jobs_per_page=1,
        )

        assert response.get_status_code() == 200
        ingestion_job_collection = response.get_result()
        assert ingestion_job_collection is not None

    @needscredentials
    def test_list_ingestion_jobs_with_pager(self):
        all_results = []

        # Test get_next().
        pager = IngestionJobsPager(
            client=self.watsonx_data_service,
            auth_instance_id='testString',
            jobs_per_page=1,
        )
        while pager.has_next():
            next_page = pager.get_next()
            assert next_page is not None
            all_results.extend(next_page)

        # Test get_all().
        pager = IngestionJobsPager(
            client=self.watsonx_data_service,
            auth_instance_id='testString',
            jobs_per_page=1,
        )
        all_items = pager.get_all()
        assert all_items is not None

        assert len(all_results) == len(all_items)
        print(f'\nlist_ingestion_jobs() returned a total of {len(all_results)} items(s) using IngestionJobsPager.')

    @needscredentials
    def test_create_ingestion_jobs(self):
        # Construct a dict representation of a IngestionJobPrototypeCsvProperty model
        ingestion_job_prototype_csv_property_model = {
            'encoding': 'utf-8',
            'escape_character': '\\\\',
            'field_delimiter': ',',
            'header': True,
            'line_delimiter': '\\n',
        }
        # Construct a dict representation of a IngestionJobPrototypeExecuteConfig model
        ingestion_job_prototype_execute_config_model = {
            'driver_cores': 1,
            'driver_memory': '2G',
            'executor_cores': 1,
            'executor_memory': '2G',
            'num_executors': 1,
        }

        response = self.watsonx_data_service.create_ingestion_jobs(
            auth_instance_id='testString',
            job_id='ingestion-1699459946935',
            source_data_files='s3://demobucket/data/yellow_tripdata_2022-01.parquet',
            target_table='demodb.test.targettable',
            username='user1',
            create_if_not_exist=False,
            csv_property=ingestion_job_prototype_csv_property_model,
            engine_id='spark123',
            execute_config=ingestion_job_prototype_execute_config_model,
            partition_by='col1, col2',
            schema='{"type":"struct","schema-id":0,"fields":[{"id":1,"name":"ID","required":true,"type":"int"},{"id":2,"name":"Name","required":true,"type":"string"}]}',
            source_file_type='csv',
            validate_csv_header=False,
        )

        assert response.get_status_code() == 202
        ingestion_job = response.get_result()
        assert ingestion_job is not None

    @needscredentials
    def test_create_ingestion_jobs_local_files(self):
        response = self.watsonx_data_service.create_ingestion_jobs_local_files(
            auth_instance_id='testString',
            source_data_file=io.BytesIO(b'This is a mock file.').getvalue(),
            target_table='testString',
            job_id='testString',
            username='testString',
            source_data_file_content_type='testString',
            source_file_type='csv',
            csv_property='testString',
            create_if_not_exist=False,
            validate_csv_header=False,
            execute_config='testString',
            engine_id='testString',
        )

        assert response.get_status_code() == 202
        ingestion_job = response.get_result()
        assert ingestion_job is not None

    @needscredentials
    def test_get_ingestion_job(self):
        response = self.watsonx_data_service.get_ingestion_job(
            job_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        ingestion_job = response.get_result()
        assert ingestion_job is not None

    @needscredentials
    def test_create_preview_ingestion_file(self):
        # Construct a dict representation of a PreviewIngestionFilePrototypeCsvProperty model
        preview_ingestion_file_prototype_csv_property_model = {
            'encoding': 'utf-8',
            'escape_character': '\\\\',
            'field_delimiter': ',',
            'header': True,
            'line_delimiter': '\\n',
        }

        response = self.watsonx_data_service.create_preview_ingestion_file(
            auth_instance_id='testString',
            source_data_files='s3://demobucket/data/yellow_tripdata_2022-01.parquet',
            csv_property=preview_ingestion_file_prototype_csv_property_model,
            source_file_type='csv',
        )

        assert response.get_status_code() == 201
        preview_ingestion_file = response.get_result()
        assert preview_ingestion_file is not None

    @needscredentials
    def test_get_endpoints(self):
        response = self.watsonx_data_service.get_endpoints(
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        endpoint_collection = response.get_result()
        assert endpoint_collection is not None

    @needscredentials
    def test_register_table(self):
        response = self.watsonx_data_service.register_table(
            catalog_id='testString',
            schema_id='testString',
            metadata_location='s3a://bucketname/path/to/table/metadata_location/_delta_log',
            table_name='table1',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        register_table_created_body = response.get_result()
        assert register_table_created_body is not None

    @needscredentials
    def test_load_table(self):
        response = self.watsonx_data_service.load_table(
            catalog_id='testString',
            schema_id='testString',
            table_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        load_table_response = response.get_result()
        assert load_table_response is not None

    @needscredentials
    def test_get_all_columns(self):
        response = self.watsonx_data_service.get_all_columns(
            table_name='testString',
            catalog_name='testString',
            schema_name='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        columns_response = response.get_result()
        assert columns_response is not None

    @needscredentials
    def test_list_all_schemas(self):
        response = self.watsonx_data_service.list_all_schemas(
            catalog_name='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        schema_response_collection = response.get_result()
        assert schema_response_collection is not None

    @needscredentials
    def test_get_schema_details(self):
        response = self.watsonx_data_service.get_schema_details(
            schema_name='testString',
            catalog_name='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        schema_response = response.get_result()
        assert schema_response is not None

    @needscredentials
    def test_list_all_tables(self):
        response = self.watsonx_data_service.list_all_tables(
            catalog_name='testString',
            schema_name='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        table_response_collection = response.get_result()
        assert table_response_collection is not None

    @needscredentials
    def test_get_table_details(self):
        response = self.watsonx_data_service.get_table_details(
            table_name='testString',
            catalog_name='testString',
            schema_name='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        table_response = response.get_result()
        assert table_response is not None

    @needscredentials
    def test_delete_bucket_registration(self):
        response = self.watsonx_data_service.delete_bucket_registration(
            bucket_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_deactivate_bucket(self):
        response = self.watsonx_data_service.delete_deactivate_bucket(
            bucket_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_database_catalog(self):
        response = self.watsonx_data_service.delete_database_catalog(
            database_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_driver_registration(self):
        response = self.watsonx_data_service.delete_driver_registration(
            driver_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_driver_engines(self):
        response = self.watsonx_data_service.delete_driver_engines(
            driver_id='testString',
            engine_ids='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_other_engine(self):
        response = self.watsonx_data_service.delete_other_engine(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_integration(self):
        response = self.watsonx_data_service.delete_integration(
            integration_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_db2_engine(self):
        response = self.watsonx_data_service.delete_db2_engine(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_netezza_engine(self):
        response = self.watsonx_data_service.delete_netezza_engine(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_prestissimo_engine(self):
        response = self.watsonx_data_service.delete_prestissimo_engine(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_prestissimo_engine_catalogs(self):
        response = self.watsonx_data_service.delete_prestissimo_engine_catalogs(
            engine_id='testString',
            catalog_names='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_engine(self):
        response = self.watsonx_data_service.delete_engine(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_presto_engine_catalogs(self):
        response = self.watsonx_data_service.delete_presto_engine_catalogs(
            engine_id='testString',
            catalog_names='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_sal_integration(self):
        response = self.watsonx_data_service.delete_sal_integration()

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_spark_engine(self):
        response = self.watsonx_data_service.delete_spark_engine(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_spark_engine_applications(self):
        response = self.watsonx_data_service.delete_spark_engine_applications(
            engine_id='testString',
            application_id='testString',
            auth_instance_id='testString',
            state=['testString'],
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_spark_engine_catalogs(self):
        response = self.watsonx_data_service.delete_spark_engine_catalogs(
            engine_id='testString',
            catalog_names='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_spark_engine_history_server(self):
        response = self.watsonx_data_service.delete_spark_engine_history_server(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_schema(self):
        response = self.watsonx_data_service.delete_schema(
            engine_id='testString',
            catalog_id='testString',
            schema_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_table(self):
        response = self.watsonx_data_service.delete_table(
            catalog_id='testString',
            schema_id='testString',
            table_id='testString',
            engine_id='testString',
            type='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_column(self):
        response = self.watsonx_data_service.delete_column(
            engine_id='testString',
            catalog_id='testString',
            schema_id='testString',
            table_id='testString',
            column_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_milvus_service(self):
        response = self.watsonx_data_service.delete_milvus_service(
            service_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_ingestion_jobs(self):
        response = self.watsonx_data_service.delete_ingestion_jobs(
            job_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 204
