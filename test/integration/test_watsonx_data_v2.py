# -*- coding: utf-8 -*-
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
        list_bucket_registrations_ok_body = response.get_result()
        assert list_bucket_registrations_ok_body is not None

    @needscredentials
    def test_create_bucket_registration(self):
        # Construct a dict representation of a BucketDetails model
        bucket_details_model = {
            'access_key': '<access_key>',
            'bucket_name': 'sample-bucket',
            'endpoint': 'https://s3.<region>.cloud-object-storage.appdomain.cloud/',
            'secret_key': 'secret_key',
        }

        response = self.watsonx_data_service.create_bucket_registration(
            bucket_details=bucket_details_model,
            bucket_type='ibm_cos',
            catalog_name='sampleCatalog',
            description='COS bucket for customer data',
            managed_by='ibm',
            table_type='iceberg',
            bucket_display_name='sample-bucket-displayname',
            bucket_tags=['read customer data', 'write customer data\''],
            catalog_tags=['catalog_tag_1', 'catalog_tag_2'],
            region='us-south',
            state='active',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        create_bucket_registration_created_body = response.get_result()
        assert create_bucket_registration_created_body is not None

    @needscredentials
    def test_get_bucket_registration(self):
        response = self.watsonx_data_service.get_bucket_registration(
            bucket_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        get_bucket_registration_ok_body = response.get_result()
        assert get_bucket_registration_ok_body is not None

    @needscredentials
    def test_update_bucket_registration(self):
        # Construct a dict representation of a JsonPatchOperation model
        json_patch_operation_model = {
            'op': 'add',
            'path': 'testString',
            'from': 'testString',
            'value': 'testString',
        }

        response = self.watsonx_data_service.update_bucket_registration(
            bucket_id='testString',
            body=[json_patch_operation_model],
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        update_bucket_registration_ok_body = response.get_result()
        assert update_bucket_registration_ok_body is not None

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
    def test_list_bucket_objects(self):
        response = self.watsonx_data_service.list_bucket_objects(
            bucket_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        list_bucket_objects_ok_body = response.get_result()
        assert list_bucket_objects_ok_body is not None

    @needscredentials
    def test_test_bucket_connection(self):
        response = self.watsonx_data_service.test_bucket_connection(
            access_key='<access_key>',
            bucket_name='sample-bucket',
            bucket_type='ibm_cos',
            endpoint='https://s3.<region>.cloud-object-storage.appdomain.cloud/',
            region='us-south',
            secret_key='secret_key',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        test_bucket_connection_ok_body = response.get_result()
        assert test_bucket_connection_ok_body is not None

    @needscredentials
    def test_create_driver_database_catalog(self):
        response = self.watsonx_data_service.create_driver_database_catalog(
            database_display_name='testString',
            database_type='testString',
            catalog_name='testString',
            hostname='testString',
            port='testString',
            driver=io.BytesIO(b'This is a mock file.').getvalue(),
            driver_content_type='testString',
            driver_file_name='testString',
            certificate='testString',
            certificate_extension='testString',
            ssl='testString',
            username='testString',
            password='testString',
            database_name='testString',
            description='testString',
            created_on='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        create_driver_database_catalog_created_body = response.get_result()
        assert create_driver_database_catalog_created_body is not None

    @needscredentials
    def test_list_database_registrations(self):
        response = self.watsonx_data_service.list_database_registrations(
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        list_database_registrations_ok_body = response.get_result()
        assert list_database_registrations_ok_body is not None

    @needscredentials
    def test_create_database_registration(self):
        # Construct a dict representation of a RegisterDatabaseCatalogBodyDatabaseDetails model
        register_database_catalog_body_database_details_model = {
            'certificate': 'contents of a pem/crt file',
            'certificate_extension': 'pem/crt',
            'database_name': 'new_database',
            'hostname': 'db2@<hostname>.com',
            'hosts': 'abc.com:1234,xyz.com:4321',
            'password': 'samplepassword',
            'port': 4553,
            'sasl': True,
            'ssl': True,
            'tables': 'kafka_table_name',
            'username': 'sampleuser',
        }
        # Construct a dict representation of a RegisterDatabaseCatalogBodyDatabasePropertiesItems model
        register_database_catalog_body_database_properties_items_model = {
            'encrypt': True,
            'key': 'abc',
            'value': 'xyz',
        }

        response = self.watsonx_data_service.create_database_registration(
            catalog_name='sampleCatalog',
            database_display_name='new_database',
            database_type='db2',
            created_on=38,
            database_details=register_database_catalog_body_database_details_model,
            database_properties=[register_database_catalog_body_database_properties_items_model],
            description='db2 extenal database description',
            tags=['tag_1', 'tag_2'],
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        create_database_registration_created_body = response.get_result()
        assert create_database_registration_created_body is not None

    @needscredentials
    def test_get_database(self):
        response = self.watsonx_data_service.get_database(
            database_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        get_database_ok_body = response.get_result()
        assert get_database_ok_body is not None

    @needscredentials
    def test_update_database(self):
        # Construct a dict representation of a JsonPatchOperation model
        json_patch_operation_model = {
            'op': 'add',
            'path': 'testString',
            'from': 'testString',
            'value': 'testString',
        }

        response = self.watsonx_data_service.update_database(
            database_id='testString',
            body=[json_patch_operation_model],
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        update_database_ok_body = response.get_result()
        assert update_database_ok_body is not None

    @needscredentials
    def test_validate_database_connection(self):
        # Construct a dict representation of a ValidateDatabaseBodyDatabaseDetails model
        validate_database_body_database_details_model = {
            'database_name': 'sampledatabase',
            'hostname': 'db2@hostname.com',
            'password': 'samplepassword',
            'port': 4553,
            'sasl': True,
            'ssl': True,
            'tables': 'kafka_table_name',
            'username': 'sampleuser',
        }

        response = self.watsonx_data_service.validate_database_connection(
            database_details=validate_database_body_database_details_model,
            database_type='netezza',
            certificate='contents of a pem/crt file',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        validate_database_connection_ok_body = response.get_result()
        assert validate_database_connection_ok_body is not None

    @needscredentials
    def test_list_db2_engines(self):
        response = self.watsonx_data_service.list_db2_engines(
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        list_db2_engines_ok_body = response.get_result()
        assert list_db2_engines_ok_body is not None

    @needscredentials
    def test_create_db2_engine(self):
        # Construct a dict representation of a CreateDb2EngineDetails model
        create_db2_engine_details_model = {
            'connection_string': '1.2.3.4',
        }

        response = self.watsonx_data_service.create_db2_engine(
            origin='external',
            type='db2',
            description='db2 engine description',
            engine_details=create_db2_engine_details_model,
            engine_display_name='sampleEngine',
            tags=['tag1', 'tag2'],
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        create_db2_engine_created_body = response.get_result()
        assert create_db2_engine_created_body is not None

    @needscredentials
    def test_update_db2_engine(self):
        # Construct a dict representation of a JsonPatchOperation model
        json_patch_operation_model = {
            'op': 'add',
            'path': 'testString',
            'from': 'testString',
            'value': 'testString',
        }

        response = self.watsonx_data_service.update_db2_engine(
            engine_id='testString',
            body=[json_patch_operation_model],
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        update_db2_engine_ok_body = response.get_result()
        assert update_db2_engine_ok_body is not None

    @needscredentials
    def test_list_engines(self):
        response = self.watsonx_data_service.list_engines(
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        list_engines_ok_body = response.get_result()
        assert list_engines_ok_body is not None

    @needscredentials
    def test_get_deployments(self):
        response = self.watsonx_data_service.get_deployments(
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        get_deployments_ok_body = response.get_result()
        assert get_deployments_ok_body is not None

    @needscredentials
    def test_list_netezza_engines(self):
        response = self.watsonx_data_service.list_netezza_engines(
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        list_netezza_engines_ok_body = response.get_result()
        assert list_netezza_engines_ok_body is not None

    @needscredentials
    def test_create_netezza_engine(self):
        # Construct a dict representation of a CreateNetezzaEngineDetails model
        create_netezza_engine_details_model = {
            'connection_string': '1.2.3.4',
        }

        response = self.watsonx_data_service.create_netezza_engine(
            origin='external',
            type='netezza',
            description='netezza engine description',
            engine_details=create_netezza_engine_details_model,
            engine_display_name='sampleEngine',
            tags=['tag1', 'tag2'],
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        create_netezza_engine_created_body = response.get_result()
        assert create_netezza_engine_created_body is not None

    @needscredentials
    def test_update_netezza_engine(self):
        # Construct a dict representation of a JsonPatchOperation model
        json_patch_operation_model = {
            'op': 'add',
            'path': 'testString',
            'from': 'testString',
            'value': 'testString',
        }

        response = self.watsonx_data_service.update_netezza_engine(
            engine_id='testString',
            body=[json_patch_operation_model],
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        update_netezza_engine_ok_body = response.get_result()
        assert update_netezza_engine_ok_body is not None

    @needscredentials
    def test_list_other_engines(self):
        response = self.watsonx_data_service.list_other_engines(
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        list_other_engines_ok_body = response.get_result()
        assert list_other_engines_ok_body is not None

    @needscredentials
    def test_create_other_engine(self):
        # Construct a dict representation of a OtherEngineDetails model
        other_engine_details_model = {
            'connection_string': '1.2.3.4',
            'engine_type': 'netezza',
            'metastore_host': '1.2.3.4',
        }

        response = self.watsonx_data_service.create_other_engine(
            description='external engine description',
            engine_details=other_engine_details_model,
            engine_display_name='sampleEngine01',
            tags=['tag1', 'tag2'],
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        create_other_engine_created_body = response.get_result()
        assert create_other_engine_created_body is not None

    @needscredentials
    def test_list_presto_engines(self):
        response = self.watsonx_data_service.list_presto_engines(
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        list_presto_engines_ok_body = response.get_result()
        assert list_presto_engines_ok_body is not None

    @needscredentials
    def test_create_engine(self):
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

        response = self.watsonx_data_service.create_engine(
            origin='native',
            type='presto',
            associated_catalogs=['iceberg_data', 'hive_data'],
            description='presto engine description',
            engine_details=engine_details_body_model,
            engine_display_name='sampleEngine',
            first_time_use=True,
            region='us-south',
            tags=['tag1', 'tag2'],
            version='1.2.3',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        create_engine_created_body = response.get_result()
        assert create_engine_created_body is not None

    @needscredentials
    def test_get_presto_engine(self):
        response = self.watsonx_data_service.get_presto_engine(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        get_presto_engine_ok_body = response.get_result()
        assert get_presto_engine_ok_body is not None

    @needscredentials
    def test_update_engine(self):
        # Construct a dict representation of a JsonPatchOperation model
        json_patch_operation_model = {
            'op': 'add',
            'path': 'testString',
            'from': 'testString',
            'value': 'testString',
        }

        response = self.watsonx_data_service.update_engine(
            engine_id='testString',
            body=[json_patch_operation_model],
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        update_engine_ok_body = response.get_result()
        assert update_engine_ok_body is not None

    @needscredentials
    def test_list_presto_engine_catalogs(self):
        response = self.watsonx_data_service.list_presto_engine_catalogs(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        list_presto_engine_catalogs_ok_body = response.get_result()
        assert list_presto_engine_catalogs_ok_body is not None

    @needscredentials
    def test_replace_presto_engine_catalogs(self):
        response = self.watsonx_data_service.replace_presto_engine_catalogs(
            engine_id='testString',
            catalog_names='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        replace_presto_engine_catalogs_created_body = response.get_result()
        assert replace_presto_engine_catalogs_created_body is not None

    @needscredentials
    def test_get_presto_engine_catalog(self):
        response = self.watsonx_data_service.get_presto_engine_catalog(
            engine_id='testString',
            catalog_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        get_presto_engine_catalog_ok_body = response.get_result()
        assert get_presto_engine_catalog_ok_body is not None

    @needscredentials
    def test_create_engine_pause(self):
        response = self.watsonx_data_service.create_engine_pause(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
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
    def test_create_engine_restart(self):
        response = self.watsonx_data_service.create_engine_restart(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        create_engine_restart_created_body = response.get_result()
        assert create_engine_restart_created_body is not None

    @needscredentials
    def test_create_engine_resume(self):
        response = self.watsonx_data_service.create_engine_resume(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        create_engine_resume_created_body = response.get_result()
        assert create_engine_resume_created_body is not None

    @needscredentials
    def test_create_engine_scale(self):
        # Construct a dict representation of a NodeDescription model
        node_description_model = {
            'node_type': 'worker',
            'quantity': 38,
        }

        response = self.watsonx_data_service.create_engine_scale(
            engine_id='testString',
            coordinator=node_description_model,
            worker=node_description_model,
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        create_engine_scale_created_body = response.get_result()
        assert create_engine_scale_created_body is not None

    @needscredentials
    def test_list_spark_engines(self):
        response = self.watsonx_data_service.list_spark_engines(
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        list_spark_engines_ok_body = response.get_result()
        assert list_spark_engines_ok_body is not None

    @needscredentials
    def test_create_spark_engine(self):
        # Construct a dict representation of a SparkEngineDetailsPrototype model
        spark_engine_details_prototype_model = {
            'api_key': 'apikey',
            'connection_string': '1.2.3.4',
            'instance_id': 'spark-id',
            'managed_by': 'fully/self',
        }

        response = self.watsonx_data_service.create_spark_engine(
            origin='native',
            type='spark',
            description='spark engine description',
            engine_details=spark_engine_details_prototype_model,
            engine_display_name='sampleEngine',
            tags=['tag1', 'tag2'],
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        create_spark_engine_created_body = response.get_result()
        assert create_spark_engine_created_body is not None

    @needscredentials
    def test_update_spark_engine(self):
        # Construct a dict representation of a JsonPatchOperation model
        json_patch_operation_model = {
            'op': 'add',
            'path': 'testString',
            'from': 'testString',
            'value': 'testString',
        }

        response = self.watsonx_data_service.update_spark_engine(
            engine_id='testString',
            body=[json_patch_operation_model],
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        update_spark_engine_ok_body = response.get_result()
        assert update_spark_engine_ok_body is not None

    @needscredentials
    def test_list_spark_engine_applications(self):
        response = self.watsonx_data_service.list_spark_engine_applications(
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        list_spark_engine_applications_ok_body = response.get_result()
        assert list_spark_engine_applications_ok_body is not None

    @needscredentials
    def test_create_spark_engine_application(self):
        # Construct a dict representation of a SparkApplicationDetails model
        spark_application_details_model = {
            'application': 's3://mybucket/wordcount.py',
            'arguments': ['people.txt'],
            'conf': {'key1': 'key:value'},
            'env': {'key1': 'key:value'},
            'name': 'SparkApplicaton1',
        }

        response = self.watsonx_data_service.create_spark_engine_application(
            engine_id='testString',
            application_details=spark_application_details_model,
            job_endpoint='<host>/v4/analytics_engines/c7b3fccf-badb-46b0-b1ef-9b3154424021/engine_applications',
            service_instance_id='testString',
            type='iae',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 201
        create_spark_engine_application_created_body = response.get_result()
        assert create_spark_engine_application_created_body is not None

    @needscredentials
    def test_get_spark_engine_application_status(self):
        response = self.watsonx_data_service.get_spark_engine_application_status(
            engine_id='testString',
            application_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        get_spark_engine_application_status_ok_body = response.get_result()
        assert get_spark_engine_application_status_ok_body is not None

    @needscredentials
    def test_test_lh_console(self):
        response = self.watsonx_data_service.test_lh_console()

        assert response.get_status_code() == 200
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_list_catalogs(self):
        response = self.watsonx_data_service.list_catalogs(
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        list_catalogs_ok_body = response.get_result()
        assert list_catalogs_ok_body is not None

    @needscredentials
    def test_get_catalog(self):
        response = self.watsonx_data_service.get_catalog(
            catalog_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        get_catalog_ok_body = response.get_result()
        assert get_catalog_ok_body is not None

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
        list_tables_ok_body = response.get_result()
        assert list_tables_ok_body is not None

    @needscredentials
    def test_get_table(self):
        response = self.watsonx_data_service.get_table(
            catalog_id='testString',
            schema_id='testString',
            table_id='testString',
            engine_id='testString',
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        get_table_ok_body = response.get_result()
        assert get_table_ok_body is not None

    @needscredentials
    def test_update_table(self):
        # Construct a dict representation of a JsonPatchOperation model
        json_patch_operation_model = {
            'op': 'add',
            'path': 'testString',
            'from': 'testString',
            'value': 'testString',
        }

        response = self.watsonx_data_service.update_table(
            catalog_id='testString',
            schema_id='testString',
            table_id='testString',
            engine_id='testString',
            body=[json_patch_operation_model],
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        update_table_ok_body = response.get_result()
        assert update_table_ok_body is not None

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
        list_table_snapshots_ok_body = response.get_result()
        assert list_table_snapshots_ok_body is not None

    @needscredentials
    def test_replace_snapshot(self):
        response = self.watsonx_data_service.replace_snapshot(
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
        # Construct a dict representation of a JsonPatchOperation model
        json_patch_operation_model = {
            'op': 'add',
            'path': 'testString',
            'from': 'testString',
            'value': 'testString',
        }

        response = self.watsonx_data_service.update_sync_catalog(
            catalog_id='testString',
            body=[json_patch_operation_model],
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 200
        update_sync_catalog_ok_body = response.get_result()
        assert update_sync_catalog_ok_body is not None

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
    def test_delete_other_engine(self):
        response = self.watsonx_data_service.delete_other_engine(
            engine_id='testString',
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
            auth_instance_id='testString',
        )

        assert response.get_status_code() == 204
