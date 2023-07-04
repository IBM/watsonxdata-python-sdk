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
Integration Tests for WatsonxDataV1
"""

from ibm_cloud_sdk_core import *
import os
import pytest
from ibm_watsonxdata.watsonx_data_v1 import *

# Config file name
config_file = 'watsonx_data_v1.env'


class TestWatsonxDataV1:
    """
    Integration Test Class for WatsonxDataV1
    """

    @classmethod
    def setup_class(cls):
        if os.path.exists(config_file):
            os.environ['IBM_CREDENTIALS_FILE'] = config_file

            cls.watsonx_data_service = WatsonxDataV1.new_instance(
            )
            assert cls.watsonx_data_service is not None

            cls.config = read_external_sources(
                WatsonxDataV1.DEFAULT_SERVICE_NAME)
            assert cls.config is not None

            cls.watsonx_data_service.enable_retries()

        print('Setup complete.')

    needscredentials = pytest.mark.skipif(
        not os.path.exists(config_file), reason="External configuration not available, skipping..."
    )

    @needscredentials
    def test_create_db_conn_users(self):
        # Construct a dict representation of a BucketDbConnGroupsMetadata model
        bucket_db_conn_groups_metadata_model = {
            'group_id': 'testString',
            'permission': 'can_administer',
        }
        # Construct a dict representation of a BucketDbConnUsersMetadata model
        bucket_db_conn_users_metadata_model = {
            'user_name': 'testString',
            'permission': 'can_administer',
        }

        response = self.watsonx_data_service.create_db_conn_users(
            database_id='testString',
            groups=[bucket_db_conn_groups_metadata_model],
            users=[bucket_db_conn_users_metadata_model],
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_list_data_policies(self):
        response = self.watsonx_data_service.list_data_policies(
            lh_instance_id='teststring',
            auth_instance_id='teststring',
            catalog_name='testString',
            status='testString',
            include_metadata=True,
            include_rules=True,
        )

        assert response.get_status_code() == 200
        policy_list_schema = response.get_result()
        assert policy_list_schema is not None

    @needscredentials
    def test_create_data_policy(self):
        # Construct a dict representation of a RuleGrantee model
        rule_grantee_model = {
            'value': 'testString',
            'key': 'user_name',
            'type': 'user_identity',
        }
        # Construct a dict representation of a Rule model
        rule_model = {
            'actions': ['all'],
            'effect': 'allow',
            'grantee': rule_grantee_model,
        }

        response = self.watsonx_data_service.create_data_policy(
            catalog_name='testString',
            data_artifact='schema1/table1/(column1|column2)',
            policy_name='testString',
            rules=[rule_model],
            description='testString',
            status='active',
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 201
        create_data_policy_created_body = response.get_result()
        assert create_data_policy_created_body is not None

    @needscredentials
    def test_get_engine_users(self):
        response = self.watsonx_data_service.get_engine_users(
            engine_id='testString',
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        get_engine_users_schema = response.get_result()
        assert get_engine_users_schema is not None

    @needscredentials
    def test_update_engine_users(self):
        # Construct a dict representation of a EngineGroupsMetadata model
        engine_groups_metadata_model = {
            'group_id': 'testString',
            'permission': 'can_administer',
        }
        # Construct a dict representation of a EngineUsersMetadata model
        engine_users_metadata_model = {
            'permission': 'can_administer',
            'user_name': 'testString',
        }

        response = self.watsonx_data_service.update_engine_users(
            engine_id='testString',
            groups=[engine_groups_metadata_model],
            users=[engine_users_metadata_model],
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_update_db_conn_users(self):
        # Construct a dict representation of a BucketDbConnGroupsMetadata model
        bucket_db_conn_groups_metadata_model = {
            'group_id': 'testString',
            'permission': 'can_administer',
        }
        # Construct a dict representation of a BucketDbConnUsersMetadata model
        bucket_db_conn_users_metadata_model = {
            'user_name': 'testString',
            'permission': 'can_administer',
        }

        response = self.watsonx_data_service.update_db_conn_users(
            database_id='testString',
            groups=[bucket_db_conn_groups_metadata_model],
            users=[bucket_db_conn_users_metadata_model],
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_get_db_conn_users(self):
        response = self.watsonx_data_service.get_db_conn_users(
            database_id='testString',
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        get_db_conn_users_schema = response.get_result()
        assert get_db_conn_users_schema is not None

    @needscredentials
    def test_create_catalog_users(self):
        # Construct a dict representation of a CatalogGroupsMetadata model
        catalog_groups_metadata_model = {
            'group_id': 'testString',
            'permission': 'can_administer',
        }
        # Construct a dict representation of a CatalogUsersMetadata model
        catalog_users_metadata_model = {
            'permission': 'can_administer',
            'user_name': 'testString',
        }

        response = self.watsonx_data_service.create_catalog_users(
            catalog_name='testString',
            groups=[catalog_groups_metadata_model],
            users=[catalog_users_metadata_model],
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_get_catalog_users(self):
        response = self.watsonx_data_service.get_catalog_users(
            catalog_name='testString',
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        get_catalog_users_schema = response.get_result()
        assert get_catalog_users_schema is not None

    @needscredentials
    def test_update_catalog_users(self):
        # Construct a dict representation of a CatalogGroupsMetadata model
        catalog_groups_metadata_model = {
            'group_id': 'testString',
            'permission': 'can_administer',
        }
        # Construct a dict representation of a CatalogUsersMetadata model
        catalog_users_metadata_model = {
            'permission': 'can_administer',
            'user_name': 'testString',
        }

        response = self.watsonx_data_service.update_catalog_users(
            catalog_name='testString',
            groups=[catalog_groups_metadata_model],
            users=[catalog_users_metadata_model],
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_evaluate(self):
        # Construct a dict representation of a ResourcesMetadata model
        resources_metadata_model = {
            'action': 'testString',
            'resource_name': 'testString',
            'resource_type': 'engine',
        }

        response = self.watsonx_data_service.evaluate(
            resources=[resources_metadata_model],
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        evaluation_result_schema = response.get_result()
        assert evaluation_result_schema is not None

    @needscredentials
    def test_get_policies_list(self):
        response = self.watsonx_data_service.get_policies_list(
            lh_instance_id='teststring',
            auth_instance_id='teststring',
            catalog_list=['testString'],
            engine_list=['testString'],
            data_policies_list=['testString'],
            include_data_policies=True,
        )

        assert response.get_status_code() == 200
        policy_schema_list = response.get_result()
        assert policy_schema_list is not None

    @needscredentials
    def test_create_metastore_users(self):
        # Construct a dict representation of a GroupsMetadata model
        groups_metadata_model = {
            'group_id': 'testString',
            'permission': 'can_administer',
        }
        # Construct a dict representation of a UsersMetadata model
        users_metadata_model = {
            'permission': 'can_administer',
            'user_name': 'testString',
        }

        response = self.watsonx_data_service.create_metastore_users(
            metastore_name='testString',
            groups=[groups_metadata_model],
            users=[users_metadata_model],
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_get_metastore_users(self):
        response = self.watsonx_data_service.get_metastore_users(
            metastore_name='testString',
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        get_metastore_users_schema = response.get_result()
        assert get_metastore_users_schema is not None

    @needscredentials
    def test_update_metastore_users(self):
        # Construct a dict representation of a GroupsMetadata model
        groups_metadata_model = {
            'group_id': 'testString',
            'permission': 'can_administer',
        }
        # Construct a dict representation of a UsersMetadata model
        users_metadata_model = {
            'permission': 'can_administer',
            'user_name': 'testString',
        }

        response = self.watsonx_data_service.update_metastore_users(
            metastore_name='testString',
            groups=[groups_metadata_model],
            users=[users_metadata_model],
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_create_bucket_users(self):
        # Construct a dict representation of a BucketDbConnGroupsMetadata model
        bucket_db_conn_groups_metadata_model = {
            'group_id': 'testString',
            'permission': 'can_administer',
        }
        # Construct a dict representation of a BucketDbConnUsersMetadata model
        bucket_db_conn_users_metadata_model = {
            'user_name': 'testString',
            'permission': 'can_administer',
        }

        response = self.watsonx_data_service.create_bucket_users(
            bucket_id='testString',
            groups=[bucket_db_conn_groups_metadata_model],
            users=[bucket_db_conn_users_metadata_model],
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_get_default_policies(self):
        response = self.watsonx_data_service.get_default_policies(
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        default_policy_schema = response.get_result()
        assert default_policy_schema is not None

    @needscredentials
    def test_get_policy_version(self):
        response = self.watsonx_data_service.get_policy_version(
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        policy_version_result_schema = response.get_result()
        assert policy_version_result_schema is not None

    @needscredentials
    def test_get_data_policy(self):
        response = self.watsonx_data_service.get_data_policy(
            policy_name='testString',
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        policy_schema = response.get_result()
        assert policy_schema is not None

    @needscredentials
    def test_replace_data_policy(self):
        # Construct a dict representation of a RuleGrantee model
        rule_grantee_model = {
            'value': 'testString',
            'key': 'user_name',
            'type': 'user_identity',
        }
        # Construct a dict representation of a Rule model
        rule_model = {
            'actions': ['all'],
            'effect': 'allow',
            'grantee': rule_grantee_model,
        }

        response = self.watsonx_data_service.replace_data_policy(
            policy_name='testString',
            catalog_name='testString',
            data_artifact='schema1/table1/(column1|column2)',
            rules=[rule_model],
            description='testString',
            status='active',
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 201
        replace_data_policy_created_body = response.get_result()
        assert replace_data_policy_created_body is not None

    @needscredentials
    def test_create_engine_users(self):
        # Construct a dict representation of a EngineGroupsMetadata model
        engine_groups_metadata_model = {
            'group_id': 'testString',
            'permission': 'can_administer',
        }
        # Construct a dict representation of a EngineUsersMetadata model
        engine_users_metadata_model = {
            'permission': 'can_administer',
            'user_name': 'testString',
        }

        response = self.watsonx_data_service.create_engine_users(
            engine_id='testString',
            groups=[engine_groups_metadata_model],
            users=[engine_users_metadata_model],
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_get_bucket_users(self):
        response = self.watsonx_data_service.get_bucket_users(
            bucket_id='testString',
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        get_bucket_users_schema = response.get_result()
        assert get_bucket_users_schema is not None

    @needscredentials
    def test_update_bucket_users(self):
        # Construct a dict representation of a BucketDbConnGroupsMetadata model
        bucket_db_conn_groups_metadata_model = {
            'group_id': 'testString',
            'permission': 'can_administer',
        }
        # Construct a dict representation of a BucketDbConnUsersMetadata model
        bucket_db_conn_users_metadata_model = {
            'user_name': 'testString',
            'permission': 'can_administer',
        }

        response = self.watsonx_data_service.update_bucket_users(
            bucket_id='testString',
            groups=[bucket_db_conn_groups_metadata_model],
            users=[bucket_db_conn_users_metadata_model],
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_get_buckets(self):
        response = self.watsonx_data_service.get_buckets(
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        get_buckets_ok_body = response.get_result()
        assert get_buckets_ok_body is not None

    @needscredentials
    def test_get_bucket_objects(self):
        response = self.watsonx_data_service.get_bucket_objects(
            bucket_id='testString',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        get_bucket_objects_ok_body = response.get_result()
        assert get_bucket_objects_ok_body is not None

    @needscredentials
    def test_deactivate_bucket(self):
        response = self.watsonx_data_service.deactivate_bucket(
            bucket_id='samplebucket123',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 201
        result = response.get_result()
        assert result is not None

    @needscredentials
    def test_register_bucket(self):
        # Construct a dict representation of a BucketDetails model
        bucket_details_model = {
            'access_key': '<access_key>',
            'bucket_name': 'sample-bucket',
            'endpoint': 'https://s3.<region>.cloud-object-storage.appdomain.cloud/',
            'secret_key': '<secret_key>',
        }

        response = self.watsonx_data_service.register_bucket(
            bucket_details=bucket_details_model,
            description='COS bucket for customer data',
            table_type='iceberg',
            bucket_type='ibm_cos',
            catalog_name='sampleCatalog',
            managed_by='ibm',
            bucket_display_name='sample-bucket-displayname',
            bucket_tags=['read customer data', 'write customer data'],
            catalog_tags=['catalog_tag_1', 'catalog_tag_2'],
            thrift_uri='thrift://samplehost-metastore:4354',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 201
        register_bucket_created_body = response.get_result()
        assert register_bucket_created_body is not None

    @needscredentials
    def test_update_bucket(self):
        response = self.watsonx_data_service.update_bucket(
            bucket_id='samplebucket123',
            access_key='<access_key>',
            bucket_display_name='sample-bucket-displayname',
            description='COS bucket for customer data',
            secret_key='<secret_key>',
            tags=['testbucket', 'userbucket'],
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_activate_bucket(self):
        response = self.watsonx_data_service.activate_bucket(
            bucket_id='samplebucket123',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 201
        result = response.get_result()
        assert result is not None

    @needscredentials
    def test_get_databases(self):
        response = self.watsonx_data_service.get_databases(
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        result = response.get_result()
        assert result is not None

    @needscredentials
    def test_create_database_catalog(self):
        # Construct a dict representation of a RegisterDatabaseCatalogBodyDatabaseDetails model
        register_database_catalog_body_database_details_model = {
            'password': 'samplepassword',
            'port': '4553',
            'ssl': True,
            'tables': 'kafka_table_name',
            'username': 'sampleuser',
            'database_name': 'new_database',
            'hostname': 'db2@<hostname>.com',
        }

        response = self.watsonx_data_service.create_database_catalog(
            database_display_name='new_database',
            database_type='db2',
            catalog_name='sampleCatalog',
            database_details=register_database_catalog_body_database_details_model,
            description='db2 extenal database description',
            tags=['tag_1', 'tag_2'],
            created_by='<username>@<domain>.com',
            created_on=38,
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 201
        result = response.get_result()
        assert result is not None

    @needscredentials
    def test_update_database(self):
        # Construct a dict representation of a UpdateDatabaseBodyDatabaseDetails model
        update_database_body_database_details_model = {
            'password': 'samplepassword',
            'username': 'sampleuser',
        }

        response = self.watsonx_data_service.update_database(
            database_id='new_db_id',
            database_details=update_database_body_database_details_model,
            database_display_name='new_database',
            description='External database description',
            tags=['testdatabase', 'userdatabase'],
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        result = response.get_result()
        assert result is not None

    @needscredentials
    def test_pause_engine(self):
        response = self.watsonx_data_service.pause_engine(
            engine_id='testString',
            created_by='testString',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 201
        pause_engine_created_body = response.get_result()
        assert pause_engine_created_body is not None

    @needscredentials
    def test_get_engines(self):
        response = self.watsonx_data_service.get_engines(
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        get_engines_ok_body = response.get_result()
        assert get_engines_ok_body is not None

    @needscredentials
    def test_get_deployments(self):
        response = self.watsonx_data_service.get_deployments(
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        result = response.get_result()
        assert result is not None

    @needscredentials
    def test_update_engine(self):
        # Construct a dict representation of a NodeDescription model
        node_description_model = {
            'node_type': 'worker',
            'quantity': 38,
        }

        response = self.watsonx_data_service.update_engine(
            engine_id='sampleEngine123',
            coordinator=node_description_model,
            description='presto engine updated description',
            engine_display_name='sampleEngine',
            tags=['tag1', 'tag2'],
            worker=node_description_model,
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        result = response.get_result()
        assert result is not None

    @needscredentials
    def test_create_engine(self):
        # Construct a dict representation of a NodeDescriptionBody model
        node_description_body_model = {
            'node_type': 'worker',
            'quantity': 38,
        }
        # Construct a dict representation of a EngineDetailsBody model
        engine_details_body_model = {
            'worker': node_description_body_model,
            'coordinator': node_description_body_model,
            'size_config': 'starter',
        }

        response = self.watsonx_data_service.create_engine(
            version='1.2.3',
            engine_details=engine_details_body_model,
            origin='ibm',
            type='presto',
            description='presto engine description',
            engine_display_name='sampleEngine',
            first_time_use=True,
            region='us-south',
            associated_catalogs=['new_catalog_1', 'new_catalog_2'],
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 201
        result = response.get_result()
        assert result is not None

    @needscredentials
    def test_resume_engine(self):
        response = self.watsonx_data_service.resume_engine(
            engine_id='eng_id',
            created_by='<username>@<domain>.com',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 201
        resume_engine_created_body = response.get_result()
        assert resume_engine_created_body is not None

    @needscredentials
    def test_explain_analyze_statement(self):
        response = self.watsonx_data_service.explain_analyze_statement(
            catalog_name='sampleCatalog',
            engine_id='sampleEngine1',
            schema_name='new_schema',
            statement='show schemas in catalog',
            verbose=True,
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 201
        explain_analyze_statement_created_body = response.get_result()
        assert explain_analyze_statement_created_body is not None

    @needscredentials
    def test_explain_statement(self):
        response = self.watsonx_data_service.explain_statement(
            engine_id='eng_id',
            statement='show schemas',
            catalog_name='sampleCatalog',
            format='json',
            schema_name='new_schema',
            type='io',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 201
        explain_statement_created_body = response.get_result()
        assert explain_statement_created_body is not None

    @needscredentials
    def test_test_lh_console(self):
        response = self.watsonx_data_service.test_lh_console()

        assert response.get_status_code() == 200
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_get_metastores(self):
        response = self.watsonx_data_service.get_metastores(
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        get_metastores_ok_body = response.get_result()
        assert get_metastores_ok_body is not None

    @needscredentials
    def test_get_hms(self):
        response = self.watsonx_data_service.get_hms(
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        result = response.get_result()
        assert result is not None

    @needscredentials
    def test_add_metastore_to_engine(self):
        response = self.watsonx_data_service.add_metastore_to_engine(
            catalog_name='sampleCatalog',
            engine_id='sampleEngine123',
            created_by='<username>@<domain>.com',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 201
        result = response.get_result()
        assert result is not None

    @needscredentials
    def test_remove_catalog_from_engine(self):
        response = self.watsonx_data_service.remove_catalog_from_engine(
            catalog_name='testString',
            engine_id='testString',
            created_by='testString',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 201
        result = response.get_result()
        assert result is not None

    @needscredentials
    def test_save_query(self):
        response = self.watsonx_data_service.save_query(
            query_name='testString',
            created_by='<username>@<domain>.com',
            description='query to get expense data',
            query_string='select expenses from expenditure',
            created_on='1608437933',
            engine_id='sampleEngine123',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 201
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_update_query(self):
        response = self.watsonx_data_service.update_query(
            query_name='testString',
            query_string='testString',
            description='testString',
            new_query_name='testString',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_get_queries(self):
        response = self.watsonx_data_service.get_queries(
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        get_queries_ok_body = response.get_result()
        assert get_queries_ok_body is not None

    @needscredentials
    def test_create_schema(self):
        response = self.watsonx_data_service.create_schema(
            catalog_name='sampleCatalog',
            engine_id='sampleEngine123',
            schema_name='new_schema',
            bucket_name='sample-bucket',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 201
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_get_schemas(self):
        response = self.watsonx_data_service.get_schemas(
            engine_id='testString',
            catalog_name='testString',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        get_schemas_ok_body = response.get_result()
        assert get_schemas_ok_body is not None

    @needscredentials
    def test_post_query(self):
        response = self.watsonx_data_service.post_query(
            engine='testString',
            catalog='testString',
            schema='testString',
            sql_query='testString',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        result = response.get_result()
        assert result is not None

    @needscredentials
    def test_update_table(self):
        # Construct a dict representation of a UpdateTableBodyAddColumnsItems model
        update_table_body_add_columns_items_model = {
            'column_comment': 'income column',
            'column_name': 'income',
            'data_type': 'varchar',
        }
        # Construct a dict representation of a UpdateTableBodyDropColumnsItems model
        update_table_body_drop_columns_items_model = {
            'column_name': 'expenditure',
        }
        # Construct a dict representation of a UpdateTableBodyRenameColumnsItems model
        update_table_body_rename_columns_items_model = {
            'column_name': 'expenditure',
            'new_column_name': 'expenses',
        }

        response = self.watsonx_data_service.update_table(
            engine_id='testString',
            catalog_name='testString',
            schema_name='testString',
            table_name='testString',
            add_columns=[update_table_body_add_columns_items_model],
            drop_columns=[update_table_body_drop_columns_items_model],
            new_table_name='updated_table_name',
            rename_columns=[update_table_body_rename_columns_items_model],
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        result = response.get_result()
        assert result is not None

    @needscredentials
    def test_get_table_snapshots(self):
        response = self.watsonx_data_service.get_table_snapshots(
            engine_id='testString',
            catalog_name='testString',
            schema_name='testString',
            table_name='testString',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        get_table_snapshots_ok_body = response.get_result()
        assert get_table_snapshots_ok_body is not None

    @needscredentials
    def test_rollback_snapshot(self):
        response = self.watsonx_data_service.rollback_snapshot(
            engine_id='testString',
            catalog_name='testString',
            schema_name='testString',
            snapshot_id='2332342122211222',
            table_name='new_table',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 201
        success_response = response.get_result()
        assert success_response is not None

    @needscredentials
    def test_get_tables(self):
        response = self.watsonx_data_service.get_tables(
            engine_id='testString',
            catalog_name='testString',
            schema_name='testString',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        get_tables_ok_body = response.get_result()
        assert get_tables_ok_body is not None

    @needscredentials
    def test_parse_csv(self):
        response = self.watsonx_data_service.parse_csv(
            engine='testString',
            parse_file='testString',
            file_type='testString',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        result = response.get_result()
        assert result is not None

    @needscredentials
    def test_uplaod_csv(self):
        response = self.watsonx_data_service.uplaod_csv(
            engine='testString',
            catalog='testString',
            schema='testString',
            table_name='testString',
            ingestion_job_name='testString',
            scheduled='testString',
            created_by='testString',
            target_table='testString',
            headers_='testString',
            csv='testString',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 200
        result = response.get_result()
        assert result is not None

    @needscredentials
    def test_delete_data_policies(self):
        response = self.watsonx_data_service.delete_data_policies(
            data_policies=['testString'],
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_engine_users(self):
        response = self.watsonx_data_service.delete_engine_users(
            engine_id='testString',
            groups=['testString'],
            users=['testString'],
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_db_conn_users(self):
        response = self.watsonx_data_service.delete_db_conn_users(
            database_id='testString',
            groups=['testString'],
            users=['testString'],
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_catalog_users(self):
        response = self.watsonx_data_service.delete_catalog_users(
            catalog_name='testString',
            groups=['testString'],
            users=['testString'],
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_metastore_users(self):
        response = self.watsonx_data_service.delete_metastore_users(
            metastore_name='testString',
            groups=['testString'],
            users=['testString'],
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_data_policy(self):
        response = self.watsonx_data_service.delete_data_policy(
            policy_name='testString',
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_bucket_users(self):
        response = self.watsonx_data_service.delete_bucket_users(
            bucket_id='testString',
            groups=['testString'],
            users=['testString'],
            lh_instance_id='teststring',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_unregister_bucket(self):
        response = self.watsonx_data_service.unregister_bucket(
            bucket_id='bucket_id',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_database_catalog(self):
        response = self.watsonx_data_service.delete_database_catalog(
            database_id='new_db_id',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_engine(self):
        response = self.watsonx_data_service.delete_engine(
            engine_id='eng_if',
            created_by='<username>@<domain>.com',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_query(self):
        response = self.watsonx_data_service.delete_query(
            query_name='testString',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_schema(self):
        response = self.watsonx_data_service.delete_schema(
            catalog_name='sampleCatalog',
            engine_id='sampleEngine123',
            schema_name='new_schema',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_table(self):
        # Construct a dict representation of a DeleteTableBodyDeleteTablesItems model
        delete_table_body_delete_tables_items_model = {
            'catalog_name': 'sampleCatalog',
            'schema_name': 'new_schema',
            'table_name': 'new_table',
        }

        response = self.watsonx_data_service.delete_table(
            delete_tables=[delete_table_body_delete_tables_items_model],
            engine_id='sampleEngine123',
            auth_instance_id='teststring',
        )

        assert response.get_status_code() == 204
