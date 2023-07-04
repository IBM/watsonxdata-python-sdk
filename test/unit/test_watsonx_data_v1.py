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
Unit Tests for WatsonxDataV1
"""

from ibm_cloud_sdk_core.authenticators.no_auth_authenticator import NoAuthAuthenticator
import inspect
import json
import os
import pytest
import re
import requests
import responses
import urllib
from ibm_watsonxdata.watsonx_data_v1 import *


_service = WatsonxDataV1(
    authenticator=NoAuthAuthenticator()
)

_base_url = 'https://lakehouse/api/v1'
_service.set_service_url(_base_url)


def preprocess_url(operation_path: str):
    """
    Returns the request url associated with the specified operation path.
    This will be base_url concatenated with a quoted version of operation_path.
    The returned request URL is used to register the mock response so it needs
    to match the request URL that is formed by the requests library.
    """
    # First, unquote the path since it might have some quoted/escaped characters in it
    # due to how the generator inserts the operation paths into the unit test code.
    operation_path = urllib.parse.unquote(operation_path)

    # Next, quote the path using urllib so that we approximate what will
    # happen during request processing.
    operation_path = urllib.parse.quote(operation_path, safe='/')

    # Finally, form the request URL from the base URL and operation path.
    request_url = _base_url + operation_path

    # If the request url does NOT end with a /, then just return it as-is.
    # Otherwise, return a regular expression that matches one or more trailing /.
    if re.fullmatch('.*/+', request_url) is None:
        return request_url
    else:
        return re.compile(request_url.rstrip('/') + '/+')


##############################################################################
# Start of Service: AccessManagement
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ['TEST_SERVICE_AUTH_TYPE'] = 'noAuth'

        service = WatsonxDataV1.new_instance(
            service_name='TEST_SERVICE',
        )

        assert service is not None
        assert isinstance(service, WatsonxDataV1)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match='authenticator must be provided'):
            service = WatsonxDataV1.new_instance(
                service_name='TEST_SERVICE_NOT_FOUND',
            )


class TestCreateDbConnUsers:
    """
    Test Class for create_db_conn_users
    """

    @responses.activate
    def test_create_db_conn_users_all_params(self):
        """
        create_db_conn_users()
        """
        # Set up mock
        url = preprocess_url('/access/databases')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a BucketDbConnGroupsMetadata model
        bucket_db_conn_groups_metadata_model = {}
        bucket_db_conn_groups_metadata_model['group_id'] = 'testString'
        bucket_db_conn_groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a BucketDbConnUsersMetadata model
        bucket_db_conn_users_metadata_model = {}
        bucket_db_conn_users_metadata_model['user_name'] = 'testString'
        bucket_db_conn_users_metadata_model['permission'] = 'can_administer'

        # Set up parameter values
        database_id = 'testString'
        groups = [bucket_db_conn_groups_metadata_model]
        users = [bucket_db_conn_users_metadata_model]
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.create_db_conn_users(
            database_id,
            groups=groups,
            users=users,
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['database_id'] == 'testString'
        assert req_body['groups'] == [bucket_db_conn_groups_metadata_model]
        assert req_body['users'] == [bucket_db_conn_users_metadata_model]

    def test_create_db_conn_users_all_params_with_retries(self):
        # Enable retries and run test_create_db_conn_users_all_params.
        _service.enable_retries()
        self.test_create_db_conn_users_all_params()

        # Disable retries and run test_create_db_conn_users_all_params.
        _service.disable_retries()
        self.test_create_db_conn_users_all_params()

    @responses.activate
    def test_create_db_conn_users_required_params(self):
        """
        test_create_db_conn_users_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/databases')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a BucketDbConnGroupsMetadata model
        bucket_db_conn_groups_metadata_model = {}
        bucket_db_conn_groups_metadata_model['group_id'] = 'testString'
        bucket_db_conn_groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a BucketDbConnUsersMetadata model
        bucket_db_conn_users_metadata_model = {}
        bucket_db_conn_users_metadata_model['user_name'] = 'testString'
        bucket_db_conn_users_metadata_model['permission'] = 'can_administer'

        # Set up parameter values
        database_id = 'testString'
        groups = [bucket_db_conn_groups_metadata_model]
        users = [bucket_db_conn_users_metadata_model]

        # Invoke method
        response = _service.create_db_conn_users(
            database_id,
            groups=groups,
            users=users,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['database_id'] == 'testString'
        assert req_body['groups'] == [bucket_db_conn_groups_metadata_model]
        assert req_body['users'] == [bucket_db_conn_users_metadata_model]

    def test_create_db_conn_users_required_params_with_retries(self):
        # Enable retries and run test_create_db_conn_users_required_params.
        _service.enable_retries()
        self.test_create_db_conn_users_required_params()

        # Disable retries and run test_create_db_conn_users_required_params.
        _service.disable_retries()
        self.test_create_db_conn_users_required_params()

    @responses.activate
    def test_create_db_conn_users_value_error(self):
        """
        test_create_db_conn_users_value_error()
        """
        # Set up mock
        url = preprocess_url('/access/databases')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a BucketDbConnGroupsMetadata model
        bucket_db_conn_groups_metadata_model = {}
        bucket_db_conn_groups_metadata_model['group_id'] = 'testString'
        bucket_db_conn_groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a BucketDbConnUsersMetadata model
        bucket_db_conn_users_metadata_model = {}
        bucket_db_conn_users_metadata_model['user_name'] = 'testString'
        bucket_db_conn_users_metadata_model['permission'] = 'can_administer'

        # Set up parameter values
        database_id = 'testString'
        groups = [bucket_db_conn_groups_metadata_model]
        users = [bucket_db_conn_users_metadata_model]

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "database_id": database_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_db_conn_users(**req_copy)

    def test_create_db_conn_users_value_error_with_retries(self):
        # Enable retries and run test_create_db_conn_users_value_error.
        _service.enable_retries()
        self.test_create_db_conn_users_value_error()

        # Disable retries and run test_create_db_conn_users_value_error.
        _service.disable_retries()
        self.test_create_db_conn_users_value_error()


class TestListDataPolicies:
    """
    Test Class for list_data_policies
    """

    @responses.activate
    def test_list_data_policies_all_params(self):
        """
        list_data_policies()
        """
        # Set up mock
        url = preprocess_url('/access/data_policies')
        mock_response = '{"policies": [{"rule_count": 10, "rules": [{"actions": ["all"], "effect": "allow", "grantee": {"value": "value", "key": "user_name", "type": "user_identity"}}], "status": "active", "catalog_name": "catalog_name", "data_artifact": "schema1/table1/(column1|column2)", "metadata": {"creator": "creator", "description": "description", "modifier": "modifier", "pid": "pid", "policy_name": "policy_name", "updated_at": "updated_at", "version": "version", "created_at": "created_at"}, "policy_name": "policy_name"}], "total_count": 11}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'
        catalog_name = 'testString'
        status = 'testString'
        include_metadata = True
        include_rules = True

        # Invoke method
        response = _service.list_data_policies(
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            catalog_name=catalog_name,
            status=status,
            include_metadata=include_metadata,
            include_rules=include_rules,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'catalog_name={}'.format(catalog_name) in query_string
        assert 'status={}'.format(status) in query_string
        assert 'include_metadata={}'.format('true' if include_metadata else 'false') in query_string
        assert 'include_rules={}'.format('true' if include_rules else 'false') in query_string

    def test_list_data_policies_all_params_with_retries(self):
        # Enable retries and run test_list_data_policies_all_params.
        _service.enable_retries()
        self.test_list_data_policies_all_params()

        # Disable retries and run test_list_data_policies_all_params.
        _service.disable_retries()
        self.test_list_data_policies_all_params()

    @responses.activate
    def test_list_data_policies_required_params(self):
        """
        test_list_data_policies_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/data_policies')
        mock_response = '{"policies": [{"rule_count": 10, "rules": [{"actions": ["all"], "effect": "allow", "grantee": {"value": "value", "key": "user_name", "type": "user_identity"}}], "status": "active", "catalog_name": "catalog_name", "data_artifact": "schema1/table1/(column1|column2)", "metadata": {"creator": "creator", "description": "description", "modifier": "modifier", "pid": "pid", "policy_name": "policy_name", "updated_at": "updated_at", "version": "version", "created_at": "created_at"}, "policy_name": "policy_name"}], "total_count": 11}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Invoke method
        response = _service.list_data_policies()

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_list_data_policies_required_params_with_retries(self):
        # Enable retries and run test_list_data_policies_required_params.
        _service.enable_retries()
        self.test_list_data_policies_required_params()

        # Disable retries and run test_list_data_policies_required_params.
        _service.disable_retries()
        self.test_list_data_policies_required_params()


class TestCreateDataPolicy:
    """
    Test Class for create_data_policy
    """

    @responses.activate
    def test_create_data_policy_all_params(self):
        """
        create_data_policy()
        """
        # Set up mock
        url = preprocess_url('/access/data_policies')
        mock_response = '{"data_policy": {"catalog_name": "catalog_name", "data_artifact": "schema1/table1/(column1|column2)", "description": "description", "policy_name": "policy_name", "rules": [{"actions": ["all"], "effect": "allow", "grantee": {"value": "value", "key": "user_name", "type": "user_identity"}}], "status": "active"}, "metadata": {"creator": "creator", "description": "description", "modifier": "modifier", "pid": "pid", "policy_name": "policy_name", "updated_at": "updated_at", "version": "version", "created_at": "created_at"}, "response": {"_messageCode_": "<message code>", "message": "Success"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a RuleGrantee model
        rule_grantee_model = {}
        rule_grantee_model['value'] = 'testString'
        rule_grantee_model['key'] = 'user_name'
        rule_grantee_model['type'] = 'user_identity'

        # Construct a dict representation of a Rule model
        rule_model = {}
        rule_model['actions'] = ['all']
        rule_model['effect'] = 'allow'
        rule_model['grantee'] = rule_grantee_model

        # Set up parameter values
        catalog_name = 'testString'
        data_artifact = 'schema1/table1/(column1|column2)'
        policy_name = 'testString'
        rules = [rule_model]
        description = 'testString'
        status = 'active'
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.create_data_policy(
            catalog_name,
            data_artifact,
            policy_name,
            rules,
            description=description,
            status=status,
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['catalog_name'] == 'testString'
        assert req_body['data_artifact'] == 'schema1/table1/(column1|column2)'
        assert req_body['policy_name'] == 'testString'
        assert req_body['rules'] == [rule_model]
        assert req_body['description'] == 'testString'
        assert req_body['status'] == 'active'

    def test_create_data_policy_all_params_with_retries(self):
        # Enable retries and run test_create_data_policy_all_params.
        _service.enable_retries()
        self.test_create_data_policy_all_params()

        # Disable retries and run test_create_data_policy_all_params.
        _service.disable_retries()
        self.test_create_data_policy_all_params()

    @responses.activate
    def test_create_data_policy_required_params(self):
        """
        test_create_data_policy_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/data_policies')
        mock_response = '{"data_policy": {"catalog_name": "catalog_name", "data_artifact": "schema1/table1/(column1|column2)", "description": "description", "policy_name": "policy_name", "rules": [{"actions": ["all"], "effect": "allow", "grantee": {"value": "value", "key": "user_name", "type": "user_identity"}}], "status": "active"}, "metadata": {"creator": "creator", "description": "description", "modifier": "modifier", "pid": "pid", "policy_name": "policy_name", "updated_at": "updated_at", "version": "version", "created_at": "created_at"}, "response": {"_messageCode_": "<message code>", "message": "Success"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a RuleGrantee model
        rule_grantee_model = {}
        rule_grantee_model['value'] = 'testString'
        rule_grantee_model['key'] = 'user_name'
        rule_grantee_model['type'] = 'user_identity'

        # Construct a dict representation of a Rule model
        rule_model = {}
        rule_model['actions'] = ['all']
        rule_model['effect'] = 'allow'
        rule_model['grantee'] = rule_grantee_model

        # Set up parameter values
        catalog_name = 'testString'
        data_artifact = 'schema1/table1/(column1|column2)'
        policy_name = 'testString'
        rules = [rule_model]
        description = 'testString'
        status = 'active'

        # Invoke method
        response = _service.create_data_policy(
            catalog_name,
            data_artifact,
            policy_name,
            rules,
            description=description,
            status=status,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['catalog_name'] == 'testString'
        assert req_body['data_artifact'] == 'schema1/table1/(column1|column2)'
        assert req_body['policy_name'] == 'testString'
        assert req_body['rules'] == [rule_model]
        assert req_body['description'] == 'testString'
        assert req_body['status'] == 'active'

    def test_create_data_policy_required_params_with_retries(self):
        # Enable retries and run test_create_data_policy_required_params.
        _service.enable_retries()
        self.test_create_data_policy_required_params()

        # Disable retries and run test_create_data_policy_required_params.
        _service.disable_retries()
        self.test_create_data_policy_required_params()

    @responses.activate
    def test_create_data_policy_value_error(self):
        """
        test_create_data_policy_value_error()
        """
        # Set up mock
        url = preprocess_url('/access/data_policies')
        mock_response = '{"data_policy": {"catalog_name": "catalog_name", "data_artifact": "schema1/table1/(column1|column2)", "description": "description", "policy_name": "policy_name", "rules": [{"actions": ["all"], "effect": "allow", "grantee": {"value": "value", "key": "user_name", "type": "user_identity"}}], "status": "active"}, "metadata": {"creator": "creator", "description": "description", "modifier": "modifier", "pid": "pid", "policy_name": "policy_name", "updated_at": "updated_at", "version": "version", "created_at": "created_at"}, "response": {"_messageCode_": "<message code>", "message": "Success"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a RuleGrantee model
        rule_grantee_model = {}
        rule_grantee_model['value'] = 'testString'
        rule_grantee_model['key'] = 'user_name'
        rule_grantee_model['type'] = 'user_identity'

        # Construct a dict representation of a Rule model
        rule_model = {}
        rule_model['actions'] = ['all']
        rule_model['effect'] = 'allow'
        rule_model['grantee'] = rule_grantee_model

        # Set up parameter values
        catalog_name = 'testString'
        data_artifact = 'schema1/table1/(column1|column2)'
        policy_name = 'testString'
        rules = [rule_model]
        description = 'testString'
        status = 'active'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "catalog_name": catalog_name,
            "data_artifact": data_artifact,
            "policy_name": policy_name,
            "rules": rules,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_data_policy(**req_copy)

    def test_create_data_policy_value_error_with_retries(self):
        # Enable retries and run test_create_data_policy_value_error.
        _service.enable_retries()
        self.test_create_data_policy_value_error()

        # Disable retries and run test_create_data_policy_value_error.
        _service.disable_retries()
        self.test_create_data_policy_value_error()


class TestDeleteDataPolicies:
    """
    Test Class for delete_data_policies
    """

    @responses.activate
    def test_delete_data_policies_all_params(self):
        """
        delete_data_policies()
        """
        # Set up mock
        url = preprocess_url('/access/data_policies')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        data_policies = ['testString']
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.delete_data_policies(
            data_policies=data_policies,
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['data_policies'] == ['testString']

    def test_delete_data_policies_all_params_with_retries(self):
        # Enable retries and run test_delete_data_policies_all_params.
        _service.enable_retries()
        self.test_delete_data_policies_all_params()

        # Disable retries and run test_delete_data_policies_all_params.
        _service.disable_retries()
        self.test_delete_data_policies_all_params()

    @responses.activate
    def test_delete_data_policies_required_params(self):
        """
        test_delete_data_policies_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/data_policies')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        data_policies = ['testString']

        # Invoke method
        response = _service.delete_data_policies(
            data_policies=data_policies,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['data_policies'] == ['testString']

    def test_delete_data_policies_required_params_with_retries(self):
        # Enable retries and run test_delete_data_policies_required_params.
        _service.enable_retries()
        self.test_delete_data_policies_required_params()

        # Disable retries and run test_delete_data_policies_required_params.
        _service.disable_retries()
        self.test_delete_data_policies_required_params()


class TestGetEngineUsers:
    """
    Test Class for get_engine_users
    """

    @responses.activate
    def test_get_engine_users_all_params(self):
        """
        get_engine_users()
        """
        # Set up mock
        url = preprocess_url('/access/engines/testString')
        mock_response = '{"engine_id": "engine_id", "groups": [{"group_id": "group_id", "permission": "can_administer"}], "total_count": 11, "users": [{"permission": "can_administer", "user_name": "user_name"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        engine_id = 'testString'
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.get_engine_users(
            engine_id,
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_engine_users_all_params_with_retries(self):
        # Enable retries and run test_get_engine_users_all_params.
        _service.enable_retries()
        self.test_get_engine_users_all_params()

        # Disable retries and run test_get_engine_users_all_params.
        _service.disable_retries()
        self.test_get_engine_users_all_params()

    @responses.activate
    def test_get_engine_users_required_params(self):
        """
        test_get_engine_users_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/engines/testString')
        mock_response = '{"engine_id": "engine_id", "groups": [{"group_id": "group_id", "permission": "can_administer"}], "total_count": 11, "users": [{"permission": "can_administer", "user_name": "user_name"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        engine_id = 'testString'

        # Invoke method
        response = _service.get_engine_users(
            engine_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_engine_users_required_params_with_retries(self):
        # Enable retries and run test_get_engine_users_required_params.
        _service.enable_retries()
        self.test_get_engine_users_required_params()

        # Disable retries and run test_get_engine_users_required_params.
        _service.disable_retries()
        self.test_get_engine_users_required_params()

    @responses.activate
    def test_get_engine_users_value_error(self):
        """
        test_get_engine_users_value_error()
        """
        # Set up mock
        url = preprocess_url('/access/engines/testString')
        mock_response = '{"engine_id": "engine_id", "groups": [{"group_id": "group_id", "permission": "can_administer"}], "total_count": 11, "users": [{"permission": "can_administer", "user_name": "user_name"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        engine_id = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "engine_id": engine_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_engine_users(**req_copy)

    def test_get_engine_users_value_error_with_retries(self):
        # Enable retries and run test_get_engine_users_value_error.
        _service.enable_retries()
        self.test_get_engine_users_value_error()

        # Disable retries and run test_get_engine_users_value_error.
        _service.disable_retries()
        self.test_get_engine_users_value_error()


class TestDeleteEngineUsers:
    """
    Test Class for delete_engine_users
    """

    @responses.activate
    def test_delete_engine_users_all_params(self):
        """
        delete_engine_users()
        """
        # Set up mock
        url = preprocess_url('/access/engines/testString')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        engine_id = 'testString'
        groups = ['testString']
        users = ['testString']
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.delete_engine_users(
            engine_id,
            groups=groups,
            users=users,
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['groups'] == ['testString']
        assert req_body['users'] == ['testString']

    def test_delete_engine_users_all_params_with_retries(self):
        # Enable retries and run test_delete_engine_users_all_params.
        _service.enable_retries()
        self.test_delete_engine_users_all_params()

        # Disable retries and run test_delete_engine_users_all_params.
        _service.disable_retries()
        self.test_delete_engine_users_all_params()

    @responses.activate
    def test_delete_engine_users_required_params(self):
        """
        test_delete_engine_users_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/engines/testString')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        engine_id = 'testString'
        groups = ['testString']
        users = ['testString']

        # Invoke method
        response = _service.delete_engine_users(
            engine_id,
            groups=groups,
            users=users,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['groups'] == ['testString']
        assert req_body['users'] == ['testString']

    def test_delete_engine_users_required_params_with_retries(self):
        # Enable retries and run test_delete_engine_users_required_params.
        _service.enable_retries()
        self.test_delete_engine_users_required_params()

        # Disable retries and run test_delete_engine_users_required_params.
        _service.disable_retries()
        self.test_delete_engine_users_required_params()

    @responses.activate
    def test_delete_engine_users_value_error(self):
        """
        test_delete_engine_users_value_error()
        """
        # Set up mock
        url = preprocess_url('/access/engines/testString')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        engine_id = 'testString'
        groups = ['testString']
        users = ['testString']

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "engine_id": engine_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_engine_users(**req_copy)

    def test_delete_engine_users_value_error_with_retries(self):
        # Enable retries and run test_delete_engine_users_value_error.
        _service.enable_retries()
        self.test_delete_engine_users_value_error()

        # Disable retries and run test_delete_engine_users_value_error.
        _service.disable_retries()
        self.test_delete_engine_users_value_error()


class TestUpdateEngineUsers:
    """
    Test Class for update_engine_users
    """

    @responses.activate
    def test_update_engine_users_all_params(self):
        """
        update_engine_users()
        """
        # Set up mock
        url = preprocess_url('/access/engines/testString')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a EngineGroupsMetadata model
        engine_groups_metadata_model = {}
        engine_groups_metadata_model['group_id'] = 'testString'
        engine_groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a EngineUsersMetadata model
        engine_users_metadata_model = {}
        engine_users_metadata_model['permission'] = 'can_administer'
        engine_users_metadata_model['user_name'] = 'testString'

        # Set up parameter values
        engine_id = 'testString'
        groups = [engine_groups_metadata_model]
        users = [engine_users_metadata_model]
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.update_engine_users(
            engine_id,
            groups=groups,
            users=users,
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['groups'] == [engine_groups_metadata_model]
        assert req_body['users'] == [engine_users_metadata_model]

    def test_update_engine_users_all_params_with_retries(self):
        # Enable retries and run test_update_engine_users_all_params.
        _service.enable_retries()
        self.test_update_engine_users_all_params()

        # Disable retries and run test_update_engine_users_all_params.
        _service.disable_retries()
        self.test_update_engine_users_all_params()

    @responses.activate
    def test_update_engine_users_required_params(self):
        """
        test_update_engine_users_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/engines/testString')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a EngineGroupsMetadata model
        engine_groups_metadata_model = {}
        engine_groups_metadata_model['group_id'] = 'testString'
        engine_groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a EngineUsersMetadata model
        engine_users_metadata_model = {}
        engine_users_metadata_model['permission'] = 'can_administer'
        engine_users_metadata_model['user_name'] = 'testString'

        # Set up parameter values
        engine_id = 'testString'
        groups = [engine_groups_metadata_model]
        users = [engine_users_metadata_model]

        # Invoke method
        response = _service.update_engine_users(
            engine_id,
            groups=groups,
            users=users,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['groups'] == [engine_groups_metadata_model]
        assert req_body['users'] == [engine_users_metadata_model]

    def test_update_engine_users_required_params_with_retries(self):
        # Enable retries and run test_update_engine_users_required_params.
        _service.enable_retries()
        self.test_update_engine_users_required_params()

        # Disable retries and run test_update_engine_users_required_params.
        _service.disable_retries()
        self.test_update_engine_users_required_params()

    @responses.activate
    def test_update_engine_users_value_error(self):
        """
        test_update_engine_users_value_error()
        """
        # Set up mock
        url = preprocess_url('/access/engines/testString')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a EngineGroupsMetadata model
        engine_groups_metadata_model = {}
        engine_groups_metadata_model['group_id'] = 'testString'
        engine_groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a EngineUsersMetadata model
        engine_users_metadata_model = {}
        engine_users_metadata_model['permission'] = 'can_administer'
        engine_users_metadata_model['user_name'] = 'testString'

        # Set up parameter values
        engine_id = 'testString'
        groups = [engine_groups_metadata_model]
        users = [engine_users_metadata_model]

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "engine_id": engine_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.update_engine_users(**req_copy)

    def test_update_engine_users_value_error_with_retries(self):
        # Enable retries and run test_update_engine_users_value_error.
        _service.enable_retries()
        self.test_update_engine_users_value_error()

        # Disable retries and run test_update_engine_users_value_error.
        _service.disable_retries()
        self.test_update_engine_users_value_error()


class TestDeleteDbConnUsers:
    """
    Test Class for delete_db_conn_users
    """

    @responses.activate
    def test_delete_db_conn_users_all_params(self):
        """
        delete_db_conn_users()
        """
        # Set up mock
        url = preprocess_url('/access/databases/testString')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        database_id = 'testString'
        groups = ['testString']
        users = ['testString']
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.delete_db_conn_users(
            database_id,
            groups=groups,
            users=users,
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['groups'] == ['testString']
        assert req_body['users'] == ['testString']

    def test_delete_db_conn_users_all_params_with_retries(self):
        # Enable retries and run test_delete_db_conn_users_all_params.
        _service.enable_retries()
        self.test_delete_db_conn_users_all_params()

        # Disable retries and run test_delete_db_conn_users_all_params.
        _service.disable_retries()
        self.test_delete_db_conn_users_all_params()

    @responses.activate
    def test_delete_db_conn_users_required_params(self):
        """
        test_delete_db_conn_users_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/databases/testString')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        database_id = 'testString'
        groups = ['testString']
        users = ['testString']

        # Invoke method
        response = _service.delete_db_conn_users(
            database_id,
            groups=groups,
            users=users,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['groups'] == ['testString']
        assert req_body['users'] == ['testString']

    def test_delete_db_conn_users_required_params_with_retries(self):
        # Enable retries and run test_delete_db_conn_users_required_params.
        _service.enable_retries()
        self.test_delete_db_conn_users_required_params()

        # Disable retries and run test_delete_db_conn_users_required_params.
        _service.disable_retries()
        self.test_delete_db_conn_users_required_params()

    @responses.activate
    def test_delete_db_conn_users_value_error(self):
        """
        test_delete_db_conn_users_value_error()
        """
        # Set up mock
        url = preprocess_url('/access/databases/testString')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        database_id = 'testString'
        groups = ['testString']
        users = ['testString']

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "database_id": database_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_db_conn_users(**req_copy)

    def test_delete_db_conn_users_value_error_with_retries(self):
        # Enable retries and run test_delete_db_conn_users_value_error.
        _service.enable_retries()
        self.test_delete_db_conn_users_value_error()

        # Disable retries and run test_delete_db_conn_users_value_error.
        _service.disable_retries()
        self.test_delete_db_conn_users_value_error()


class TestUpdateDbConnUsers:
    """
    Test Class for update_db_conn_users
    """

    @responses.activate
    def test_update_db_conn_users_all_params(self):
        """
        update_db_conn_users()
        """
        # Set up mock
        url = preprocess_url('/access/databases/testString')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a BucketDbConnGroupsMetadata model
        bucket_db_conn_groups_metadata_model = {}
        bucket_db_conn_groups_metadata_model['group_id'] = 'testString'
        bucket_db_conn_groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a BucketDbConnUsersMetadata model
        bucket_db_conn_users_metadata_model = {}
        bucket_db_conn_users_metadata_model['user_name'] = 'testString'
        bucket_db_conn_users_metadata_model['permission'] = 'can_administer'

        # Set up parameter values
        database_id = 'testString'
        groups = [bucket_db_conn_groups_metadata_model]
        users = [bucket_db_conn_users_metadata_model]
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.update_db_conn_users(
            database_id,
            groups=groups,
            users=users,
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['groups'] == [bucket_db_conn_groups_metadata_model]
        assert req_body['users'] == [bucket_db_conn_users_metadata_model]

    def test_update_db_conn_users_all_params_with_retries(self):
        # Enable retries and run test_update_db_conn_users_all_params.
        _service.enable_retries()
        self.test_update_db_conn_users_all_params()

        # Disable retries and run test_update_db_conn_users_all_params.
        _service.disable_retries()
        self.test_update_db_conn_users_all_params()

    @responses.activate
    def test_update_db_conn_users_required_params(self):
        """
        test_update_db_conn_users_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/databases/testString')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a BucketDbConnGroupsMetadata model
        bucket_db_conn_groups_metadata_model = {}
        bucket_db_conn_groups_metadata_model['group_id'] = 'testString'
        bucket_db_conn_groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a BucketDbConnUsersMetadata model
        bucket_db_conn_users_metadata_model = {}
        bucket_db_conn_users_metadata_model['user_name'] = 'testString'
        bucket_db_conn_users_metadata_model['permission'] = 'can_administer'

        # Set up parameter values
        database_id = 'testString'
        groups = [bucket_db_conn_groups_metadata_model]
        users = [bucket_db_conn_users_metadata_model]

        # Invoke method
        response = _service.update_db_conn_users(
            database_id,
            groups=groups,
            users=users,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['groups'] == [bucket_db_conn_groups_metadata_model]
        assert req_body['users'] == [bucket_db_conn_users_metadata_model]

    def test_update_db_conn_users_required_params_with_retries(self):
        # Enable retries and run test_update_db_conn_users_required_params.
        _service.enable_retries()
        self.test_update_db_conn_users_required_params()

        # Disable retries and run test_update_db_conn_users_required_params.
        _service.disable_retries()
        self.test_update_db_conn_users_required_params()

    @responses.activate
    def test_update_db_conn_users_value_error(self):
        """
        test_update_db_conn_users_value_error()
        """
        # Set up mock
        url = preprocess_url('/access/databases/testString')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a BucketDbConnGroupsMetadata model
        bucket_db_conn_groups_metadata_model = {}
        bucket_db_conn_groups_metadata_model['group_id'] = 'testString'
        bucket_db_conn_groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a BucketDbConnUsersMetadata model
        bucket_db_conn_users_metadata_model = {}
        bucket_db_conn_users_metadata_model['user_name'] = 'testString'
        bucket_db_conn_users_metadata_model['permission'] = 'can_administer'

        # Set up parameter values
        database_id = 'testString'
        groups = [bucket_db_conn_groups_metadata_model]
        users = [bucket_db_conn_users_metadata_model]

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "database_id": database_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.update_db_conn_users(**req_copy)

    def test_update_db_conn_users_value_error_with_retries(self):
        # Enable retries and run test_update_db_conn_users_value_error.
        _service.enable_retries()
        self.test_update_db_conn_users_value_error()

        # Disable retries and run test_update_db_conn_users_value_error.
        _service.disable_retries()
        self.test_update_db_conn_users_value_error()


class TestGetDbConnUsers:
    """
    Test Class for get_db_conn_users
    """

    @responses.activate
    def test_get_db_conn_users_all_params(self):
        """
        get_db_conn_users()
        """
        # Set up mock
        url = preprocess_url('/access/databases/testString')
        mock_response = '{"groups": [{"group_id": "group_id", "permission": "can_administer"}], "total_count": 11, "users": [{"user_name": "user_name", "permission": "can_administer"}], "database_id": "database_id"}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        database_id = 'testString'
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.get_db_conn_users(
            database_id,
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_db_conn_users_all_params_with_retries(self):
        # Enable retries and run test_get_db_conn_users_all_params.
        _service.enable_retries()
        self.test_get_db_conn_users_all_params()

        # Disable retries and run test_get_db_conn_users_all_params.
        _service.disable_retries()
        self.test_get_db_conn_users_all_params()

    @responses.activate
    def test_get_db_conn_users_required_params(self):
        """
        test_get_db_conn_users_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/databases/testString')
        mock_response = '{"groups": [{"group_id": "group_id", "permission": "can_administer"}], "total_count": 11, "users": [{"user_name": "user_name", "permission": "can_administer"}], "database_id": "database_id"}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        database_id = 'testString'

        # Invoke method
        response = _service.get_db_conn_users(
            database_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_db_conn_users_required_params_with_retries(self):
        # Enable retries and run test_get_db_conn_users_required_params.
        _service.enable_retries()
        self.test_get_db_conn_users_required_params()

        # Disable retries and run test_get_db_conn_users_required_params.
        _service.disable_retries()
        self.test_get_db_conn_users_required_params()

    @responses.activate
    def test_get_db_conn_users_value_error(self):
        """
        test_get_db_conn_users_value_error()
        """
        # Set up mock
        url = preprocess_url('/access/databases/testString')
        mock_response = '{"groups": [{"group_id": "group_id", "permission": "can_administer"}], "total_count": 11, "users": [{"user_name": "user_name", "permission": "can_administer"}], "database_id": "database_id"}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        database_id = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "database_id": database_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_db_conn_users(**req_copy)

    def test_get_db_conn_users_value_error_with_retries(self):
        # Enable retries and run test_get_db_conn_users_value_error.
        _service.enable_retries()
        self.test_get_db_conn_users_value_error()

        # Disable retries and run test_get_db_conn_users_value_error.
        _service.disable_retries()
        self.test_get_db_conn_users_value_error()


class TestCreateCatalogUsers:
    """
    Test Class for create_catalog_users
    """

    @responses.activate
    def test_create_catalog_users_all_params(self):
        """
        create_catalog_users()
        """
        # Set up mock
        url = preprocess_url('/access/catalogs')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a CatalogGroupsMetadata model
        catalog_groups_metadata_model = {}
        catalog_groups_metadata_model['group_id'] = 'testString'
        catalog_groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a CatalogUsersMetadata model
        catalog_users_metadata_model = {}
        catalog_users_metadata_model['permission'] = 'can_administer'
        catalog_users_metadata_model['user_name'] = 'testString'

        # Set up parameter values
        catalog_name = 'testString'
        groups = [catalog_groups_metadata_model]
        users = [catalog_users_metadata_model]
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.create_catalog_users(
            catalog_name,
            groups=groups,
            users=users,
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['catalog_name'] == 'testString'
        assert req_body['groups'] == [catalog_groups_metadata_model]
        assert req_body['users'] == [catalog_users_metadata_model]

    def test_create_catalog_users_all_params_with_retries(self):
        # Enable retries and run test_create_catalog_users_all_params.
        _service.enable_retries()
        self.test_create_catalog_users_all_params()

        # Disable retries and run test_create_catalog_users_all_params.
        _service.disable_retries()
        self.test_create_catalog_users_all_params()

    @responses.activate
    def test_create_catalog_users_required_params(self):
        """
        test_create_catalog_users_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/catalogs')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a CatalogGroupsMetadata model
        catalog_groups_metadata_model = {}
        catalog_groups_metadata_model['group_id'] = 'testString'
        catalog_groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a CatalogUsersMetadata model
        catalog_users_metadata_model = {}
        catalog_users_metadata_model['permission'] = 'can_administer'
        catalog_users_metadata_model['user_name'] = 'testString'

        # Set up parameter values
        catalog_name = 'testString'
        groups = [catalog_groups_metadata_model]
        users = [catalog_users_metadata_model]

        # Invoke method
        response = _service.create_catalog_users(
            catalog_name,
            groups=groups,
            users=users,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['catalog_name'] == 'testString'
        assert req_body['groups'] == [catalog_groups_metadata_model]
        assert req_body['users'] == [catalog_users_metadata_model]

    def test_create_catalog_users_required_params_with_retries(self):
        # Enable retries and run test_create_catalog_users_required_params.
        _service.enable_retries()
        self.test_create_catalog_users_required_params()

        # Disable retries and run test_create_catalog_users_required_params.
        _service.disable_retries()
        self.test_create_catalog_users_required_params()

    @responses.activate
    def test_create_catalog_users_value_error(self):
        """
        test_create_catalog_users_value_error()
        """
        # Set up mock
        url = preprocess_url('/access/catalogs')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a CatalogGroupsMetadata model
        catalog_groups_metadata_model = {}
        catalog_groups_metadata_model['group_id'] = 'testString'
        catalog_groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a CatalogUsersMetadata model
        catalog_users_metadata_model = {}
        catalog_users_metadata_model['permission'] = 'can_administer'
        catalog_users_metadata_model['user_name'] = 'testString'

        # Set up parameter values
        catalog_name = 'testString'
        groups = [catalog_groups_metadata_model]
        users = [catalog_users_metadata_model]

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "catalog_name": catalog_name,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_catalog_users(**req_copy)

    def test_create_catalog_users_value_error_with_retries(self):
        # Enable retries and run test_create_catalog_users_value_error.
        _service.enable_retries()
        self.test_create_catalog_users_value_error()

        # Disable retries and run test_create_catalog_users_value_error.
        _service.disable_retries()
        self.test_create_catalog_users_value_error()


class TestGetCatalogUsers:
    """
    Test Class for get_catalog_users
    """

    @responses.activate
    def test_get_catalog_users_all_params(self):
        """
        get_catalog_users()
        """
        # Set up mock
        url = preprocess_url('/access/catalogs/testString')
        mock_response = '{"total_count": 11, "users": [{"permission": "can_administer", "user_name": "user_name"}], "catalog_name": "catalog_name", "groups": [{"group_id": "group_id", "permission": "can_administer"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        catalog_name = 'testString'
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.get_catalog_users(
            catalog_name,
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_catalog_users_all_params_with_retries(self):
        # Enable retries and run test_get_catalog_users_all_params.
        _service.enable_retries()
        self.test_get_catalog_users_all_params()

        # Disable retries and run test_get_catalog_users_all_params.
        _service.disable_retries()
        self.test_get_catalog_users_all_params()

    @responses.activate
    def test_get_catalog_users_required_params(self):
        """
        test_get_catalog_users_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/catalogs/testString')
        mock_response = '{"total_count": 11, "users": [{"permission": "can_administer", "user_name": "user_name"}], "catalog_name": "catalog_name", "groups": [{"group_id": "group_id", "permission": "can_administer"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        catalog_name = 'testString'

        # Invoke method
        response = _service.get_catalog_users(
            catalog_name,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_catalog_users_required_params_with_retries(self):
        # Enable retries and run test_get_catalog_users_required_params.
        _service.enable_retries()
        self.test_get_catalog_users_required_params()

        # Disable retries and run test_get_catalog_users_required_params.
        _service.disable_retries()
        self.test_get_catalog_users_required_params()

    @responses.activate
    def test_get_catalog_users_value_error(self):
        """
        test_get_catalog_users_value_error()
        """
        # Set up mock
        url = preprocess_url('/access/catalogs/testString')
        mock_response = '{"total_count": 11, "users": [{"permission": "can_administer", "user_name": "user_name"}], "catalog_name": "catalog_name", "groups": [{"group_id": "group_id", "permission": "can_administer"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        catalog_name = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "catalog_name": catalog_name,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_catalog_users(**req_copy)

    def test_get_catalog_users_value_error_with_retries(self):
        # Enable retries and run test_get_catalog_users_value_error.
        _service.enable_retries()
        self.test_get_catalog_users_value_error()

        # Disable retries and run test_get_catalog_users_value_error.
        _service.disable_retries()
        self.test_get_catalog_users_value_error()


class TestDeleteCatalogUsers:
    """
    Test Class for delete_catalog_users
    """

    @responses.activate
    def test_delete_catalog_users_all_params(self):
        """
        delete_catalog_users()
        """
        # Set up mock
        url = preprocess_url('/access/catalogs/testString')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        catalog_name = 'testString'
        groups = ['testString']
        users = ['testString']
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.delete_catalog_users(
            catalog_name,
            groups=groups,
            users=users,
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['groups'] == ['testString']
        assert req_body['users'] == ['testString']

    def test_delete_catalog_users_all_params_with_retries(self):
        # Enable retries and run test_delete_catalog_users_all_params.
        _service.enable_retries()
        self.test_delete_catalog_users_all_params()

        # Disable retries and run test_delete_catalog_users_all_params.
        _service.disable_retries()
        self.test_delete_catalog_users_all_params()

    @responses.activate
    def test_delete_catalog_users_required_params(self):
        """
        test_delete_catalog_users_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/catalogs/testString')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        catalog_name = 'testString'
        groups = ['testString']
        users = ['testString']

        # Invoke method
        response = _service.delete_catalog_users(
            catalog_name,
            groups=groups,
            users=users,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['groups'] == ['testString']
        assert req_body['users'] == ['testString']

    def test_delete_catalog_users_required_params_with_retries(self):
        # Enable retries and run test_delete_catalog_users_required_params.
        _service.enable_retries()
        self.test_delete_catalog_users_required_params()

        # Disable retries and run test_delete_catalog_users_required_params.
        _service.disable_retries()
        self.test_delete_catalog_users_required_params()

    @responses.activate
    def test_delete_catalog_users_value_error(self):
        """
        test_delete_catalog_users_value_error()
        """
        # Set up mock
        url = preprocess_url('/access/catalogs/testString')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        catalog_name = 'testString'
        groups = ['testString']
        users = ['testString']

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "catalog_name": catalog_name,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_catalog_users(**req_copy)

    def test_delete_catalog_users_value_error_with_retries(self):
        # Enable retries and run test_delete_catalog_users_value_error.
        _service.enable_retries()
        self.test_delete_catalog_users_value_error()

        # Disable retries and run test_delete_catalog_users_value_error.
        _service.disable_retries()
        self.test_delete_catalog_users_value_error()


class TestUpdateCatalogUsers:
    """
    Test Class for update_catalog_users
    """

    @responses.activate
    def test_update_catalog_users_all_params(self):
        """
        update_catalog_users()
        """
        # Set up mock
        url = preprocess_url('/access/catalogs/testString')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a CatalogGroupsMetadata model
        catalog_groups_metadata_model = {}
        catalog_groups_metadata_model['group_id'] = 'testString'
        catalog_groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a CatalogUsersMetadata model
        catalog_users_metadata_model = {}
        catalog_users_metadata_model['permission'] = 'can_administer'
        catalog_users_metadata_model['user_name'] = 'testString'

        # Set up parameter values
        catalog_name = 'testString'
        groups = [catalog_groups_metadata_model]
        users = [catalog_users_metadata_model]
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.update_catalog_users(
            catalog_name,
            groups=groups,
            users=users,
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['groups'] == [catalog_groups_metadata_model]
        assert req_body['users'] == [catalog_users_metadata_model]

    def test_update_catalog_users_all_params_with_retries(self):
        # Enable retries and run test_update_catalog_users_all_params.
        _service.enable_retries()
        self.test_update_catalog_users_all_params()

        # Disable retries and run test_update_catalog_users_all_params.
        _service.disable_retries()
        self.test_update_catalog_users_all_params()

    @responses.activate
    def test_update_catalog_users_required_params(self):
        """
        test_update_catalog_users_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/catalogs/testString')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a CatalogGroupsMetadata model
        catalog_groups_metadata_model = {}
        catalog_groups_metadata_model['group_id'] = 'testString'
        catalog_groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a CatalogUsersMetadata model
        catalog_users_metadata_model = {}
        catalog_users_metadata_model['permission'] = 'can_administer'
        catalog_users_metadata_model['user_name'] = 'testString'

        # Set up parameter values
        catalog_name = 'testString'
        groups = [catalog_groups_metadata_model]
        users = [catalog_users_metadata_model]

        # Invoke method
        response = _service.update_catalog_users(
            catalog_name,
            groups=groups,
            users=users,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['groups'] == [catalog_groups_metadata_model]
        assert req_body['users'] == [catalog_users_metadata_model]

    def test_update_catalog_users_required_params_with_retries(self):
        # Enable retries and run test_update_catalog_users_required_params.
        _service.enable_retries()
        self.test_update_catalog_users_required_params()

        # Disable retries and run test_update_catalog_users_required_params.
        _service.disable_retries()
        self.test_update_catalog_users_required_params()

    @responses.activate
    def test_update_catalog_users_value_error(self):
        """
        test_update_catalog_users_value_error()
        """
        # Set up mock
        url = preprocess_url('/access/catalogs/testString')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a CatalogGroupsMetadata model
        catalog_groups_metadata_model = {}
        catalog_groups_metadata_model['group_id'] = 'testString'
        catalog_groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a CatalogUsersMetadata model
        catalog_users_metadata_model = {}
        catalog_users_metadata_model['permission'] = 'can_administer'
        catalog_users_metadata_model['user_name'] = 'testString'

        # Set up parameter values
        catalog_name = 'testString'
        groups = [catalog_groups_metadata_model]
        users = [catalog_users_metadata_model]

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "catalog_name": catalog_name,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.update_catalog_users(**req_copy)

    def test_update_catalog_users_value_error_with_retries(self):
        # Enable retries and run test_update_catalog_users_value_error.
        _service.enable_retries()
        self.test_update_catalog_users_value_error()

        # Disable retries and run test_update_catalog_users_value_error.
        _service.disable_retries()
        self.test_update_catalog_users_value_error()


class TestEvaluate:
    """
    Test Class for evaluate
    """

    @responses.activate
    def test_evaluate_all_params(self):
        """
        evaluate()
        """
        # Set up mock
        url = preprocess_url('/access/evaluation')
        mock_response = '{"resources": [{"action": "action", "resource_name": "resource_name", "resource_type": "resource_type", "result": true}]}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a ResourcesMetadata model
        resources_metadata_model = {}
        resources_metadata_model['action'] = 'testString'
        resources_metadata_model['resource_name'] = 'testString'
        resources_metadata_model['resource_type'] = 'engine'

        # Set up parameter values
        resources = [resources_metadata_model]
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.evaluate(
            resources=resources,
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['resources'] == [resources_metadata_model]

    def test_evaluate_all_params_with_retries(self):
        # Enable retries and run test_evaluate_all_params.
        _service.enable_retries()
        self.test_evaluate_all_params()

        # Disable retries and run test_evaluate_all_params.
        _service.disable_retries()
        self.test_evaluate_all_params()

    @responses.activate
    def test_evaluate_required_params(self):
        """
        test_evaluate_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/evaluation')
        mock_response = '{"resources": [{"action": "action", "resource_name": "resource_name", "resource_type": "resource_type", "result": true}]}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a ResourcesMetadata model
        resources_metadata_model = {}
        resources_metadata_model['action'] = 'testString'
        resources_metadata_model['resource_name'] = 'testString'
        resources_metadata_model['resource_type'] = 'engine'

        # Set up parameter values
        resources = [resources_metadata_model]

        # Invoke method
        response = _service.evaluate(
            resources=resources,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['resources'] == [resources_metadata_model]

    def test_evaluate_required_params_with_retries(self):
        # Enable retries and run test_evaluate_required_params.
        _service.enable_retries()
        self.test_evaluate_required_params()

        # Disable retries and run test_evaluate_required_params.
        _service.disable_retries()
        self.test_evaluate_required_params()


class TestGetPoliciesList:
    """
    Test Class for get_policies_list
    """

    @responses.activate
    def test_get_policies_list_all_params(self):
        """
        get_policies_list()
        """
        # Set up mock
        url = preprocess_url('/access/policies')
        mock_response = '{"catalog_policies": [{"total_count": 11, "users": [{"permission": "can_administer", "user_name": "user_name"}], "catalog_name": "catalog_name", "groups": [{"group_id": "group_id", "permission": "can_administer"}]}], "data_policies": [{"rule_count": 10, "rules": [{"actions": ["all"], "effect": "allow", "grantee": {"value": "value", "key": "user_name", "type": "user_identity"}}], "status": "active", "catalog_name": "catalog_name", "data_artifact": "schema1/table1/(column1|column2)", "metadata": {"creator": "creator", "description": "description", "modifier": "modifier", "pid": "pid", "policy_name": "policy_name", "updated_at": "updated_at", "version": "version", "created_at": "created_at"}, "policy_name": "policy_name"}], "engine_policies": [{"engine_id": "engine_id", "groups": [{"group_id": "group_id", "permission": "can_administer"}], "total_count": 11, "users": [{"permission": "can_administer", "user_name": "user_name"}]}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'
        catalog_list = ['testString']
        engine_list = ['testString']
        data_policies_list = ['testString']
        include_data_policies = True

        # Invoke method
        response = _service.get_policies_list(
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            catalog_list=catalog_list,
            engine_list=engine_list,
            data_policies_list=data_policies_list,
            include_data_policies=include_data_policies,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'catalog_list={}'.format(','.join(catalog_list)) in query_string
        assert 'engine_list={}'.format(','.join(engine_list)) in query_string
        assert 'data_policies_list={}'.format(','.join(data_policies_list)) in query_string
        assert 'include_data_policies={}'.format('true' if include_data_policies else 'false') in query_string

    def test_get_policies_list_all_params_with_retries(self):
        # Enable retries and run test_get_policies_list_all_params.
        _service.enable_retries()
        self.test_get_policies_list_all_params()

        # Disable retries and run test_get_policies_list_all_params.
        _service.disable_retries()
        self.test_get_policies_list_all_params()

    @responses.activate
    def test_get_policies_list_required_params(self):
        """
        test_get_policies_list_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/policies')
        mock_response = '{"catalog_policies": [{"total_count": 11, "users": [{"permission": "can_administer", "user_name": "user_name"}], "catalog_name": "catalog_name", "groups": [{"group_id": "group_id", "permission": "can_administer"}]}], "data_policies": [{"rule_count": 10, "rules": [{"actions": ["all"], "effect": "allow", "grantee": {"value": "value", "key": "user_name", "type": "user_identity"}}], "status": "active", "catalog_name": "catalog_name", "data_artifact": "schema1/table1/(column1|column2)", "metadata": {"creator": "creator", "description": "description", "modifier": "modifier", "pid": "pid", "policy_name": "policy_name", "updated_at": "updated_at", "version": "version", "created_at": "created_at"}, "policy_name": "policy_name"}], "engine_policies": [{"engine_id": "engine_id", "groups": [{"group_id": "group_id", "permission": "can_administer"}], "total_count": 11, "users": [{"permission": "can_administer", "user_name": "user_name"}]}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Invoke method
        response = _service.get_policies_list()

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_policies_list_required_params_with_retries(self):
        # Enable retries and run test_get_policies_list_required_params.
        _service.enable_retries()
        self.test_get_policies_list_required_params()

        # Disable retries and run test_get_policies_list_required_params.
        _service.disable_retries()
        self.test_get_policies_list_required_params()


class TestCreateMetastoreUsers:
    """
    Test Class for create_metastore_users
    """

    @responses.activate
    def test_create_metastore_users_all_params(self):
        """
        create_metastore_users()
        """
        # Set up mock
        url = preprocess_url('/access/metastores')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a GroupsMetadata model
        groups_metadata_model = {}
        groups_metadata_model['group_id'] = 'testString'
        groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a UsersMetadata model
        users_metadata_model = {}
        users_metadata_model['permission'] = 'can_administer'
        users_metadata_model['user_name'] = 'testString'

        # Set up parameter values
        metastore_name = 'testString'
        groups = [groups_metadata_model]
        users = [users_metadata_model]
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.create_metastore_users(
            metastore_name,
            groups=groups,
            users=users,
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['metastore_name'] == 'testString'
        assert req_body['groups'] == [groups_metadata_model]
        assert req_body['users'] == [users_metadata_model]

    def test_create_metastore_users_all_params_with_retries(self):
        # Enable retries and run test_create_metastore_users_all_params.
        _service.enable_retries()
        self.test_create_metastore_users_all_params()

        # Disable retries and run test_create_metastore_users_all_params.
        _service.disable_retries()
        self.test_create_metastore_users_all_params()

    @responses.activate
    def test_create_metastore_users_required_params(self):
        """
        test_create_metastore_users_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/metastores')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a GroupsMetadata model
        groups_metadata_model = {}
        groups_metadata_model['group_id'] = 'testString'
        groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a UsersMetadata model
        users_metadata_model = {}
        users_metadata_model['permission'] = 'can_administer'
        users_metadata_model['user_name'] = 'testString'

        # Set up parameter values
        metastore_name = 'testString'
        groups = [groups_metadata_model]
        users = [users_metadata_model]

        # Invoke method
        response = _service.create_metastore_users(
            metastore_name,
            groups=groups,
            users=users,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['metastore_name'] == 'testString'
        assert req_body['groups'] == [groups_metadata_model]
        assert req_body['users'] == [users_metadata_model]

    def test_create_metastore_users_required_params_with_retries(self):
        # Enable retries and run test_create_metastore_users_required_params.
        _service.enable_retries()
        self.test_create_metastore_users_required_params()

        # Disable retries and run test_create_metastore_users_required_params.
        _service.disable_retries()
        self.test_create_metastore_users_required_params()

    @responses.activate
    def test_create_metastore_users_value_error(self):
        """
        test_create_metastore_users_value_error()
        """
        # Set up mock
        url = preprocess_url('/access/metastores')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a GroupsMetadata model
        groups_metadata_model = {}
        groups_metadata_model['group_id'] = 'testString'
        groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a UsersMetadata model
        users_metadata_model = {}
        users_metadata_model['permission'] = 'can_administer'
        users_metadata_model['user_name'] = 'testString'

        # Set up parameter values
        metastore_name = 'testString'
        groups = [groups_metadata_model]
        users = [users_metadata_model]

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "metastore_name": metastore_name,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_metastore_users(**req_copy)

    def test_create_metastore_users_value_error_with_retries(self):
        # Enable retries and run test_create_metastore_users_value_error.
        _service.enable_retries()
        self.test_create_metastore_users_value_error()

        # Disable retries and run test_create_metastore_users_value_error.
        _service.disable_retries()
        self.test_create_metastore_users_value_error()


class TestGetMetastoreUsers:
    """
    Test Class for get_metastore_users
    """

    @responses.activate
    def test_get_metastore_users_all_params(self):
        """
        get_metastore_users()
        """
        # Set up mock
        url = preprocess_url('/access/metastores/testString')
        mock_response = '{"groups": [{"group_id": "group_id", "permission": "can_administer"}], "metastore_name": "metastore_name", "total_count": 11, "users": [{"permission": "can_administer", "user_name": "user_name"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        metastore_name = 'testString'
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.get_metastore_users(
            metastore_name,
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_metastore_users_all_params_with_retries(self):
        # Enable retries and run test_get_metastore_users_all_params.
        _service.enable_retries()
        self.test_get_metastore_users_all_params()

        # Disable retries and run test_get_metastore_users_all_params.
        _service.disable_retries()
        self.test_get_metastore_users_all_params()

    @responses.activate
    def test_get_metastore_users_required_params(self):
        """
        test_get_metastore_users_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/metastores/testString')
        mock_response = '{"groups": [{"group_id": "group_id", "permission": "can_administer"}], "metastore_name": "metastore_name", "total_count": 11, "users": [{"permission": "can_administer", "user_name": "user_name"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        metastore_name = 'testString'

        # Invoke method
        response = _service.get_metastore_users(
            metastore_name,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_metastore_users_required_params_with_retries(self):
        # Enable retries and run test_get_metastore_users_required_params.
        _service.enable_retries()
        self.test_get_metastore_users_required_params()

        # Disable retries and run test_get_metastore_users_required_params.
        _service.disable_retries()
        self.test_get_metastore_users_required_params()

    @responses.activate
    def test_get_metastore_users_value_error(self):
        """
        test_get_metastore_users_value_error()
        """
        # Set up mock
        url = preprocess_url('/access/metastores/testString')
        mock_response = '{"groups": [{"group_id": "group_id", "permission": "can_administer"}], "metastore_name": "metastore_name", "total_count": 11, "users": [{"permission": "can_administer", "user_name": "user_name"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        metastore_name = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "metastore_name": metastore_name,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_metastore_users(**req_copy)

    def test_get_metastore_users_value_error_with_retries(self):
        # Enable retries and run test_get_metastore_users_value_error.
        _service.enable_retries()
        self.test_get_metastore_users_value_error()

        # Disable retries and run test_get_metastore_users_value_error.
        _service.disable_retries()
        self.test_get_metastore_users_value_error()


class TestDeleteMetastoreUsers:
    """
    Test Class for delete_metastore_users
    """

    @responses.activate
    def test_delete_metastore_users_all_params(self):
        """
        delete_metastore_users()
        """
        # Set up mock
        url = preprocess_url('/access/metastores/testString')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        metastore_name = 'testString'
        groups = ['testString']
        users = ['testString']
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.delete_metastore_users(
            metastore_name,
            groups=groups,
            users=users,
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['groups'] == ['testString']
        assert req_body['users'] == ['testString']

    def test_delete_metastore_users_all_params_with_retries(self):
        # Enable retries and run test_delete_metastore_users_all_params.
        _service.enable_retries()
        self.test_delete_metastore_users_all_params()

        # Disable retries and run test_delete_metastore_users_all_params.
        _service.disable_retries()
        self.test_delete_metastore_users_all_params()

    @responses.activate
    def test_delete_metastore_users_required_params(self):
        """
        test_delete_metastore_users_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/metastores/testString')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        metastore_name = 'testString'
        groups = ['testString']
        users = ['testString']

        # Invoke method
        response = _service.delete_metastore_users(
            metastore_name,
            groups=groups,
            users=users,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['groups'] == ['testString']
        assert req_body['users'] == ['testString']

    def test_delete_metastore_users_required_params_with_retries(self):
        # Enable retries and run test_delete_metastore_users_required_params.
        _service.enable_retries()
        self.test_delete_metastore_users_required_params()

        # Disable retries and run test_delete_metastore_users_required_params.
        _service.disable_retries()
        self.test_delete_metastore_users_required_params()

    @responses.activate
    def test_delete_metastore_users_value_error(self):
        """
        test_delete_metastore_users_value_error()
        """
        # Set up mock
        url = preprocess_url('/access/metastores/testString')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        metastore_name = 'testString'
        groups = ['testString']
        users = ['testString']

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "metastore_name": metastore_name,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_metastore_users(**req_copy)

    def test_delete_metastore_users_value_error_with_retries(self):
        # Enable retries and run test_delete_metastore_users_value_error.
        _service.enable_retries()
        self.test_delete_metastore_users_value_error()

        # Disable retries and run test_delete_metastore_users_value_error.
        _service.disable_retries()
        self.test_delete_metastore_users_value_error()


class TestUpdateMetastoreUsers:
    """
    Test Class for update_metastore_users
    """

    @responses.activate
    def test_update_metastore_users_all_params(self):
        """
        update_metastore_users()
        """
        # Set up mock
        url = preprocess_url('/access/metastores/testString')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a GroupsMetadata model
        groups_metadata_model = {}
        groups_metadata_model['group_id'] = 'testString'
        groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a UsersMetadata model
        users_metadata_model = {}
        users_metadata_model['permission'] = 'can_administer'
        users_metadata_model['user_name'] = 'testString'

        # Set up parameter values
        metastore_name = 'testString'
        groups = [groups_metadata_model]
        users = [users_metadata_model]
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.update_metastore_users(
            metastore_name,
            groups=groups,
            users=users,
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['groups'] == [groups_metadata_model]
        assert req_body['users'] == [users_metadata_model]

    def test_update_metastore_users_all_params_with_retries(self):
        # Enable retries and run test_update_metastore_users_all_params.
        _service.enable_retries()
        self.test_update_metastore_users_all_params()

        # Disable retries and run test_update_metastore_users_all_params.
        _service.disable_retries()
        self.test_update_metastore_users_all_params()

    @responses.activate
    def test_update_metastore_users_required_params(self):
        """
        test_update_metastore_users_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/metastores/testString')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a GroupsMetadata model
        groups_metadata_model = {}
        groups_metadata_model['group_id'] = 'testString'
        groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a UsersMetadata model
        users_metadata_model = {}
        users_metadata_model['permission'] = 'can_administer'
        users_metadata_model['user_name'] = 'testString'

        # Set up parameter values
        metastore_name = 'testString'
        groups = [groups_metadata_model]
        users = [users_metadata_model]

        # Invoke method
        response = _service.update_metastore_users(
            metastore_name,
            groups=groups,
            users=users,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['groups'] == [groups_metadata_model]
        assert req_body['users'] == [users_metadata_model]

    def test_update_metastore_users_required_params_with_retries(self):
        # Enable retries and run test_update_metastore_users_required_params.
        _service.enable_retries()
        self.test_update_metastore_users_required_params()

        # Disable retries and run test_update_metastore_users_required_params.
        _service.disable_retries()
        self.test_update_metastore_users_required_params()

    @responses.activate
    def test_update_metastore_users_value_error(self):
        """
        test_update_metastore_users_value_error()
        """
        # Set up mock
        url = preprocess_url('/access/metastores/testString')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a GroupsMetadata model
        groups_metadata_model = {}
        groups_metadata_model['group_id'] = 'testString'
        groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a UsersMetadata model
        users_metadata_model = {}
        users_metadata_model['permission'] = 'can_administer'
        users_metadata_model['user_name'] = 'testString'

        # Set up parameter values
        metastore_name = 'testString'
        groups = [groups_metadata_model]
        users = [users_metadata_model]

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "metastore_name": metastore_name,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.update_metastore_users(**req_copy)

    def test_update_metastore_users_value_error_with_retries(self):
        # Enable retries and run test_update_metastore_users_value_error.
        _service.enable_retries()
        self.test_update_metastore_users_value_error()

        # Disable retries and run test_update_metastore_users_value_error.
        _service.disable_retries()
        self.test_update_metastore_users_value_error()


class TestCreateBucketUsers:
    """
    Test Class for create_bucket_users
    """

    @responses.activate
    def test_create_bucket_users_all_params(self):
        """
        create_bucket_users()
        """
        # Set up mock
        url = preprocess_url('/access/buckets')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a BucketDbConnGroupsMetadata model
        bucket_db_conn_groups_metadata_model = {}
        bucket_db_conn_groups_metadata_model['group_id'] = 'testString'
        bucket_db_conn_groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a BucketDbConnUsersMetadata model
        bucket_db_conn_users_metadata_model = {}
        bucket_db_conn_users_metadata_model['user_name'] = 'testString'
        bucket_db_conn_users_metadata_model['permission'] = 'can_administer'

        # Set up parameter values
        bucket_id = 'testString'
        groups = [bucket_db_conn_groups_metadata_model]
        users = [bucket_db_conn_users_metadata_model]
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.create_bucket_users(
            bucket_id,
            groups=groups,
            users=users,
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['bucket_id'] == 'testString'
        assert req_body['groups'] == [bucket_db_conn_groups_metadata_model]
        assert req_body['users'] == [bucket_db_conn_users_metadata_model]

    def test_create_bucket_users_all_params_with_retries(self):
        # Enable retries and run test_create_bucket_users_all_params.
        _service.enable_retries()
        self.test_create_bucket_users_all_params()

        # Disable retries and run test_create_bucket_users_all_params.
        _service.disable_retries()
        self.test_create_bucket_users_all_params()

    @responses.activate
    def test_create_bucket_users_required_params(self):
        """
        test_create_bucket_users_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/buckets')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a BucketDbConnGroupsMetadata model
        bucket_db_conn_groups_metadata_model = {}
        bucket_db_conn_groups_metadata_model['group_id'] = 'testString'
        bucket_db_conn_groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a BucketDbConnUsersMetadata model
        bucket_db_conn_users_metadata_model = {}
        bucket_db_conn_users_metadata_model['user_name'] = 'testString'
        bucket_db_conn_users_metadata_model['permission'] = 'can_administer'

        # Set up parameter values
        bucket_id = 'testString'
        groups = [bucket_db_conn_groups_metadata_model]
        users = [bucket_db_conn_users_metadata_model]

        # Invoke method
        response = _service.create_bucket_users(
            bucket_id,
            groups=groups,
            users=users,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['bucket_id'] == 'testString'
        assert req_body['groups'] == [bucket_db_conn_groups_metadata_model]
        assert req_body['users'] == [bucket_db_conn_users_metadata_model]

    def test_create_bucket_users_required_params_with_retries(self):
        # Enable retries and run test_create_bucket_users_required_params.
        _service.enable_retries()
        self.test_create_bucket_users_required_params()

        # Disable retries and run test_create_bucket_users_required_params.
        _service.disable_retries()
        self.test_create_bucket_users_required_params()

    @responses.activate
    def test_create_bucket_users_value_error(self):
        """
        test_create_bucket_users_value_error()
        """
        # Set up mock
        url = preprocess_url('/access/buckets')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a BucketDbConnGroupsMetadata model
        bucket_db_conn_groups_metadata_model = {}
        bucket_db_conn_groups_metadata_model['group_id'] = 'testString'
        bucket_db_conn_groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a BucketDbConnUsersMetadata model
        bucket_db_conn_users_metadata_model = {}
        bucket_db_conn_users_metadata_model['user_name'] = 'testString'
        bucket_db_conn_users_metadata_model['permission'] = 'can_administer'

        # Set up parameter values
        bucket_id = 'testString'
        groups = [bucket_db_conn_groups_metadata_model]
        users = [bucket_db_conn_users_metadata_model]

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "bucket_id": bucket_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_bucket_users(**req_copy)

    def test_create_bucket_users_value_error_with_retries(self):
        # Enable retries and run test_create_bucket_users_value_error.
        _service.enable_retries()
        self.test_create_bucket_users_value_error()

        # Disable retries and run test_create_bucket_users_value_error.
        _service.disable_retries()
        self.test_create_bucket_users_value_error()


class TestGetDefaultPolicies:
    """
    Test Class for get_default_policies
    """

    @responses.activate
    def test_get_default_policies_all_params(self):
        """
        get_default_policies()
        """
        # Set up mock
        url = preprocess_url('/access/default_policies')
        mock_response = '{"grouping_policies": [{"domain": "domain", "inheritor": "inheritor", "role": "role"}], "model": "model", "policies": [{"subject": "subject", "actions": ["actions"], "domain": "domain", "object": "object"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.get_default_policies(
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_default_policies_all_params_with_retries(self):
        # Enable retries and run test_get_default_policies_all_params.
        _service.enable_retries()
        self.test_get_default_policies_all_params()

        # Disable retries and run test_get_default_policies_all_params.
        _service.disable_retries()
        self.test_get_default_policies_all_params()

    @responses.activate
    def test_get_default_policies_required_params(self):
        """
        test_get_default_policies_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/default_policies')
        mock_response = '{"grouping_policies": [{"domain": "domain", "inheritor": "inheritor", "role": "role"}], "model": "model", "policies": [{"subject": "subject", "actions": ["actions"], "domain": "domain", "object": "object"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Invoke method
        response = _service.get_default_policies()

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_default_policies_required_params_with_retries(self):
        # Enable retries and run test_get_default_policies_required_params.
        _service.enable_retries()
        self.test_get_default_policies_required_params()

        # Disable retries and run test_get_default_policies_required_params.
        _service.disable_retries()
        self.test_get_default_policies_required_params()


class TestGetPolicyVersion:
    """
    Test Class for get_policy_version
    """

    @responses.activate
    def test_get_policy_version_all_params(self):
        """
        get_policy_version()
        """
        # Set up mock
        url = preprocess_url('/access/policy_versions')
        mock_response = '{"catalog_policies": [{"policy_name": "policy_name", "policy_version": "policy_version"}], "data_policies": [{"associate_catalog": "associate_catalog", "policy_name": "policy_name", "policy_version": "policy_version"}], "database_policies": [{"policy_name": "policy_name", "policy_version": "policy_version"}], "engine_policies": [{"policy_name": "policy_name", "policy_version": "policy_version"}], "bucket_policies": [{"policy_version": "policy_version", "policy_name": "policy_name"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.get_policy_version(
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_policy_version_all_params_with_retries(self):
        # Enable retries and run test_get_policy_version_all_params.
        _service.enable_retries()
        self.test_get_policy_version_all_params()

        # Disable retries and run test_get_policy_version_all_params.
        _service.disable_retries()
        self.test_get_policy_version_all_params()

    @responses.activate
    def test_get_policy_version_required_params(self):
        """
        test_get_policy_version_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/policy_versions')
        mock_response = '{"catalog_policies": [{"policy_name": "policy_name", "policy_version": "policy_version"}], "data_policies": [{"associate_catalog": "associate_catalog", "policy_name": "policy_name", "policy_version": "policy_version"}], "database_policies": [{"policy_name": "policy_name", "policy_version": "policy_version"}], "engine_policies": [{"policy_name": "policy_name", "policy_version": "policy_version"}], "bucket_policies": [{"policy_version": "policy_version", "policy_name": "policy_name"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Invoke method
        response = _service.get_policy_version()

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_policy_version_required_params_with_retries(self):
        # Enable retries and run test_get_policy_version_required_params.
        _service.enable_retries()
        self.test_get_policy_version_required_params()

        # Disable retries and run test_get_policy_version_required_params.
        _service.disable_retries()
        self.test_get_policy_version_required_params()


class TestGetDataPolicy:
    """
    Test Class for get_data_policy
    """

    @responses.activate
    def test_get_data_policy_all_params(self):
        """
        get_data_policy()
        """
        # Set up mock
        url = preprocess_url('/access/data_policies/testString')
        mock_response = '{"rule_count": 10, "rules": [{"actions": ["all"], "effect": "allow", "grantee": {"value": "value", "key": "user_name", "type": "user_identity"}}], "status": "active", "catalog_name": "catalog_name", "data_artifact": "schema1/table1/(column1|column2)", "metadata": {"creator": "creator", "description": "description", "modifier": "modifier", "pid": "pid", "policy_name": "policy_name", "updated_at": "updated_at", "version": "version", "created_at": "created_at"}, "policy_name": "policy_name"}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        policy_name = 'testString'
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.get_data_policy(
            policy_name,
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_data_policy_all_params_with_retries(self):
        # Enable retries and run test_get_data_policy_all_params.
        _service.enable_retries()
        self.test_get_data_policy_all_params()

        # Disable retries and run test_get_data_policy_all_params.
        _service.disable_retries()
        self.test_get_data_policy_all_params()

    @responses.activate
    def test_get_data_policy_required_params(self):
        """
        test_get_data_policy_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/data_policies/testString')
        mock_response = '{"rule_count": 10, "rules": [{"actions": ["all"], "effect": "allow", "grantee": {"value": "value", "key": "user_name", "type": "user_identity"}}], "status": "active", "catalog_name": "catalog_name", "data_artifact": "schema1/table1/(column1|column2)", "metadata": {"creator": "creator", "description": "description", "modifier": "modifier", "pid": "pid", "policy_name": "policy_name", "updated_at": "updated_at", "version": "version", "created_at": "created_at"}, "policy_name": "policy_name"}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        policy_name = 'testString'

        # Invoke method
        response = _service.get_data_policy(
            policy_name,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_data_policy_required_params_with_retries(self):
        # Enable retries and run test_get_data_policy_required_params.
        _service.enable_retries()
        self.test_get_data_policy_required_params()

        # Disable retries and run test_get_data_policy_required_params.
        _service.disable_retries()
        self.test_get_data_policy_required_params()

    @responses.activate
    def test_get_data_policy_value_error(self):
        """
        test_get_data_policy_value_error()
        """
        # Set up mock
        url = preprocess_url('/access/data_policies/testString')
        mock_response = '{"rule_count": 10, "rules": [{"actions": ["all"], "effect": "allow", "grantee": {"value": "value", "key": "user_name", "type": "user_identity"}}], "status": "active", "catalog_name": "catalog_name", "data_artifact": "schema1/table1/(column1|column2)", "metadata": {"creator": "creator", "description": "description", "modifier": "modifier", "pid": "pid", "policy_name": "policy_name", "updated_at": "updated_at", "version": "version", "created_at": "created_at"}, "policy_name": "policy_name"}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        policy_name = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "policy_name": policy_name,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_data_policy(**req_copy)

    def test_get_data_policy_value_error_with_retries(self):
        # Enable retries and run test_get_data_policy_value_error.
        _service.enable_retries()
        self.test_get_data_policy_value_error()

        # Disable retries and run test_get_data_policy_value_error.
        _service.disable_retries()
        self.test_get_data_policy_value_error()


class TestReplaceDataPolicy:
    """
    Test Class for replace_data_policy
    """

    @responses.activate
    def test_replace_data_policy_all_params(self):
        """
        replace_data_policy()
        """
        # Set up mock
        url = preprocess_url('/access/data_policies/testString')
        mock_response = '{"data_policy": {"catalog_name": "catalog_name", "data_artifact": "schema1/table1/(column1|column2)", "description": "description", "rules": [{"actions": ["all"], "effect": "allow", "grantee": {"value": "value", "key": "user_name", "type": "user_identity"}}], "status": "active"}, "metadata": {"creator": "creator", "description": "description", "modifier": "modifier", "pid": "pid", "policy_name": "policy_name", "updated_at": "updated_at", "version": "version", "created_at": "created_at"}, "response": {"_messageCode_": "<message code>", "message": "Success"}}'
        responses.add(
            responses.PUT,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a RuleGrantee model
        rule_grantee_model = {}
        rule_grantee_model['value'] = 'testString'
        rule_grantee_model['key'] = 'user_name'
        rule_grantee_model['type'] = 'user_identity'

        # Construct a dict representation of a Rule model
        rule_model = {}
        rule_model['actions'] = ['all']
        rule_model['effect'] = 'allow'
        rule_model['grantee'] = rule_grantee_model

        # Set up parameter values
        policy_name = 'testString'
        catalog_name = 'testString'
        data_artifact = 'schema1/table1/(column1|column2)'
        rules = [rule_model]
        description = 'testString'
        status = 'active'
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.replace_data_policy(
            policy_name,
            catalog_name,
            data_artifact,
            rules,
            description=description,
            status=status,
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['catalog_name'] == 'testString'
        assert req_body['data_artifact'] == 'schema1/table1/(column1|column2)'
        assert req_body['rules'] == [rule_model]
        assert req_body['description'] == 'testString'
        assert req_body['status'] == 'active'

    def test_replace_data_policy_all_params_with_retries(self):
        # Enable retries and run test_replace_data_policy_all_params.
        _service.enable_retries()
        self.test_replace_data_policy_all_params()

        # Disable retries and run test_replace_data_policy_all_params.
        _service.disable_retries()
        self.test_replace_data_policy_all_params()

    @responses.activate
    def test_replace_data_policy_required_params(self):
        """
        test_replace_data_policy_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/data_policies/testString')
        mock_response = '{"data_policy": {"catalog_name": "catalog_name", "data_artifact": "schema1/table1/(column1|column2)", "description": "description", "rules": [{"actions": ["all"], "effect": "allow", "grantee": {"value": "value", "key": "user_name", "type": "user_identity"}}], "status": "active"}, "metadata": {"creator": "creator", "description": "description", "modifier": "modifier", "pid": "pid", "policy_name": "policy_name", "updated_at": "updated_at", "version": "version", "created_at": "created_at"}, "response": {"_messageCode_": "<message code>", "message": "Success"}}'
        responses.add(
            responses.PUT,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a RuleGrantee model
        rule_grantee_model = {}
        rule_grantee_model['value'] = 'testString'
        rule_grantee_model['key'] = 'user_name'
        rule_grantee_model['type'] = 'user_identity'

        # Construct a dict representation of a Rule model
        rule_model = {}
        rule_model['actions'] = ['all']
        rule_model['effect'] = 'allow'
        rule_model['grantee'] = rule_grantee_model

        # Set up parameter values
        policy_name = 'testString'
        catalog_name = 'testString'
        data_artifact = 'schema1/table1/(column1|column2)'
        rules = [rule_model]
        description = 'testString'
        status = 'active'

        # Invoke method
        response = _service.replace_data_policy(
            policy_name,
            catalog_name,
            data_artifact,
            rules,
            description=description,
            status=status,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['catalog_name'] == 'testString'
        assert req_body['data_artifact'] == 'schema1/table1/(column1|column2)'
        assert req_body['rules'] == [rule_model]
        assert req_body['description'] == 'testString'
        assert req_body['status'] == 'active'

    def test_replace_data_policy_required_params_with_retries(self):
        # Enable retries and run test_replace_data_policy_required_params.
        _service.enable_retries()
        self.test_replace_data_policy_required_params()

        # Disable retries and run test_replace_data_policy_required_params.
        _service.disable_retries()
        self.test_replace_data_policy_required_params()

    @responses.activate
    def test_replace_data_policy_value_error(self):
        """
        test_replace_data_policy_value_error()
        """
        # Set up mock
        url = preprocess_url('/access/data_policies/testString')
        mock_response = '{"data_policy": {"catalog_name": "catalog_name", "data_artifact": "schema1/table1/(column1|column2)", "description": "description", "rules": [{"actions": ["all"], "effect": "allow", "grantee": {"value": "value", "key": "user_name", "type": "user_identity"}}], "status": "active"}, "metadata": {"creator": "creator", "description": "description", "modifier": "modifier", "pid": "pid", "policy_name": "policy_name", "updated_at": "updated_at", "version": "version", "created_at": "created_at"}, "response": {"_messageCode_": "<message code>", "message": "Success"}}'
        responses.add(
            responses.PUT,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a RuleGrantee model
        rule_grantee_model = {}
        rule_grantee_model['value'] = 'testString'
        rule_grantee_model['key'] = 'user_name'
        rule_grantee_model['type'] = 'user_identity'

        # Construct a dict representation of a Rule model
        rule_model = {}
        rule_model['actions'] = ['all']
        rule_model['effect'] = 'allow'
        rule_model['grantee'] = rule_grantee_model

        # Set up parameter values
        policy_name = 'testString'
        catalog_name = 'testString'
        data_artifact = 'schema1/table1/(column1|column2)'
        rules = [rule_model]
        description = 'testString'
        status = 'active'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "policy_name": policy_name,
            "catalog_name": catalog_name,
            "data_artifact": data_artifact,
            "rules": rules,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.replace_data_policy(**req_copy)

    def test_replace_data_policy_value_error_with_retries(self):
        # Enable retries and run test_replace_data_policy_value_error.
        _service.enable_retries()
        self.test_replace_data_policy_value_error()

        # Disable retries and run test_replace_data_policy_value_error.
        _service.disable_retries()
        self.test_replace_data_policy_value_error()


class TestDeleteDataPolicy:
    """
    Test Class for delete_data_policy
    """

    @responses.activate
    def test_delete_data_policy_all_params(self):
        """
        delete_data_policy()
        """
        # Set up mock
        url = preprocess_url('/access/data_policies/testString')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        policy_name = 'testString'
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.delete_data_policy(
            policy_name,
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_delete_data_policy_all_params_with_retries(self):
        # Enable retries and run test_delete_data_policy_all_params.
        _service.enable_retries()
        self.test_delete_data_policy_all_params()

        # Disable retries and run test_delete_data_policy_all_params.
        _service.disable_retries()
        self.test_delete_data_policy_all_params()

    @responses.activate
    def test_delete_data_policy_required_params(self):
        """
        test_delete_data_policy_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/data_policies/testString')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        policy_name = 'testString'

        # Invoke method
        response = _service.delete_data_policy(
            policy_name,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_delete_data_policy_required_params_with_retries(self):
        # Enable retries and run test_delete_data_policy_required_params.
        _service.enable_retries()
        self.test_delete_data_policy_required_params()

        # Disable retries and run test_delete_data_policy_required_params.
        _service.disable_retries()
        self.test_delete_data_policy_required_params()

    @responses.activate
    def test_delete_data_policy_value_error(self):
        """
        test_delete_data_policy_value_error()
        """
        # Set up mock
        url = preprocess_url('/access/data_policies/testString')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        policy_name = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "policy_name": policy_name,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_data_policy(**req_copy)

    def test_delete_data_policy_value_error_with_retries(self):
        # Enable retries and run test_delete_data_policy_value_error.
        _service.enable_retries()
        self.test_delete_data_policy_value_error()

        # Disable retries and run test_delete_data_policy_value_error.
        _service.disable_retries()
        self.test_delete_data_policy_value_error()


class TestCreateEngineUsers:
    """
    Test Class for create_engine_users
    """

    @responses.activate
    def test_create_engine_users_all_params(self):
        """
        create_engine_users()
        """
        # Set up mock
        url = preprocess_url('/access/engines')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a EngineGroupsMetadata model
        engine_groups_metadata_model = {}
        engine_groups_metadata_model['group_id'] = 'testString'
        engine_groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a EngineUsersMetadata model
        engine_users_metadata_model = {}
        engine_users_metadata_model['permission'] = 'can_administer'
        engine_users_metadata_model['user_name'] = 'testString'

        # Set up parameter values
        engine_id = 'testString'
        groups = [engine_groups_metadata_model]
        users = [engine_users_metadata_model]
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.create_engine_users(
            engine_id,
            groups=groups,
            users=users,
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['engine_id'] == 'testString'
        assert req_body['groups'] == [engine_groups_metadata_model]
        assert req_body['users'] == [engine_users_metadata_model]

    def test_create_engine_users_all_params_with_retries(self):
        # Enable retries and run test_create_engine_users_all_params.
        _service.enable_retries()
        self.test_create_engine_users_all_params()

        # Disable retries and run test_create_engine_users_all_params.
        _service.disable_retries()
        self.test_create_engine_users_all_params()

    @responses.activate
    def test_create_engine_users_required_params(self):
        """
        test_create_engine_users_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/engines')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a EngineGroupsMetadata model
        engine_groups_metadata_model = {}
        engine_groups_metadata_model['group_id'] = 'testString'
        engine_groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a EngineUsersMetadata model
        engine_users_metadata_model = {}
        engine_users_metadata_model['permission'] = 'can_administer'
        engine_users_metadata_model['user_name'] = 'testString'

        # Set up parameter values
        engine_id = 'testString'
        groups = [engine_groups_metadata_model]
        users = [engine_users_metadata_model]

        # Invoke method
        response = _service.create_engine_users(
            engine_id,
            groups=groups,
            users=users,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['engine_id'] == 'testString'
        assert req_body['groups'] == [engine_groups_metadata_model]
        assert req_body['users'] == [engine_users_metadata_model]

    def test_create_engine_users_required_params_with_retries(self):
        # Enable retries and run test_create_engine_users_required_params.
        _service.enable_retries()
        self.test_create_engine_users_required_params()

        # Disable retries and run test_create_engine_users_required_params.
        _service.disable_retries()
        self.test_create_engine_users_required_params()

    @responses.activate
    def test_create_engine_users_value_error(self):
        """
        test_create_engine_users_value_error()
        """
        # Set up mock
        url = preprocess_url('/access/engines')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a EngineGroupsMetadata model
        engine_groups_metadata_model = {}
        engine_groups_metadata_model['group_id'] = 'testString'
        engine_groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a EngineUsersMetadata model
        engine_users_metadata_model = {}
        engine_users_metadata_model['permission'] = 'can_administer'
        engine_users_metadata_model['user_name'] = 'testString'

        # Set up parameter values
        engine_id = 'testString'
        groups = [engine_groups_metadata_model]
        users = [engine_users_metadata_model]

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "engine_id": engine_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_engine_users(**req_copy)

    def test_create_engine_users_value_error_with_retries(self):
        # Enable retries and run test_create_engine_users_value_error.
        _service.enable_retries()
        self.test_create_engine_users_value_error()

        # Disable retries and run test_create_engine_users_value_error.
        _service.disable_retries()
        self.test_create_engine_users_value_error()


class TestGetBucketUsers:
    """
    Test Class for get_bucket_users
    """

    @responses.activate
    def test_get_bucket_users_all_params(self):
        """
        get_bucket_users()
        """
        # Set up mock
        url = preprocess_url('/access/buckets/testString')
        mock_response = '{"bucket_id": "bucket_id", "groups": [{"group_id": "group_id", "permission": "can_administer"}], "total_count": 11, "users": [{"user_name": "user_name", "permission": "can_administer"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        bucket_id = 'testString'
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.get_bucket_users(
            bucket_id,
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_bucket_users_all_params_with_retries(self):
        # Enable retries and run test_get_bucket_users_all_params.
        _service.enable_retries()
        self.test_get_bucket_users_all_params()

        # Disable retries and run test_get_bucket_users_all_params.
        _service.disable_retries()
        self.test_get_bucket_users_all_params()

    @responses.activate
    def test_get_bucket_users_required_params(self):
        """
        test_get_bucket_users_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/buckets/testString')
        mock_response = '{"bucket_id": "bucket_id", "groups": [{"group_id": "group_id", "permission": "can_administer"}], "total_count": 11, "users": [{"user_name": "user_name", "permission": "can_administer"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        bucket_id = 'testString'

        # Invoke method
        response = _service.get_bucket_users(
            bucket_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_bucket_users_required_params_with_retries(self):
        # Enable retries and run test_get_bucket_users_required_params.
        _service.enable_retries()
        self.test_get_bucket_users_required_params()

        # Disable retries and run test_get_bucket_users_required_params.
        _service.disable_retries()
        self.test_get_bucket_users_required_params()

    @responses.activate
    def test_get_bucket_users_value_error(self):
        """
        test_get_bucket_users_value_error()
        """
        # Set up mock
        url = preprocess_url('/access/buckets/testString')
        mock_response = '{"bucket_id": "bucket_id", "groups": [{"group_id": "group_id", "permission": "can_administer"}], "total_count": 11, "users": [{"user_name": "user_name", "permission": "can_administer"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        bucket_id = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "bucket_id": bucket_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_bucket_users(**req_copy)

    def test_get_bucket_users_value_error_with_retries(self):
        # Enable retries and run test_get_bucket_users_value_error.
        _service.enable_retries()
        self.test_get_bucket_users_value_error()

        # Disable retries and run test_get_bucket_users_value_error.
        _service.disable_retries()
        self.test_get_bucket_users_value_error()


class TestDeleteBucketUsers:
    """
    Test Class for delete_bucket_users
    """

    @responses.activate
    def test_delete_bucket_users_all_params(self):
        """
        delete_bucket_users()
        """
        # Set up mock
        url = preprocess_url('/access/buckets/testString')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        bucket_id = 'testString'
        groups = ['testString']
        users = ['testString']
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.delete_bucket_users(
            bucket_id,
            groups=groups,
            users=users,
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['groups'] == ['testString']
        assert req_body['users'] == ['testString']

    def test_delete_bucket_users_all_params_with_retries(self):
        # Enable retries and run test_delete_bucket_users_all_params.
        _service.enable_retries()
        self.test_delete_bucket_users_all_params()

        # Disable retries and run test_delete_bucket_users_all_params.
        _service.disable_retries()
        self.test_delete_bucket_users_all_params()

    @responses.activate
    def test_delete_bucket_users_required_params(self):
        """
        test_delete_bucket_users_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/buckets/testString')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        bucket_id = 'testString'
        groups = ['testString']
        users = ['testString']

        # Invoke method
        response = _service.delete_bucket_users(
            bucket_id,
            groups=groups,
            users=users,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['groups'] == ['testString']
        assert req_body['users'] == ['testString']

    def test_delete_bucket_users_required_params_with_retries(self):
        # Enable retries and run test_delete_bucket_users_required_params.
        _service.enable_retries()
        self.test_delete_bucket_users_required_params()

        # Disable retries and run test_delete_bucket_users_required_params.
        _service.disable_retries()
        self.test_delete_bucket_users_required_params()

    @responses.activate
    def test_delete_bucket_users_value_error(self):
        """
        test_delete_bucket_users_value_error()
        """
        # Set up mock
        url = preprocess_url('/access/buckets/testString')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        bucket_id = 'testString'
        groups = ['testString']
        users = ['testString']

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "bucket_id": bucket_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_bucket_users(**req_copy)

    def test_delete_bucket_users_value_error_with_retries(self):
        # Enable retries and run test_delete_bucket_users_value_error.
        _service.enable_retries()
        self.test_delete_bucket_users_value_error()

        # Disable retries and run test_delete_bucket_users_value_error.
        _service.disable_retries()
        self.test_delete_bucket_users_value_error()


class TestUpdateBucketUsers:
    """
    Test Class for update_bucket_users
    """

    @responses.activate
    def test_update_bucket_users_all_params(self):
        """
        update_bucket_users()
        """
        # Set up mock
        url = preprocess_url('/access/buckets/testString')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a BucketDbConnGroupsMetadata model
        bucket_db_conn_groups_metadata_model = {}
        bucket_db_conn_groups_metadata_model['group_id'] = 'testString'
        bucket_db_conn_groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a BucketDbConnUsersMetadata model
        bucket_db_conn_users_metadata_model = {}
        bucket_db_conn_users_metadata_model['user_name'] = 'testString'
        bucket_db_conn_users_metadata_model['permission'] = 'can_administer'

        # Set up parameter values
        bucket_id = 'testString'
        groups = [bucket_db_conn_groups_metadata_model]
        users = [bucket_db_conn_users_metadata_model]
        lh_instance_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.update_bucket_users(
            bucket_id,
            groups=groups,
            users=users,
            lh_instance_id=lh_instance_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['groups'] == [bucket_db_conn_groups_metadata_model]
        assert req_body['users'] == [bucket_db_conn_users_metadata_model]

    def test_update_bucket_users_all_params_with_retries(self):
        # Enable retries and run test_update_bucket_users_all_params.
        _service.enable_retries()
        self.test_update_bucket_users_all_params()

        # Disable retries and run test_update_bucket_users_all_params.
        _service.disable_retries()
        self.test_update_bucket_users_all_params()

    @responses.activate
    def test_update_bucket_users_required_params(self):
        """
        test_update_bucket_users_required_params()
        """
        # Set up mock
        url = preprocess_url('/access/buckets/testString')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a BucketDbConnGroupsMetadata model
        bucket_db_conn_groups_metadata_model = {}
        bucket_db_conn_groups_metadata_model['group_id'] = 'testString'
        bucket_db_conn_groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a BucketDbConnUsersMetadata model
        bucket_db_conn_users_metadata_model = {}
        bucket_db_conn_users_metadata_model['user_name'] = 'testString'
        bucket_db_conn_users_metadata_model['permission'] = 'can_administer'

        # Set up parameter values
        bucket_id = 'testString'
        groups = [bucket_db_conn_groups_metadata_model]
        users = [bucket_db_conn_users_metadata_model]

        # Invoke method
        response = _service.update_bucket_users(
            bucket_id,
            groups=groups,
            users=users,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['groups'] == [bucket_db_conn_groups_metadata_model]
        assert req_body['users'] == [bucket_db_conn_users_metadata_model]

    def test_update_bucket_users_required_params_with_retries(self):
        # Enable retries and run test_update_bucket_users_required_params.
        _service.enable_retries()
        self.test_update_bucket_users_required_params()

        # Disable retries and run test_update_bucket_users_required_params.
        _service.disable_retries()
        self.test_update_bucket_users_required_params()

    @responses.activate
    def test_update_bucket_users_value_error(self):
        """
        test_update_bucket_users_value_error()
        """
        # Set up mock
        url = preprocess_url('/access/buckets/testString')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a BucketDbConnGroupsMetadata model
        bucket_db_conn_groups_metadata_model = {}
        bucket_db_conn_groups_metadata_model['group_id'] = 'testString'
        bucket_db_conn_groups_metadata_model['permission'] = 'can_administer'

        # Construct a dict representation of a BucketDbConnUsersMetadata model
        bucket_db_conn_users_metadata_model = {}
        bucket_db_conn_users_metadata_model['user_name'] = 'testString'
        bucket_db_conn_users_metadata_model['permission'] = 'can_administer'

        # Set up parameter values
        bucket_id = 'testString'
        groups = [bucket_db_conn_groups_metadata_model]
        users = [bucket_db_conn_users_metadata_model]

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "bucket_id": bucket_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.update_bucket_users(**req_copy)

    def test_update_bucket_users_value_error_with_retries(self):
        # Enable retries and run test_update_bucket_users_value_error.
        _service.enable_retries()
        self.test_update_bucket_users_value_error()

        # Disable retries and run test_update_bucket_users_value_error.
        _service.disable_retries()
        self.test_update_bucket_users_value_error()


# endregion
##############################################################################
# End of Service: AccessManagement
##############################################################################

##############################################################################
# Start of Service: Buckets
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ['TEST_SERVICE_AUTH_TYPE'] = 'noAuth'

        service = WatsonxDataV1.new_instance(
            service_name='TEST_SERVICE',
        )

        assert service is not None
        assert isinstance(service, WatsonxDataV1)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match='authenticator must be provided'):
            service = WatsonxDataV1.new_instance(
                service_name='TEST_SERVICE_NOT_FOUND',
            )


class TestGetBuckets:
    """
    Test Class for get_buckets
    """

    @responses.activate
    def test_get_buckets_all_params(self):
        """
        get_buckets()
        """
        # Set up mock
        url = preprocess_url('/buckets')
        mock_response = '{"buckets": [{"created_by": "<username>@<domain>.com", "created_on": "1686120645", "description": "COS bucket for customer data", "endpoint": "https://s3.<region>.cloud-object-storage.appdomain.cloud/", "managed_by": "IBM", "state": "active", "tags": ["tags"], "associated_catalogs": ["associated_catalogs"], "bucket_display_name": "sample-bucket-displayname", "bucket_id": "samplebucket123", "bucket_name": "sample-bucket", "bucket_type": "ibm_cos", "actions": ["actions"]}], "response": {"_messageCode_": "<message code>", "message": "Success"}}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.get_buckets(
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_buckets_all_params_with_retries(self):
        # Enable retries and run test_get_buckets_all_params.
        _service.enable_retries()
        self.test_get_buckets_all_params()

        # Disable retries and run test_get_buckets_all_params.
        _service.disable_retries()
        self.test_get_buckets_all_params()

    @responses.activate
    def test_get_buckets_required_params(self):
        """
        test_get_buckets_required_params()
        """
        # Set up mock
        url = preprocess_url('/buckets')
        mock_response = '{"buckets": [{"created_by": "<username>@<domain>.com", "created_on": "1686120645", "description": "COS bucket for customer data", "endpoint": "https://s3.<region>.cloud-object-storage.appdomain.cloud/", "managed_by": "IBM", "state": "active", "tags": ["tags"], "associated_catalogs": ["associated_catalogs"], "bucket_display_name": "sample-bucket-displayname", "bucket_id": "samplebucket123", "bucket_name": "sample-bucket", "bucket_type": "ibm_cos", "actions": ["actions"]}], "response": {"_messageCode_": "<message code>", "message": "Success"}}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Invoke method
        response = _service.get_buckets()

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_buckets_required_params_with_retries(self):
        # Enable retries and run test_get_buckets_required_params.
        _service.enable_retries()
        self.test_get_buckets_required_params()

        # Disable retries and run test_get_buckets_required_params.
        _service.disable_retries()
        self.test_get_buckets_required_params()


class TestGetBucketObjects:
    """
    Test Class for get_bucket_objects
    """

    @responses.activate
    def test_get_bucket_objects_all_params(self):
        """
        get_bucket_objects()
        """
        # Set up mock
        url = preprocess_url('/buckets/bucket/objects')
        mock_response = '{"objects": ["object_1"], "response": {"_messageCode_": "<message code>", "message": "Success"}}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        bucket_id = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.get_bucket_objects(
            bucket_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'bucket_id={}'.format(bucket_id) in query_string

    def test_get_bucket_objects_all_params_with_retries(self):
        # Enable retries and run test_get_bucket_objects_all_params.
        _service.enable_retries()
        self.test_get_bucket_objects_all_params()

        # Disable retries and run test_get_bucket_objects_all_params.
        _service.disable_retries()
        self.test_get_bucket_objects_all_params()

    @responses.activate
    def test_get_bucket_objects_required_params(self):
        """
        test_get_bucket_objects_required_params()
        """
        # Set up mock
        url = preprocess_url('/buckets/bucket/objects')
        mock_response = '{"objects": ["object_1"], "response": {"_messageCode_": "<message code>", "message": "Success"}}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        bucket_id = 'testString'

        # Invoke method
        response = _service.get_bucket_objects(
            bucket_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'bucket_id={}'.format(bucket_id) in query_string

    def test_get_bucket_objects_required_params_with_retries(self):
        # Enable retries and run test_get_bucket_objects_required_params.
        _service.enable_retries()
        self.test_get_bucket_objects_required_params()

        # Disable retries and run test_get_bucket_objects_required_params.
        _service.disable_retries()
        self.test_get_bucket_objects_required_params()

    @responses.activate
    def test_get_bucket_objects_value_error(self):
        """
        test_get_bucket_objects_value_error()
        """
        # Set up mock
        url = preprocess_url('/buckets/bucket/objects')
        mock_response = '{"objects": ["object_1"], "response": {"_messageCode_": "<message code>", "message": "Success"}}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        bucket_id = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "bucket_id": bucket_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_bucket_objects(**req_copy)

    def test_get_bucket_objects_value_error_with_retries(self):
        # Enable retries and run test_get_bucket_objects_value_error.
        _service.enable_retries()
        self.test_get_bucket_objects_value_error()

        # Disable retries and run test_get_bucket_objects_value_error.
        _service.disable_retries()
        self.test_get_bucket_objects_value_error()


class TestDeactivateBucket:
    """
    Test Class for deactivate_bucket
    """

    @responses.activate
    def test_deactivate_bucket_all_params(self):
        """
        deactivate_bucket()
        """
        # Set up mock
        url = preprocess_url('/buckets/bucket/deactivate')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=201,
        )

        # Set up parameter values
        bucket_id = 'samplebucket123'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.deactivate_bucket(
            bucket_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['bucket_id'] == 'samplebucket123'

    def test_deactivate_bucket_all_params_with_retries(self):
        # Enable retries and run test_deactivate_bucket_all_params.
        _service.enable_retries()
        self.test_deactivate_bucket_all_params()

        # Disable retries and run test_deactivate_bucket_all_params.
        _service.disable_retries()
        self.test_deactivate_bucket_all_params()

    @responses.activate
    def test_deactivate_bucket_required_params(self):
        """
        test_deactivate_bucket_required_params()
        """
        # Set up mock
        url = preprocess_url('/buckets/bucket/deactivate')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=201,
        )

        # Set up parameter values
        bucket_id = 'samplebucket123'

        # Invoke method
        response = _service.deactivate_bucket(
            bucket_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['bucket_id'] == 'samplebucket123'

    def test_deactivate_bucket_required_params_with_retries(self):
        # Enable retries and run test_deactivate_bucket_required_params.
        _service.enable_retries()
        self.test_deactivate_bucket_required_params()

        # Disable retries and run test_deactivate_bucket_required_params.
        _service.disable_retries()
        self.test_deactivate_bucket_required_params()

    @responses.activate
    def test_deactivate_bucket_value_error(self):
        """
        test_deactivate_bucket_value_error()
        """
        # Set up mock
        url = preprocess_url('/buckets/bucket/deactivate')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=201,
        )

        # Set up parameter values
        bucket_id = 'samplebucket123'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "bucket_id": bucket_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.deactivate_bucket(**req_copy)

    def test_deactivate_bucket_value_error_with_retries(self):
        # Enable retries and run test_deactivate_bucket_value_error.
        _service.enable_retries()
        self.test_deactivate_bucket_value_error()

        # Disable retries and run test_deactivate_bucket_value_error.
        _service.disable_retries()
        self.test_deactivate_bucket_value_error()


class TestRegisterBucket:
    """
    Test Class for register_bucket
    """

    @responses.activate
    def test_register_bucket_all_params(self):
        """
        register_bucket()
        """
        # Set up mock
        url = preprocess_url('/buckets/bucket')
        mock_response = '{"bucket": {"bucket_display_name": "bucket_display_name", "bucket_id": "bucket_id"}, "response": {"_messageCode_": "<message code>", "message": "Success"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a BucketDetails model
        bucket_details_model = {}
        bucket_details_model['access_key'] = '<access_key>'
        bucket_details_model['bucket_name'] = 'sample-bucket'
        bucket_details_model['endpoint'] = 'https://s3.<region>.cloud-object-storage.appdomain.cloud/'
        bucket_details_model['secret_key'] = '<secret_key>'

        # Set up parameter values
        bucket_details = bucket_details_model
        description = 'COS bucket for customer data'
        table_type = 'iceberg'
        bucket_type = 'ibm_cos'
        catalog_name = 'sampleCatalog'
        managed_by = 'ibm'
        bucket_display_name = 'sample-bucket-displayname'
        bucket_tags = ['read customer data', 'write customer data']
        catalog_tags = ['catalog_tag_1', 'catalog_tag_2']
        thrift_uri = 'thrift://samplehost-metastore:4354'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.register_bucket(
            bucket_details,
            description,
            table_type,
            bucket_type,
            catalog_name,
            managed_by,
            bucket_display_name=bucket_display_name,
            bucket_tags=bucket_tags,
            catalog_tags=catalog_tags,
            thrift_uri=thrift_uri,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['bucket_details'] == bucket_details_model
        assert req_body['description'] == 'COS bucket for customer data'
        assert req_body['table_type'] == 'iceberg'
        assert req_body['bucket_type'] == 'ibm_cos'
        assert req_body['catalog_name'] == 'sampleCatalog'
        assert req_body['managed_by'] == 'ibm'
        assert req_body['bucket_display_name'] == 'sample-bucket-displayname'
        assert req_body['bucket_tags'] == ['read customer data', 'write customer data']
        assert req_body['catalog_tags'] == ['catalog_tag_1', 'catalog_tag_2']
        assert req_body['thrift_uri'] == 'thrift://samplehost-metastore:4354'

    def test_register_bucket_all_params_with_retries(self):
        # Enable retries and run test_register_bucket_all_params.
        _service.enable_retries()
        self.test_register_bucket_all_params()

        # Disable retries and run test_register_bucket_all_params.
        _service.disable_retries()
        self.test_register_bucket_all_params()

    @responses.activate
    def test_register_bucket_required_params(self):
        """
        test_register_bucket_required_params()
        """
        # Set up mock
        url = preprocess_url('/buckets/bucket')
        mock_response = '{"bucket": {"bucket_display_name": "bucket_display_name", "bucket_id": "bucket_id"}, "response": {"_messageCode_": "<message code>", "message": "Success"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a BucketDetails model
        bucket_details_model = {}
        bucket_details_model['access_key'] = '<access_key>'
        bucket_details_model['bucket_name'] = 'sample-bucket'
        bucket_details_model['endpoint'] = 'https://s3.<region>.cloud-object-storage.appdomain.cloud/'
        bucket_details_model['secret_key'] = '<secret_key>'

        # Set up parameter values
        bucket_details = bucket_details_model
        description = 'COS bucket for customer data'
        table_type = 'iceberg'
        bucket_type = 'ibm_cos'
        catalog_name = 'sampleCatalog'
        managed_by = 'ibm'
        bucket_display_name = 'sample-bucket-displayname'
        bucket_tags = ['read customer data', 'write customer data']
        catalog_tags = ['catalog_tag_1', 'catalog_tag_2']
        thrift_uri = 'thrift://samplehost-metastore:4354'

        # Invoke method
        response = _service.register_bucket(
            bucket_details,
            description,
            table_type,
            bucket_type,
            catalog_name,
            managed_by,
            bucket_display_name=bucket_display_name,
            bucket_tags=bucket_tags,
            catalog_tags=catalog_tags,
            thrift_uri=thrift_uri,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['bucket_details'] == bucket_details_model
        assert req_body['description'] == 'COS bucket for customer data'
        assert req_body['table_type'] == 'iceberg'
        assert req_body['bucket_type'] == 'ibm_cos'
        assert req_body['catalog_name'] == 'sampleCatalog'
        assert req_body['managed_by'] == 'ibm'
        assert req_body['bucket_display_name'] == 'sample-bucket-displayname'
        assert req_body['bucket_tags'] == ['read customer data', 'write customer data']
        assert req_body['catalog_tags'] == ['catalog_tag_1', 'catalog_tag_2']
        assert req_body['thrift_uri'] == 'thrift://samplehost-metastore:4354'

    def test_register_bucket_required_params_with_retries(self):
        # Enable retries and run test_register_bucket_required_params.
        _service.enable_retries()
        self.test_register_bucket_required_params()

        # Disable retries and run test_register_bucket_required_params.
        _service.disable_retries()
        self.test_register_bucket_required_params()

    @responses.activate
    def test_register_bucket_value_error(self):
        """
        test_register_bucket_value_error()
        """
        # Set up mock
        url = preprocess_url('/buckets/bucket')
        mock_response = '{"bucket": {"bucket_display_name": "bucket_display_name", "bucket_id": "bucket_id"}, "response": {"_messageCode_": "<message code>", "message": "Success"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a BucketDetails model
        bucket_details_model = {}
        bucket_details_model['access_key'] = '<access_key>'
        bucket_details_model['bucket_name'] = 'sample-bucket'
        bucket_details_model['endpoint'] = 'https://s3.<region>.cloud-object-storage.appdomain.cloud/'
        bucket_details_model['secret_key'] = '<secret_key>'

        # Set up parameter values
        bucket_details = bucket_details_model
        description = 'COS bucket for customer data'
        table_type = 'iceberg'
        bucket_type = 'ibm_cos'
        catalog_name = 'sampleCatalog'
        managed_by = 'ibm'
        bucket_display_name = 'sample-bucket-displayname'
        bucket_tags = ['read customer data', 'write customer data']
        catalog_tags = ['catalog_tag_1', 'catalog_tag_2']
        thrift_uri = 'thrift://samplehost-metastore:4354'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "bucket_details": bucket_details,
            "description": description,
            "table_type": table_type,
            "bucket_type": bucket_type,
            "catalog_name": catalog_name,
            "managed_by": managed_by,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.register_bucket(**req_copy)

    def test_register_bucket_value_error_with_retries(self):
        # Enable retries and run test_register_bucket_value_error.
        _service.enable_retries()
        self.test_register_bucket_value_error()

        # Disable retries and run test_register_bucket_value_error.
        _service.disable_retries()
        self.test_register_bucket_value_error()


class TestUnregisterBucket:
    """
    Test Class for unregister_bucket
    """

    @responses.activate
    def test_unregister_bucket_all_params(self):
        """
        unregister_bucket()
        """
        # Set up mock
        url = preprocess_url('/buckets/bucket')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        bucket_id = 'bucket_id'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.unregister_bucket(
            bucket_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['bucket_id'] == 'bucket_id'

    def test_unregister_bucket_all_params_with_retries(self):
        # Enable retries and run test_unregister_bucket_all_params.
        _service.enable_retries()
        self.test_unregister_bucket_all_params()

        # Disable retries and run test_unregister_bucket_all_params.
        _service.disable_retries()
        self.test_unregister_bucket_all_params()

    @responses.activate
    def test_unregister_bucket_required_params(self):
        """
        test_unregister_bucket_required_params()
        """
        # Set up mock
        url = preprocess_url('/buckets/bucket')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        bucket_id = 'bucket_id'

        # Invoke method
        response = _service.unregister_bucket(
            bucket_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['bucket_id'] == 'bucket_id'

    def test_unregister_bucket_required_params_with_retries(self):
        # Enable retries and run test_unregister_bucket_required_params.
        _service.enable_retries()
        self.test_unregister_bucket_required_params()

        # Disable retries and run test_unregister_bucket_required_params.
        _service.disable_retries()
        self.test_unregister_bucket_required_params()

    @responses.activate
    def test_unregister_bucket_value_error(self):
        """
        test_unregister_bucket_value_error()
        """
        # Set up mock
        url = preprocess_url('/buckets/bucket')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        bucket_id = 'bucket_id'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "bucket_id": bucket_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.unregister_bucket(**req_copy)

    def test_unregister_bucket_value_error_with_retries(self):
        # Enable retries and run test_unregister_bucket_value_error.
        _service.enable_retries()
        self.test_unregister_bucket_value_error()

        # Disable retries and run test_unregister_bucket_value_error.
        _service.disable_retries()
        self.test_unregister_bucket_value_error()


class TestUpdateBucket:
    """
    Test Class for update_bucket
    """

    @responses.activate
    def test_update_bucket_all_params(self):
        """
        update_bucket()
        """
        # Set up mock
        url = preprocess_url('/buckets/bucket')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        bucket_id = 'samplebucket123'
        access_key = '<access_key>'
        bucket_display_name = 'sample-bucket-displayname'
        description = 'COS bucket for customer data'
        secret_key = '<secret_key>'
        tags = ['testbucket', 'userbucket']
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.update_bucket(
            bucket_id,
            access_key=access_key,
            bucket_display_name=bucket_display_name,
            description=description,
            secret_key=secret_key,
            tags=tags,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['bucket_id'] == 'samplebucket123'
        assert req_body['access_key'] == '<access_key>'
        assert req_body['bucket_display_name'] == 'sample-bucket-displayname'
        assert req_body['description'] == 'COS bucket for customer data'
        assert req_body['secret_key'] == '<secret_key>'
        assert req_body['tags'] == ['testbucket', 'userbucket']

    def test_update_bucket_all_params_with_retries(self):
        # Enable retries and run test_update_bucket_all_params.
        _service.enable_retries()
        self.test_update_bucket_all_params()

        # Disable retries and run test_update_bucket_all_params.
        _service.disable_retries()
        self.test_update_bucket_all_params()

    @responses.activate
    def test_update_bucket_required_params(self):
        """
        test_update_bucket_required_params()
        """
        # Set up mock
        url = preprocess_url('/buckets/bucket')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        bucket_id = 'samplebucket123'
        access_key = '<access_key>'
        bucket_display_name = 'sample-bucket-displayname'
        description = 'COS bucket for customer data'
        secret_key = '<secret_key>'
        tags = ['testbucket', 'userbucket']

        # Invoke method
        response = _service.update_bucket(
            bucket_id,
            access_key=access_key,
            bucket_display_name=bucket_display_name,
            description=description,
            secret_key=secret_key,
            tags=tags,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['bucket_id'] == 'samplebucket123'
        assert req_body['access_key'] == '<access_key>'
        assert req_body['bucket_display_name'] == 'sample-bucket-displayname'
        assert req_body['description'] == 'COS bucket for customer data'
        assert req_body['secret_key'] == '<secret_key>'
        assert req_body['tags'] == ['testbucket', 'userbucket']

    def test_update_bucket_required_params_with_retries(self):
        # Enable retries and run test_update_bucket_required_params.
        _service.enable_retries()
        self.test_update_bucket_required_params()

        # Disable retries and run test_update_bucket_required_params.
        _service.disable_retries()
        self.test_update_bucket_required_params()

    @responses.activate
    def test_update_bucket_value_error(self):
        """
        test_update_bucket_value_error()
        """
        # Set up mock
        url = preprocess_url('/buckets/bucket')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        bucket_id = 'samplebucket123'
        access_key = '<access_key>'
        bucket_display_name = 'sample-bucket-displayname'
        description = 'COS bucket for customer data'
        secret_key = '<secret_key>'
        tags = ['testbucket', 'userbucket']

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "bucket_id": bucket_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.update_bucket(**req_copy)

    def test_update_bucket_value_error_with_retries(self):
        # Enable retries and run test_update_bucket_value_error.
        _service.enable_retries()
        self.test_update_bucket_value_error()

        # Disable retries and run test_update_bucket_value_error.
        _service.disable_retries()
        self.test_update_bucket_value_error()


class TestActivateBucket:
    """
    Test Class for activate_bucket
    """

    @responses.activate
    def test_activate_bucket_all_params(self):
        """
        activate_bucket()
        """
        # Set up mock
        url = preprocess_url('/buckets/bucket/activate')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=201,
        )

        # Set up parameter values
        bucket_id = 'samplebucket123'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.activate_bucket(
            bucket_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['bucket_id'] == 'samplebucket123'

    def test_activate_bucket_all_params_with_retries(self):
        # Enable retries and run test_activate_bucket_all_params.
        _service.enable_retries()
        self.test_activate_bucket_all_params()

        # Disable retries and run test_activate_bucket_all_params.
        _service.disable_retries()
        self.test_activate_bucket_all_params()

    @responses.activate
    def test_activate_bucket_required_params(self):
        """
        test_activate_bucket_required_params()
        """
        # Set up mock
        url = preprocess_url('/buckets/bucket/activate')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=201,
        )

        # Set up parameter values
        bucket_id = 'samplebucket123'

        # Invoke method
        response = _service.activate_bucket(
            bucket_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['bucket_id'] == 'samplebucket123'

    def test_activate_bucket_required_params_with_retries(self):
        # Enable retries and run test_activate_bucket_required_params.
        _service.enable_retries()
        self.test_activate_bucket_required_params()

        # Disable retries and run test_activate_bucket_required_params.
        _service.disable_retries()
        self.test_activate_bucket_required_params()

    @responses.activate
    def test_activate_bucket_value_error(self):
        """
        test_activate_bucket_value_error()
        """
        # Set up mock
        url = preprocess_url('/buckets/bucket/activate')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=201,
        )

        # Set up parameter values
        bucket_id = 'samplebucket123'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "bucket_id": bucket_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.activate_bucket(**req_copy)

    def test_activate_bucket_value_error_with_retries(self):
        # Enable retries and run test_activate_bucket_value_error.
        _service.enable_retries()
        self.test_activate_bucket_value_error()

        # Disable retries and run test_activate_bucket_value_error.
        _service.disable_retries()
        self.test_activate_bucket_value_error()


# endregion
##############################################################################
# End of Service: Buckets
##############################################################################

##############################################################################
# Start of Service: Databases
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ['TEST_SERVICE_AUTH_TYPE'] = 'noAuth'

        service = WatsonxDataV1.new_instance(
            service_name='TEST_SERVICE',
        )

        assert service is not None
        assert isinstance(service, WatsonxDataV1)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match='authenticator must be provided'):
            service = WatsonxDataV1.new_instance(
                service_name='TEST_SERVICE_NOT_FOUND',
            )


class TestGetDatabases:
    """
    Test Class for get_databases
    """

    @responses.activate
    def test_get_databases_all_params(self):
        """
        get_databases()
        """
        # Set up mock
        url = preprocess_url('/databases')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='*/*',
            status=200,
        )

        # Set up parameter values
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.get_databases(
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_databases_all_params_with_retries(self):
        # Enable retries and run test_get_databases_all_params.
        _service.enable_retries()
        self.test_get_databases_all_params()

        # Disable retries and run test_get_databases_all_params.
        _service.disable_retries()
        self.test_get_databases_all_params()

    @responses.activate
    def test_get_databases_required_params(self):
        """
        test_get_databases_required_params()
        """
        # Set up mock
        url = preprocess_url('/databases')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='*/*',
            status=200,
        )

        # Invoke method
        response = _service.get_databases()

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_databases_required_params_with_retries(self):
        # Enable retries and run test_get_databases_required_params.
        _service.enable_retries()
        self.test_get_databases_required_params()

        # Disable retries and run test_get_databases_required_params.
        _service.disable_retries()
        self.test_get_databases_required_params()


class TestCreateDatabaseCatalog:
    """
    Test Class for create_database_catalog
    """

    @responses.activate
    def test_create_database_catalog_all_params(self):
        """
        create_database_catalog()
        """
        # Set up mock
        url = preprocess_url('/databases/database')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=201,
        )

        # Construct a dict representation of a RegisterDatabaseCatalogBodyDatabaseDetails model
        register_database_catalog_body_database_details_model = {}
        register_database_catalog_body_database_details_model['password'] = 'samplepassword'
        register_database_catalog_body_database_details_model['port'] = '4553'
        register_database_catalog_body_database_details_model['ssl'] = True
        register_database_catalog_body_database_details_model['tables'] = 'kafka_table_name'
        register_database_catalog_body_database_details_model['username'] = 'sampleuser'
        register_database_catalog_body_database_details_model['database_name'] = 'new_database'
        register_database_catalog_body_database_details_model['hostname'] = 'db2@<hostname>.com'

        # Set up parameter values
        database_display_name = 'new_database'
        database_type = 'db2'
        catalog_name = 'sampleCatalog'
        database_details = register_database_catalog_body_database_details_model
        description = 'db2 extenal database description'
        tags = ['tag_1', 'tag_2']
        created_by = '<username>@<domain>.com'
        created_on = 38
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.create_database_catalog(
            database_display_name,
            database_type,
            catalog_name,
            database_details=database_details,
            description=description,
            tags=tags,
            created_by=created_by,
            created_on=created_on,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['database_display_name'] == 'new_database'
        assert req_body['database_type'] == 'db2'
        assert req_body['catalog_name'] == 'sampleCatalog'
        assert req_body['database_details'] == register_database_catalog_body_database_details_model
        assert req_body['description'] == 'db2 extenal database description'
        assert req_body['tags'] == ['tag_1', 'tag_2']
        assert req_body['created_by'] == '<username>@<domain>.com'
        assert req_body['created_on'] == 38

    def test_create_database_catalog_all_params_with_retries(self):
        # Enable retries and run test_create_database_catalog_all_params.
        _service.enable_retries()
        self.test_create_database_catalog_all_params()

        # Disable retries and run test_create_database_catalog_all_params.
        _service.disable_retries()
        self.test_create_database_catalog_all_params()

    @responses.activate
    def test_create_database_catalog_required_params(self):
        """
        test_create_database_catalog_required_params()
        """
        # Set up mock
        url = preprocess_url('/databases/database')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=201,
        )

        # Construct a dict representation of a RegisterDatabaseCatalogBodyDatabaseDetails model
        register_database_catalog_body_database_details_model = {}
        register_database_catalog_body_database_details_model['password'] = 'samplepassword'
        register_database_catalog_body_database_details_model['port'] = '4553'
        register_database_catalog_body_database_details_model['ssl'] = True
        register_database_catalog_body_database_details_model['tables'] = 'kafka_table_name'
        register_database_catalog_body_database_details_model['username'] = 'sampleuser'
        register_database_catalog_body_database_details_model['database_name'] = 'new_database'
        register_database_catalog_body_database_details_model['hostname'] = 'db2@<hostname>.com'

        # Set up parameter values
        database_display_name = 'new_database'
        database_type = 'db2'
        catalog_name = 'sampleCatalog'
        database_details = register_database_catalog_body_database_details_model
        description = 'db2 extenal database description'
        tags = ['tag_1', 'tag_2']
        created_by = '<username>@<domain>.com'
        created_on = 38

        # Invoke method
        response = _service.create_database_catalog(
            database_display_name,
            database_type,
            catalog_name,
            database_details=database_details,
            description=description,
            tags=tags,
            created_by=created_by,
            created_on=created_on,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['database_display_name'] == 'new_database'
        assert req_body['database_type'] == 'db2'
        assert req_body['catalog_name'] == 'sampleCatalog'
        assert req_body['database_details'] == register_database_catalog_body_database_details_model
        assert req_body['description'] == 'db2 extenal database description'
        assert req_body['tags'] == ['tag_1', 'tag_2']
        assert req_body['created_by'] == '<username>@<domain>.com'
        assert req_body['created_on'] == 38

    def test_create_database_catalog_required_params_with_retries(self):
        # Enable retries and run test_create_database_catalog_required_params.
        _service.enable_retries()
        self.test_create_database_catalog_required_params()

        # Disable retries and run test_create_database_catalog_required_params.
        _service.disable_retries()
        self.test_create_database_catalog_required_params()

    @responses.activate
    def test_create_database_catalog_value_error(self):
        """
        test_create_database_catalog_value_error()
        """
        # Set up mock
        url = preprocess_url('/databases/database')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=201,
        )

        # Construct a dict representation of a RegisterDatabaseCatalogBodyDatabaseDetails model
        register_database_catalog_body_database_details_model = {}
        register_database_catalog_body_database_details_model['password'] = 'samplepassword'
        register_database_catalog_body_database_details_model['port'] = '4553'
        register_database_catalog_body_database_details_model['ssl'] = True
        register_database_catalog_body_database_details_model['tables'] = 'kafka_table_name'
        register_database_catalog_body_database_details_model['username'] = 'sampleuser'
        register_database_catalog_body_database_details_model['database_name'] = 'new_database'
        register_database_catalog_body_database_details_model['hostname'] = 'db2@<hostname>.com'

        # Set up parameter values
        database_display_name = 'new_database'
        database_type = 'db2'
        catalog_name = 'sampleCatalog'
        database_details = register_database_catalog_body_database_details_model
        description = 'db2 extenal database description'
        tags = ['tag_1', 'tag_2']
        created_by = '<username>@<domain>.com'
        created_on = 38

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "database_display_name": database_display_name,
            "database_type": database_type,
            "catalog_name": catalog_name,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_database_catalog(**req_copy)

    def test_create_database_catalog_value_error_with_retries(self):
        # Enable retries and run test_create_database_catalog_value_error.
        _service.enable_retries()
        self.test_create_database_catalog_value_error()

        # Disable retries and run test_create_database_catalog_value_error.
        _service.disable_retries()
        self.test_create_database_catalog_value_error()


class TestDeleteDatabaseCatalog:
    """
    Test Class for delete_database_catalog
    """

    @responses.activate
    def test_delete_database_catalog_all_params(self):
        """
        delete_database_catalog()
        """
        # Set up mock
        url = preprocess_url('/databases/database')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        database_id = 'new_db_id'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.delete_database_catalog(
            database_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['database_id'] == 'new_db_id'

    def test_delete_database_catalog_all_params_with_retries(self):
        # Enable retries and run test_delete_database_catalog_all_params.
        _service.enable_retries()
        self.test_delete_database_catalog_all_params()

        # Disable retries and run test_delete_database_catalog_all_params.
        _service.disable_retries()
        self.test_delete_database_catalog_all_params()

    @responses.activate
    def test_delete_database_catalog_required_params(self):
        """
        test_delete_database_catalog_required_params()
        """
        # Set up mock
        url = preprocess_url('/databases/database')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        database_id = 'new_db_id'

        # Invoke method
        response = _service.delete_database_catalog(
            database_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['database_id'] == 'new_db_id'

    def test_delete_database_catalog_required_params_with_retries(self):
        # Enable retries and run test_delete_database_catalog_required_params.
        _service.enable_retries()
        self.test_delete_database_catalog_required_params()

        # Disable retries and run test_delete_database_catalog_required_params.
        _service.disable_retries()
        self.test_delete_database_catalog_required_params()

    @responses.activate
    def test_delete_database_catalog_value_error(self):
        """
        test_delete_database_catalog_value_error()
        """
        # Set up mock
        url = preprocess_url('/databases/database')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        database_id = 'new_db_id'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "database_id": database_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_database_catalog(**req_copy)

    def test_delete_database_catalog_value_error_with_retries(self):
        # Enable retries and run test_delete_database_catalog_value_error.
        _service.enable_retries()
        self.test_delete_database_catalog_value_error()

        # Disable retries and run test_delete_database_catalog_value_error.
        _service.disable_retries()
        self.test_delete_database_catalog_value_error()


class TestUpdateDatabase:
    """
    Test Class for update_database
    """

    @responses.activate
    def test_update_database_all_params(self):
        """
        update_database()
        """
        # Set up mock
        url = preprocess_url('/databases/database')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='*/*',
            status=200,
        )

        # Construct a dict representation of a UpdateDatabaseBodyDatabaseDetails model
        update_database_body_database_details_model = {}
        update_database_body_database_details_model['password'] = 'samplepassword'
        update_database_body_database_details_model['username'] = 'sampleuser'

        # Set up parameter values
        database_id = 'new_db_id'
        database_details = update_database_body_database_details_model
        database_display_name = 'new_database'
        description = 'External database description'
        tags = ['testdatabase', 'userdatabase']
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.update_database(
            database_id,
            database_details=database_details,
            database_display_name=database_display_name,
            description=description,
            tags=tags,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['database_id'] == 'new_db_id'
        assert req_body['database_details'] == update_database_body_database_details_model
        assert req_body['database_display_name'] == 'new_database'
        assert req_body['description'] == 'External database description'
        assert req_body['tags'] == ['testdatabase', 'userdatabase']

    def test_update_database_all_params_with_retries(self):
        # Enable retries and run test_update_database_all_params.
        _service.enable_retries()
        self.test_update_database_all_params()

        # Disable retries and run test_update_database_all_params.
        _service.disable_retries()
        self.test_update_database_all_params()

    @responses.activate
    def test_update_database_required_params(self):
        """
        test_update_database_required_params()
        """
        # Set up mock
        url = preprocess_url('/databases/database')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='*/*',
            status=200,
        )

        # Construct a dict representation of a UpdateDatabaseBodyDatabaseDetails model
        update_database_body_database_details_model = {}
        update_database_body_database_details_model['password'] = 'samplepassword'
        update_database_body_database_details_model['username'] = 'sampleuser'

        # Set up parameter values
        database_id = 'new_db_id'
        database_details = update_database_body_database_details_model
        database_display_name = 'new_database'
        description = 'External database description'
        tags = ['testdatabase', 'userdatabase']

        # Invoke method
        response = _service.update_database(
            database_id,
            database_details=database_details,
            database_display_name=database_display_name,
            description=description,
            tags=tags,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['database_id'] == 'new_db_id'
        assert req_body['database_details'] == update_database_body_database_details_model
        assert req_body['database_display_name'] == 'new_database'
        assert req_body['description'] == 'External database description'
        assert req_body['tags'] == ['testdatabase', 'userdatabase']

    def test_update_database_required_params_with_retries(self):
        # Enable retries and run test_update_database_required_params.
        _service.enable_retries()
        self.test_update_database_required_params()

        # Disable retries and run test_update_database_required_params.
        _service.disable_retries()
        self.test_update_database_required_params()

    @responses.activate
    def test_update_database_value_error(self):
        """
        test_update_database_value_error()
        """
        # Set up mock
        url = preprocess_url('/databases/database')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='*/*',
            status=200,
        )

        # Construct a dict representation of a UpdateDatabaseBodyDatabaseDetails model
        update_database_body_database_details_model = {}
        update_database_body_database_details_model['password'] = 'samplepassword'
        update_database_body_database_details_model['username'] = 'sampleuser'

        # Set up parameter values
        database_id = 'new_db_id'
        database_details = update_database_body_database_details_model
        database_display_name = 'new_database'
        description = 'External database description'
        tags = ['testdatabase', 'userdatabase']

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "database_id": database_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.update_database(**req_copy)

    def test_update_database_value_error_with_retries(self):
        # Enable retries and run test_update_database_value_error.
        _service.enable_retries()
        self.test_update_database_value_error()

        # Disable retries and run test_update_database_value_error.
        _service.disable_retries()
        self.test_update_database_value_error()


# endregion
##############################################################################
# End of Service: Databases
##############################################################################

##############################################################################
# Start of Service: Engines
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ['TEST_SERVICE_AUTH_TYPE'] = 'noAuth'

        service = WatsonxDataV1.new_instance(
            service_name='TEST_SERVICE',
        )

        assert service is not None
        assert isinstance(service, WatsonxDataV1)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match='authenticator must be provided'):
            service = WatsonxDataV1.new_instance(
                service_name='TEST_SERVICE_NOT_FOUND',
            )


class TestPauseEngine:
    """
    Test Class for pause_engine
    """

    @responses.activate
    def test_pause_engine_all_params(self):
        """
        pause_engine()
        """
        # Set up mock
        url = preprocess_url('/engines/engine/pause')
        mock_response = '{"response": {"_messageCode_": "<message code>", "message": "Success"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Set up parameter values
        engine_id = 'testString'
        created_by = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.pause_engine(
            engine_id,
            created_by=created_by,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['engine_id'] == 'testString'
        assert req_body['created_by'] == 'testString'

    def test_pause_engine_all_params_with_retries(self):
        # Enable retries and run test_pause_engine_all_params.
        _service.enable_retries()
        self.test_pause_engine_all_params()

        # Disable retries and run test_pause_engine_all_params.
        _service.disable_retries()
        self.test_pause_engine_all_params()

    @responses.activate
    def test_pause_engine_required_params(self):
        """
        test_pause_engine_required_params()
        """
        # Set up mock
        url = preprocess_url('/engines/engine/pause')
        mock_response = '{"response": {"_messageCode_": "<message code>", "message": "Success"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Set up parameter values
        engine_id = 'testString'
        created_by = 'testString'

        # Invoke method
        response = _service.pause_engine(
            engine_id,
            created_by=created_by,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['engine_id'] == 'testString'
        assert req_body['created_by'] == 'testString'

    def test_pause_engine_required_params_with_retries(self):
        # Enable retries and run test_pause_engine_required_params.
        _service.enable_retries()
        self.test_pause_engine_required_params()

        # Disable retries and run test_pause_engine_required_params.
        _service.disable_retries()
        self.test_pause_engine_required_params()

    @responses.activate
    def test_pause_engine_value_error(self):
        """
        test_pause_engine_value_error()
        """
        # Set up mock
        url = preprocess_url('/engines/engine/pause')
        mock_response = '{"response": {"_messageCode_": "<message code>", "message": "Success"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Set up parameter values
        engine_id = 'testString'
        created_by = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "engine_id": engine_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.pause_engine(**req_copy)

    def test_pause_engine_value_error_with_retries(self):
        # Enable retries and run test_pause_engine_value_error.
        _service.enable_retries()
        self.test_pause_engine_value_error()

        # Disable retries and run test_pause_engine_value_error.
        _service.disable_retries()
        self.test_pause_engine_value_error()


class TestGetEngines:
    """
    Test Class for get_engines
    """

    @responses.activate
    def test_get_engines_all_params(self):
        """
        get_engines()
        """
        # Set up mock
        url = preprocess_url('/engines')
        mock_response = '{"engines": [{"group_id": "new_group_id", "region": "us-south", "size_config": "starter", "created_on": 10, "engine_display_name": "sampleEngine", "origin": "ibm", "port": 4, "type": "presto", "version": "1.2.0", "worker": {"node_type": "worker", "quantity": 8}, "actions": ["actions"], "associated_catalogs": ["associated_catalogs"], "status": "running", "tags": ["tags"], "coordinator": {"node_type": "worker", "quantity": 8}, "created_by": "<username>@<domain>.com", "host_name": "ibm-lh-presto-svc.com", "status_code": 11, "description": "presto engine for running sql queries", "engine_id": "sampleEngine123"}], "response": {"_messageCode_": "<message code>", "message": "Success"}}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.get_engines(
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_engines_all_params_with_retries(self):
        # Enable retries and run test_get_engines_all_params.
        _service.enable_retries()
        self.test_get_engines_all_params()

        # Disable retries and run test_get_engines_all_params.
        _service.disable_retries()
        self.test_get_engines_all_params()

    @responses.activate
    def test_get_engines_required_params(self):
        """
        test_get_engines_required_params()
        """
        # Set up mock
        url = preprocess_url('/engines')
        mock_response = '{"engines": [{"group_id": "new_group_id", "region": "us-south", "size_config": "starter", "created_on": 10, "engine_display_name": "sampleEngine", "origin": "ibm", "port": 4, "type": "presto", "version": "1.2.0", "worker": {"node_type": "worker", "quantity": 8}, "actions": ["actions"], "associated_catalogs": ["associated_catalogs"], "status": "running", "tags": ["tags"], "coordinator": {"node_type": "worker", "quantity": 8}, "created_by": "<username>@<domain>.com", "host_name": "ibm-lh-presto-svc.com", "status_code": 11, "description": "presto engine for running sql queries", "engine_id": "sampleEngine123"}], "response": {"_messageCode_": "<message code>", "message": "Success"}}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Invoke method
        response = _service.get_engines()

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_engines_required_params_with_retries(self):
        # Enable retries and run test_get_engines_required_params.
        _service.enable_retries()
        self.test_get_engines_required_params()

        # Disable retries and run test_get_engines_required_params.
        _service.disable_retries()
        self.test_get_engines_required_params()


class TestGetDeployments:
    """
    Test Class for get_deployments
    """

    @responses.activate
    def test_get_deployments_all_params(self):
        """
        get_deployments()
        """
        # Set up mock
        url = preprocess_url('/instance')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='*/*',
            status=200,
        )

        # Set up parameter values
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.get_deployments(
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_deployments_all_params_with_retries(self):
        # Enable retries and run test_get_deployments_all_params.
        _service.enable_retries()
        self.test_get_deployments_all_params()

        # Disable retries and run test_get_deployments_all_params.
        _service.disable_retries()
        self.test_get_deployments_all_params()

    @responses.activate
    def test_get_deployments_required_params(self):
        """
        test_get_deployments_required_params()
        """
        # Set up mock
        url = preprocess_url('/instance')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='*/*',
            status=200,
        )

        # Invoke method
        response = _service.get_deployments()

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_deployments_required_params_with_retries(self):
        # Enable retries and run test_get_deployments_required_params.
        _service.enable_retries()
        self.test_get_deployments_required_params()

        # Disable retries and run test_get_deployments_required_params.
        _service.disable_retries()
        self.test_get_deployments_required_params()


class TestUpdateEngine:
    """
    Test Class for update_engine
    """

    @responses.activate
    def test_update_engine_all_params(self):
        """
        update_engine()
        """
        # Set up mock
        url = preprocess_url('/engines/engine')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='*/*',
            status=200,
        )

        # Construct a dict representation of a NodeDescription model
        node_description_model = {}
        node_description_model['node_type'] = 'worker'
        node_description_model['quantity'] = 38

        # Set up parameter values
        engine_id = 'sampleEngine123'
        coordinator = node_description_model
        description = 'presto engine updated description'
        engine_display_name = 'sampleEngine'
        tags = ['tag1', 'tag2']
        worker = node_description_model
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.update_engine(
            engine_id,
            coordinator=coordinator,
            description=description,
            engine_display_name=engine_display_name,
            tags=tags,
            worker=worker,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['engine_id'] == 'sampleEngine123'
        assert req_body['coordinator'] == node_description_model
        assert req_body['description'] == 'presto engine updated description'
        assert req_body['engine_display_name'] == 'sampleEngine'
        assert req_body['tags'] == ['tag1', 'tag2']
        assert req_body['worker'] == node_description_model

    def test_update_engine_all_params_with_retries(self):
        # Enable retries and run test_update_engine_all_params.
        _service.enable_retries()
        self.test_update_engine_all_params()

        # Disable retries and run test_update_engine_all_params.
        _service.disable_retries()
        self.test_update_engine_all_params()

    @responses.activate
    def test_update_engine_required_params(self):
        """
        test_update_engine_required_params()
        """
        # Set up mock
        url = preprocess_url('/engines/engine')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='*/*',
            status=200,
        )

        # Construct a dict representation of a NodeDescription model
        node_description_model = {}
        node_description_model['node_type'] = 'worker'
        node_description_model['quantity'] = 38

        # Set up parameter values
        engine_id = 'sampleEngine123'
        coordinator = node_description_model
        description = 'presto engine updated description'
        engine_display_name = 'sampleEngine'
        tags = ['tag1', 'tag2']
        worker = node_description_model

        # Invoke method
        response = _service.update_engine(
            engine_id,
            coordinator=coordinator,
            description=description,
            engine_display_name=engine_display_name,
            tags=tags,
            worker=worker,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['engine_id'] == 'sampleEngine123'
        assert req_body['coordinator'] == node_description_model
        assert req_body['description'] == 'presto engine updated description'
        assert req_body['engine_display_name'] == 'sampleEngine'
        assert req_body['tags'] == ['tag1', 'tag2']
        assert req_body['worker'] == node_description_model

    def test_update_engine_required_params_with_retries(self):
        # Enable retries and run test_update_engine_required_params.
        _service.enable_retries()
        self.test_update_engine_required_params()

        # Disable retries and run test_update_engine_required_params.
        _service.disable_retries()
        self.test_update_engine_required_params()

    @responses.activate
    def test_update_engine_value_error(self):
        """
        test_update_engine_value_error()
        """
        # Set up mock
        url = preprocess_url('/engines/engine')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='*/*',
            status=200,
        )

        # Construct a dict representation of a NodeDescription model
        node_description_model = {}
        node_description_model['node_type'] = 'worker'
        node_description_model['quantity'] = 38

        # Set up parameter values
        engine_id = 'sampleEngine123'
        coordinator = node_description_model
        description = 'presto engine updated description'
        engine_display_name = 'sampleEngine'
        tags = ['tag1', 'tag2']
        worker = node_description_model

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "engine_id": engine_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.update_engine(**req_copy)

    def test_update_engine_value_error_with_retries(self):
        # Enable retries and run test_update_engine_value_error.
        _service.enable_retries()
        self.test_update_engine_value_error()

        # Disable retries and run test_update_engine_value_error.
        _service.disable_retries()
        self.test_update_engine_value_error()


class TestCreateEngine:
    """
    Test Class for create_engine
    """

    @responses.activate
    def test_create_engine_all_params(self):
        """
        create_engine()
        """
        # Set up mock
        url = preprocess_url('/engines/engine')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=201,
        )

        # Construct a dict representation of a NodeDescriptionBody model
        node_description_body_model = {}
        node_description_body_model['node_type'] = 'worker'
        node_description_body_model['quantity'] = 38

        # Construct a dict representation of a EngineDetailsBody model
        engine_details_body_model = {}
        engine_details_body_model['worker'] = node_description_body_model
        engine_details_body_model['coordinator'] = node_description_body_model
        engine_details_body_model['size_config'] = 'starter'

        # Set up parameter values
        version = '1.2.3'
        engine_details = engine_details_body_model
        origin = 'ibm'
        type = 'presto'
        description = 'presto engine description'
        engine_display_name = 'sampleEngine'
        first_time_use = True
        region = 'us-south'
        associated_catalogs = ['new_catalog_1', 'new_catalog_2']
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.create_engine(
            version,
            engine_details,
            origin,
            type,
            description=description,
            engine_display_name=engine_display_name,
            first_time_use=first_time_use,
            region=region,
            associated_catalogs=associated_catalogs,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['version'] == '1.2.3'
        assert req_body['engine_details'] == engine_details_body_model
        assert req_body['origin'] == 'ibm'
        assert req_body['type'] == 'presto'
        assert req_body['description'] == 'presto engine description'
        assert req_body['engine_display_name'] == 'sampleEngine'
        assert req_body['first_time_use'] == True
        assert req_body['region'] == 'us-south'
        assert req_body['associated_catalogs'] == ['new_catalog_1', 'new_catalog_2']

    def test_create_engine_all_params_with_retries(self):
        # Enable retries and run test_create_engine_all_params.
        _service.enable_retries()
        self.test_create_engine_all_params()

        # Disable retries and run test_create_engine_all_params.
        _service.disable_retries()
        self.test_create_engine_all_params()

    @responses.activate
    def test_create_engine_required_params(self):
        """
        test_create_engine_required_params()
        """
        # Set up mock
        url = preprocess_url('/engines/engine')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=201,
        )

        # Construct a dict representation of a NodeDescriptionBody model
        node_description_body_model = {}
        node_description_body_model['node_type'] = 'worker'
        node_description_body_model['quantity'] = 38

        # Construct a dict representation of a EngineDetailsBody model
        engine_details_body_model = {}
        engine_details_body_model['worker'] = node_description_body_model
        engine_details_body_model['coordinator'] = node_description_body_model
        engine_details_body_model['size_config'] = 'starter'

        # Set up parameter values
        version = '1.2.3'
        engine_details = engine_details_body_model
        origin = 'ibm'
        type = 'presto'
        description = 'presto engine description'
        engine_display_name = 'sampleEngine'
        first_time_use = True
        region = 'us-south'
        associated_catalogs = ['new_catalog_1', 'new_catalog_2']

        # Invoke method
        response = _service.create_engine(
            version,
            engine_details,
            origin,
            type,
            description=description,
            engine_display_name=engine_display_name,
            first_time_use=first_time_use,
            region=region,
            associated_catalogs=associated_catalogs,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['version'] == '1.2.3'
        assert req_body['engine_details'] == engine_details_body_model
        assert req_body['origin'] == 'ibm'
        assert req_body['type'] == 'presto'
        assert req_body['description'] == 'presto engine description'
        assert req_body['engine_display_name'] == 'sampleEngine'
        assert req_body['first_time_use'] == True
        assert req_body['region'] == 'us-south'
        assert req_body['associated_catalogs'] == ['new_catalog_1', 'new_catalog_2']

    def test_create_engine_required_params_with_retries(self):
        # Enable retries and run test_create_engine_required_params.
        _service.enable_retries()
        self.test_create_engine_required_params()

        # Disable retries and run test_create_engine_required_params.
        _service.disable_retries()
        self.test_create_engine_required_params()

    @responses.activate
    def test_create_engine_value_error(self):
        """
        test_create_engine_value_error()
        """
        # Set up mock
        url = preprocess_url('/engines/engine')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=201,
        )

        # Construct a dict representation of a NodeDescriptionBody model
        node_description_body_model = {}
        node_description_body_model['node_type'] = 'worker'
        node_description_body_model['quantity'] = 38

        # Construct a dict representation of a EngineDetailsBody model
        engine_details_body_model = {}
        engine_details_body_model['worker'] = node_description_body_model
        engine_details_body_model['coordinator'] = node_description_body_model
        engine_details_body_model['size_config'] = 'starter'

        # Set up parameter values
        version = '1.2.3'
        engine_details = engine_details_body_model
        origin = 'ibm'
        type = 'presto'
        description = 'presto engine description'
        engine_display_name = 'sampleEngine'
        first_time_use = True
        region = 'us-south'
        associated_catalogs = ['new_catalog_1', 'new_catalog_2']

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "version": version,
            "engine_details": engine_details,
            "origin": origin,
            "type": type,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_engine(**req_copy)

    def test_create_engine_value_error_with_retries(self):
        # Enable retries and run test_create_engine_value_error.
        _service.enable_retries()
        self.test_create_engine_value_error()

        # Disable retries and run test_create_engine_value_error.
        _service.disable_retries()
        self.test_create_engine_value_error()


class TestDeleteEngine:
    """
    Test Class for delete_engine
    """

    @responses.activate
    def test_delete_engine_all_params(self):
        """
        delete_engine()
        """
        # Set up mock
        url = preprocess_url('/engines/engine')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        engine_id = 'eng_if'
        created_by = '<username>@<domain>.com'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.delete_engine(
            engine_id,
            created_by=created_by,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['engine_id'] == 'eng_if'
        assert req_body['created_by'] == '<username>@<domain>.com'

    def test_delete_engine_all_params_with_retries(self):
        # Enable retries and run test_delete_engine_all_params.
        _service.enable_retries()
        self.test_delete_engine_all_params()

        # Disable retries and run test_delete_engine_all_params.
        _service.disable_retries()
        self.test_delete_engine_all_params()

    @responses.activate
    def test_delete_engine_required_params(self):
        """
        test_delete_engine_required_params()
        """
        # Set up mock
        url = preprocess_url('/engines/engine')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        engine_id = 'eng_if'
        created_by = '<username>@<domain>.com'

        # Invoke method
        response = _service.delete_engine(
            engine_id,
            created_by=created_by,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['engine_id'] == 'eng_if'
        assert req_body['created_by'] == '<username>@<domain>.com'

    def test_delete_engine_required_params_with_retries(self):
        # Enable retries and run test_delete_engine_required_params.
        _service.enable_retries()
        self.test_delete_engine_required_params()

        # Disable retries and run test_delete_engine_required_params.
        _service.disable_retries()
        self.test_delete_engine_required_params()

    @responses.activate
    def test_delete_engine_value_error(self):
        """
        test_delete_engine_value_error()
        """
        # Set up mock
        url = preprocess_url('/engines/engine')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        engine_id = 'eng_if'
        created_by = '<username>@<domain>.com'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "engine_id": engine_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_engine(**req_copy)

    def test_delete_engine_value_error_with_retries(self):
        # Enable retries and run test_delete_engine_value_error.
        _service.enable_retries()
        self.test_delete_engine_value_error()

        # Disable retries and run test_delete_engine_value_error.
        _service.disable_retries()
        self.test_delete_engine_value_error()


class TestResumeEngine:
    """
    Test Class for resume_engine
    """

    @responses.activate
    def test_resume_engine_all_params(self):
        """
        resume_engine()
        """
        # Set up mock
        url = preprocess_url('/engines/engine/resume')
        mock_response = '{"response": {"_messageCode_": "<message code>", "message": "Success"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Set up parameter values
        engine_id = 'eng_id'
        created_by = '<username>@<domain>.com'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.resume_engine(
            engine_id,
            created_by=created_by,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['engine_id'] == 'eng_id'
        assert req_body['created_by'] == '<username>@<domain>.com'

    def test_resume_engine_all_params_with_retries(self):
        # Enable retries and run test_resume_engine_all_params.
        _service.enable_retries()
        self.test_resume_engine_all_params()

        # Disable retries and run test_resume_engine_all_params.
        _service.disable_retries()
        self.test_resume_engine_all_params()

    @responses.activate
    def test_resume_engine_required_params(self):
        """
        test_resume_engine_required_params()
        """
        # Set up mock
        url = preprocess_url('/engines/engine/resume')
        mock_response = '{"response": {"_messageCode_": "<message code>", "message": "Success"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Set up parameter values
        engine_id = 'eng_id'
        created_by = '<username>@<domain>.com'

        # Invoke method
        response = _service.resume_engine(
            engine_id,
            created_by=created_by,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['engine_id'] == 'eng_id'
        assert req_body['created_by'] == '<username>@<domain>.com'

    def test_resume_engine_required_params_with_retries(self):
        # Enable retries and run test_resume_engine_required_params.
        _service.enable_retries()
        self.test_resume_engine_required_params()

        # Disable retries and run test_resume_engine_required_params.
        _service.disable_retries()
        self.test_resume_engine_required_params()

    @responses.activate
    def test_resume_engine_value_error(self):
        """
        test_resume_engine_value_error()
        """
        # Set up mock
        url = preprocess_url('/engines/engine/resume')
        mock_response = '{"response": {"_messageCode_": "<message code>", "message": "Success"}}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Set up parameter values
        engine_id = 'eng_id'
        created_by = '<username>@<domain>.com'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "engine_id": engine_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.resume_engine(**req_copy)

    def test_resume_engine_value_error_with_retries(self):
        # Enable retries and run test_resume_engine_value_error.
        _service.enable_retries()
        self.test_resume_engine_value_error()

        # Disable retries and run test_resume_engine_value_error.
        _service.disable_retries()
        self.test_resume_engine_value_error()


# endregion
##############################################################################
# End of Service: Engines
##############################################################################

##############################################################################
# Start of Service: Explain
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ['TEST_SERVICE_AUTH_TYPE'] = 'noAuth'

        service = WatsonxDataV1.new_instance(
            service_name='TEST_SERVICE',
        )

        assert service is not None
        assert isinstance(service, WatsonxDataV1)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match='authenticator must be provided'):
            service = WatsonxDataV1.new_instance(
                service_name='TEST_SERVICE_NOT_FOUND',
            )


class TestExplainAnalyzeStatement:
    """
    Test Class for explain_analyze_statement
    """

    @responses.activate
    def test_explain_analyze_statement_all_params(self):
        """
        explain_analyze_statement()
        """
        # Set up mock
        url = preprocess_url('/explainanalyze')
        mock_response = '{"response": {"_messageCode_": "<message code>", "message": "Success"}, "result": "result"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Set up parameter values
        catalog_name = 'sampleCatalog'
        engine_id = 'sampleEngine1'
        schema_name = 'new_schema'
        statement = 'show schemas in catalog'
        verbose = True
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.explain_analyze_statement(
            catalog_name,
            engine_id,
            schema_name,
            statement,
            verbose=verbose,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['catalog_name'] == 'sampleCatalog'
        assert req_body['engine_id'] == 'sampleEngine1'
        assert req_body['schema_name'] == 'new_schema'
        assert req_body['statement'] == 'show schemas in catalog'
        assert req_body['verbose'] == True

    def test_explain_analyze_statement_all_params_with_retries(self):
        # Enable retries and run test_explain_analyze_statement_all_params.
        _service.enable_retries()
        self.test_explain_analyze_statement_all_params()

        # Disable retries and run test_explain_analyze_statement_all_params.
        _service.disable_retries()
        self.test_explain_analyze_statement_all_params()

    @responses.activate
    def test_explain_analyze_statement_required_params(self):
        """
        test_explain_analyze_statement_required_params()
        """
        # Set up mock
        url = preprocess_url('/explainanalyze')
        mock_response = '{"response": {"_messageCode_": "<message code>", "message": "Success"}, "result": "result"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Set up parameter values
        catalog_name = 'sampleCatalog'
        engine_id = 'sampleEngine1'
        schema_name = 'new_schema'
        statement = 'show schemas in catalog'
        verbose = True

        # Invoke method
        response = _service.explain_analyze_statement(
            catalog_name,
            engine_id,
            schema_name,
            statement,
            verbose=verbose,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['catalog_name'] == 'sampleCatalog'
        assert req_body['engine_id'] == 'sampleEngine1'
        assert req_body['schema_name'] == 'new_schema'
        assert req_body['statement'] == 'show schemas in catalog'
        assert req_body['verbose'] == True

    def test_explain_analyze_statement_required_params_with_retries(self):
        # Enable retries and run test_explain_analyze_statement_required_params.
        _service.enable_retries()
        self.test_explain_analyze_statement_required_params()

        # Disable retries and run test_explain_analyze_statement_required_params.
        _service.disable_retries()
        self.test_explain_analyze_statement_required_params()

    @responses.activate
    def test_explain_analyze_statement_value_error(self):
        """
        test_explain_analyze_statement_value_error()
        """
        # Set up mock
        url = preprocess_url('/explainanalyze')
        mock_response = '{"response": {"_messageCode_": "<message code>", "message": "Success"}, "result": "result"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Set up parameter values
        catalog_name = 'sampleCatalog'
        engine_id = 'sampleEngine1'
        schema_name = 'new_schema'
        statement = 'show schemas in catalog'
        verbose = True

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "catalog_name": catalog_name,
            "engine_id": engine_id,
            "schema_name": schema_name,
            "statement": statement,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.explain_analyze_statement(**req_copy)

    def test_explain_analyze_statement_value_error_with_retries(self):
        # Enable retries and run test_explain_analyze_statement_value_error.
        _service.enable_retries()
        self.test_explain_analyze_statement_value_error()

        # Disable retries and run test_explain_analyze_statement_value_error.
        _service.disable_retries()
        self.test_explain_analyze_statement_value_error()


class TestExplainStatement:
    """
    Test Class for explain_statement
    """

    @responses.activate
    def test_explain_statement_all_params(self):
        """
        explain_statement()
        """
        # Set up mock
        url = preprocess_url('/explain')
        mock_response = '{"response": {"_messageCode_": "<message code>", "message": "Success"}, "result": "result"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Set up parameter values
        engine_id = 'eng_id'
        statement = 'show schemas'
        catalog_name = 'sampleCatalog'
        format = 'json'
        schema_name = 'new_schema'
        type = 'io'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.explain_statement(
            engine_id,
            statement,
            catalog_name=catalog_name,
            format=format,
            schema_name=schema_name,
            type=type,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['engine_id'] == 'eng_id'
        assert req_body['statement'] == 'show schemas'
        assert req_body['catalog_name'] == 'sampleCatalog'
        assert req_body['format'] == 'json'
        assert req_body['schema_name'] == 'new_schema'
        assert req_body['type'] == 'io'

    def test_explain_statement_all_params_with_retries(self):
        # Enable retries and run test_explain_statement_all_params.
        _service.enable_retries()
        self.test_explain_statement_all_params()

        # Disable retries and run test_explain_statement_all_params.
        _service.disable_retries()
        self.test_explain_statement_all_params()

    @responses.activate
    def test_explain_statement_required_params(self):
        """
        test_explain_statement_required_params()
        """
        # Set up mock
        url = preprocess_url('/explain')
        mock_response = '{"response": {"_messageCode_": "<message code>", "message": "Success"}, "result": "result"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Set up parameter values
        engine_id = 'eng_id'
        statement = 'show schemas'
        catalog_name = 'sampleCatalog'
        format = 'json'
        schema_name = 'new_schema'
        type = 'io'

        # Invoke method
        response = _service.explain_statement(
            engine_id,
            statement,
            catalog_name=catalog_name,
            format=format,
            schema_name=schema_name,
            type=type,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['engine_id'] == 'eng_id'
        assert req_body['statement'] == 'show schemas'
        assert req_body['catalog_name'] == 'sampleCatalog'
        assert req_body['format'] == 'json'
        assert req_body['schema_name'] == 'new_schema'
        assert req_body['type'] == 'io'

    def test_explain_statement_required_params_with_retries(self):
        # Enable retries and run test_explain_statement_required_params.
        _service.enable_retries()
        self.test_explain_statement_required_params()

        # Disable retries and run test_explain_statement_required_params.
        _service.disable_retries()
        self.test_explain_statement_required_params()

    @responses.activate
    def test_explain_statement_value_error(self):
        """
        test_explain_statement_value_error()
        """
        # Set up mock
        url = preprocess_url('/explain')
        mock_response = '{"response": {"_messageCode_": "<message code>", "message": "Success"}, "result": "result"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Set up parameter values
        engine_id = 'eng_id'
        statement = 'show schemas'
        catalog_name = 'sampleCatalog'
        format = 'json'
        schema_name = 'new_schema'
        type = 'io'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "engine_id": engine_id,
            "statement": statement,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.explain_statement(**req_copy)

    def test_explain_statement_value_error_with_retries(self):
        # Enable retries and run test_explain_statement_value_error.
        _service.enable_retries()
        self.test_explain_statement_value_error()

        # Disable retries and run test_explain_statement_value_error.
        _service.disable_retries()
        self.test_explain_statement_value_error()


# endregion
##############################################################################
# End of Service: Explain
##############################################################################

##############################################################################
# Start of Service: Lhconsole
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ['TEST_SERVICE_AUTH_TYPE'] = 'noAuth'

        service = WatsonxDataV1.new_instance(
            service_name='TEST_SERVICE',
        )

        assert service is not None
        assert isinstance(service, WatsonxDataV1)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match='authenticator must be provided'):
            service = WatsonxDataV1.new_instance(
                service_name='TEST_SERVICE_NOT_FOUND',
            )


class TestTestLhConsole:
    """
    Test Class for test_lh_console
    """

    @responses.activate
    def test_test_lh_console_all_params(self):
        """
        test_lh_console()
        """
        # Set up mock
        url = preprocess_url('/ready')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Invoke method
        response = _service.test_lh_console()

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_test_lh_console_all_params_with_retries(self):
        # Enable retries and run test_test_lh_console_all_params.
        _service.enable_retries()
        self.test_test_lh_console_all_params()

        # Disable retries and run test_test_lh_console_all_params.
        _service.disable_retries()
        self.test_test_lh_console_all_params()


# endregion
##############################################################################
# End of Service: Lhconsole
##############################################################################

##############################################################################
# Start of Service: Metastores
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ['TEST_SERVICE_AUTH_TYPE'] = 'noAuth'

        service = WatsonxDataV1.new_instance(
            service_name='TEST_SERVICE',
        )

        assert service is not None
        assert isinstance(service, WatsonxDataV1)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match='authenticator must be provided'):
            service = WatsonxDataV1.new_instance(
                service_name='TEST_SERVICE_NOT_FOUND',
            )


class TestGetMetastores:
    """
    Test Class for get_metastores
    """

    @responses.activate
    def test_get_metastores_all_params(self):
        """
        get_metastores()
        """
        # Set up mock
        url = preprocess_url('/catalogs')
        mock_response = '{"catalogs": [{"catalog_name": "sampleCatalog", "hostname": "s3a://samplehost.com", "managed_by": "ibm", "status": "running", "tags": ["tags"], "actions": ["actions"], "associated_buckets": ["associated_buckets"], "created_by": "<username>@<domain>.com", "thrift_uri": "thrift://samplehost-metastore:4354", "catalog_type": "iceberg", "description": "Iceberg catalog description", "associated_databases": ["associated_databases"], "associated_engines": ["associated_engines"], "created_on": "1602839833", "port": "3232"}], "response": {"_messageCode_": "<message code>", "message": "Success"}}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.get_metastores(
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_metastores_all_params_with_retries(self):
        # Enable retries and run test_get_metastores_all_params.
        _service.enable_retries()
        self.test_get_metastores_all_params()

        # Disable retries and run test_get_metastores_all_params.
        _service.disable_retries()
        self.test_get_metastores_all_params()

    @responses.activate
    def test_get_metastores_required_params(self):
        """
        test_get_metastores_required_params()
        """
        # Set up mock
        url = preprocess_url('/catalogs')
        mock_response = '{"catalogs": [{"catalog_name": "sampleCatalog", "hostname": "s3a://samplehost.com", "managed_by": "ibm", "status": "running", "tags": ["tags"], "actions": ["actions"], "associated_buckets": ["associated_buckets"], "created_by": "<username>@<domain>.com", "thrift_uri": "thrift://samplehost-metastore:4354", "catalog_type": "iceberg", "description": "Iceberg catalog description", "associated_databases": ["associated_databases"], "associated_engines": ["associated_engines"], "created_on": "1602839833", "port": "3232"}], "response": {"_messageCode_": "<message code>", "message": "Success"}}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Invoke method
        response = _service.get_metastores()

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_metastores_required_params_with_retries(self):
        # Enable retries and run test_get_metastores_required_params.
        _service.enable_retries()
        self.test_get_metastores_required_params()

        # Disable retries and run test_get_metastores_required_params.
        _service.disable_retries()
        self.test_get_metastores_required_params()


class TestGetHms:
    """
    Test Class for get_hms
    """

    @responses.activate
    def test_get_hms_all_params(self):
        """
        get_hms()
        """
        # Set up mock
        url = preprocess_url('/metastores')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='*/*',
            status=200,
        )

        # Set up parameter values
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.get_hms(
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_hms_all_params_with_retries(self):
        # Enable retries and run test_get_hms_all_params.
        _service.enable_retries()
        self.test_get_hms_all_params()

        # Disable retries and run test_get_hms_all_params.
        _service.disable_retries()
        self.test_get_hms_all_params()

    @responses.activate
    def test_get_hms_required_params(self):
        """
        test_get_hms_required_params()
        """
        # Set up mock
        url = preprocess_url('/metastores')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='*/*',
            status=200,
        )

        # Invoke method
        response = _service.get_hms()

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_hms_required_params_with_retries(self):
        # Enable retries and run test_get_hms_required_params.
        _service.enable_retries()
        self.test_get_hms_required_params()

        # Disable retries and run test_get_hms_required_params.
        _service.disable_retries()
        self.test_get_hms_required_params()


class TestAddMetastoreToEngine:
    """
    Test Class for add_metastore_to_engine
    """

    @responses.activate
    def test_add_metastore_to_engine_all_params(self):
        """
        add_metastore_to_engine()
        """
        # Set up mock
        url = preprocess_url('/catalogs/add_catalog_to_engine')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=201,
        )

        # Set up parameter values
        catalog_name = 'sampleCatalog'
        engine_id = 'sampleEngine123'
        created_by = '<username>@<domain>.com'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.add_metastore_to_engine(
            catalog_name,
            engine_id,
            created_by=created_by,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['catalog_name'] == 'sampleCatalog'
        assert req_body['engine_id'] == 'sampleEngine123'
        assert req_body['created_by'] == '<username>@<domain>.com'

    def test_add_metastore_to_engine_all_params_with_retries(self):
        # Enable retries and run test_add_metastore_to_engine_all_params.
        _service.enable_retries()
        self.test_add_metastore_to_engine_all_params()

        # Disable retries and run test_add_metastore_to_engine_all_params.
        _service.disable_retries()
        self.test_add_metastore_to_engine_all_params()

    @responses.activate
    def test_add_metastore_to_engine_required_params(self):
        """
        test_add_metastore_to_engine_required_params()
        """
        # Set up mock
        url = preprocess_url('/catalogs/add_catalog_to_engine')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=201,
        )

        # Set up parameter values
        catalog_name = 'sampleCatalog'
        engine_id = 'sampleEngine123'
        created_by = '<username>@<domain>.com'

        # Invoke method
        response = _service.add_metastore_to_engine(
            catalog_name,
            engine_id,
            created_by=created_by,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['catalog_name'] == 'sampleCatalog'
        assert req_body['engine_id'] == 'sampleEngine123'
        assert req_body['created_by'] == '<username>@<domain>.com'

    def test_add_metastore_to_engine_required_params_with_retries(self):
        # Enable retries and run test_add_metastore_to_engine_required_params.
        _service.enable_retries()
        self.test_add_metastore_to_engine_required_params()

        # Disable retries and run test_add_metastore_to_engine_required_params.
        _service.disable_retries()
        self.test_add_metastore_to_engine_required_params()

    @responses.activate
    def test_add_metastore_to_engine_value_error(self):
        """
        test_add_metastore_to_engine_value_error()
        """
        # Set up mock
        url = preprocess_url('/catalogs/add_catalog_to_engine')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=201,
        )

        # Set up parameter values
        catalog_name = 'sampleCatalog'
        engine_id = 'sampleEngine123'
        created_by = '<username>@<domain>.com'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "catalog_name": catalog_name,
            "engine_id": engine_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.add_metastore_to_engine(**req_copy)

    def test_add_metastore_to_engine_value_error_with_retries(self):
        # Enable retries and run test_add_metastore_to_engine_value_error.
        _service.enable_retries()
        self.test_add_metastore_to_engine_value_error()

        # Disable retries and run test_add_metastore_to_engine_value_error.
        _service.disable_retries()
        self.test_add_metastore_to_engine_value_error()


class TestRemoveCatalogFromEngine:
    """
    Test Class for remove_catalog_from_engine
    """

    @responses.activate
    def test_remove_catalog_from_engine_all_params(self):
        """
        remove_catalog_from_engine()
        """
        # Set up mock
        url = preprocess_url('/catalogs/remove_catalog_from_engine')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=201,
        )

        # Set up parameter values
        catalog_name = 'testString'
        engine_id = 'testString'
        created_by = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.remove_catalog_from_engine(
            catalog_name,
            engine_id,
            created_by=created_by,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['catalog_name'] == 'testString'
        assert req_body['engine_id'] == 'testString'
        assert req_body['created_by'] == 'testString'

    def test_remove_catalog_from_engine_all_params_with_retries(self):
        # Enable retries and run test_remove_catalog_from_engine_all_params.
        _service.enable_retries()
        self.test_remove_catalog_from_engine_all_params()

        # Disable retries and run test_remove_catalog_from_engine_all_params.
        _service.disable_retries()
        self.test_remove_catalog_from_engine_all_params()

    @responses.activate
    def test_remove_catalog_from_engine_required_params(self):
        """
        test_remove_catalog_from_engine_required_params()
        """
        # Set up mock
        url = preprocess_url('/catalogs/remove_catalog_from_engine')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=201,
        )

        # Set up parameter values
        catalog_name = 'testString'
        engine_id = 'testString'
        created_by = 'testString'

        # Invoke method
        response = _service.remove_catalog_from_engine(
            catalog_name,
            engine_id,
            created_by=created_by,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['catalog_name'] == 'testString'
        assert req_body['engine_id'] == 'testString'
        assert req_body['created_by'] == 'testString'

    def test_remove_catalog_from_engine_required_params_with_retries(self):
        # Enable retries and run test_remove_catalog_from_engine_required_params.
        _service.enable_retries()
        self.test_remove_catalog_from_engine_required_params()

        # Disable retries and run test_remove_catalog_from_engine_required_params.
        _service.disable_retries()
        self.test_remove_catalog_from_engine_required_params()

    @responses.activate
    def test_remove_catalog_from_engine_value_error(self):
        """
        test_remove_catalog_from_engine_value_error()
        """
        # Set up mock
        url = preprocess_url('/catalogs/remove_catalog_from_engine')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=201,
        )

        # Set up parameter values
        catalog_name = 'testString'
        engine_id = 'testString'
        created_by = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "catalog_name": catalog_name,
            "engine_id": engine_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.remove_catalog_from_engine(**req_copy)

    def test_remove_catalog_from_engine_value_error_with_retries(self):
        # Enable retries and run test_remove_catalog_from_engine_value_error.
        _service.enable_retries()
        self.test_remove_catalog_from_engine_value_error()

        # Disable retries and run test_remove_catalog_from_engine_value_error.
        _service.disable_retries()
        self.test_remove_catalog_from_engine_value_error()


# endregion
##############################################################################
# End of Service: Metastores
##############################################################################

##############################################################################
# Start of Service: Queries
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ['TEST_SERVICE_AUTH_TYPE'] = 'noAuth'

        service = WatsonxDataV1.new_instance(
            service_name='TEST_SERVICE',
        )

        assert service is not None
        assert isinstance(service, WatsonxDataV1)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match='authenticator must be provided'):
            service = WatsonxDataV1.new_instance(
                service_name='TEST_SERVICE_NOT_FOUND',
            )


class TestSaveQuery:
    """
    Test Class for save_query
    """

    @responses.activate
    def test_save_query_all_params(self):
        """
        save_query()
        """
        # Set up mock
        url = preprocess_url('/queries/testString')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Set up parameter values
        query_name = 'testString'
        created_by = '<username>@<domain>.com'
        description = 'query to get expense data'
        query_string = 'select expenses from expenditure'
        created_on = '1608437933'
        engine_id = 'sampleEngine123'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.save_query(
            query_name,
            created_by,
            description,
            query_string,
            created_on=created_on,
            engine_id=engine_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['created_by'] == '<username>@<domain>.com'
        assert req_body['description'] == 'query to get expense data'
        assert req_body['query_string'] == 'select expenses from expenditure'
        assert req_body['created_on'] == '1608437933'
        assert req_body['engine_id'] == 'sampleEngine123'

    def test_save_query_all_params_with_retries(self):
        # Enable retries and run test_save_query_all_params.
        _service.enable_retries()
        self.test_save_query_all_params()

        # Disable retries and run test_save_query_all_params.
        _service.disable_retries()
        self.test_save_query_all_params()

    @responses.activate
    def test_save_query_required_params(self):
        """
        test_save_query_required_params()
        """
        # Set up mock
        url = preprocess_url('/queries/testString')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Set up parameter values
        query_name = 'testString'
        created_by = '<username>@<domain>.com'
        description = 'query to get expense data'
        query_string = 'select expenses from expenditure'
        created_on = '1608437933'
        engine_id = 'sampleEngine123'

        # Invoke method
        response = _service.save_query(
            query_name,
            created_by,
            description,
            query_string,
            created_on=created_on,
            engine_id=engine_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['created_by'] == '<username>@<domain>.com'
        assert req_body['description'] == 'query to get expense data'
        assert req_body['query_string'] == 'select expenses from expenditure'
        assert req_body['created_on'] == '1608437933'
        assert req_body['engine_id'] == 'sampleEngine123'

    def test_save_query_required_params_with_retries(self):
        # Enable retries and run test_save_query_required_params.
        _service.enable_retries()
        self.test_save_query_required_params()

        # Disable retries and run test_save_query_required_params.
        _service.disable_retries()
        self.test_save_query_required_params()

    @responses.activate
    def test_save_query_value_error(self):
        """
        test_save_query_value_error()
        """
        # Set up mock
        url = preprocess_url('/queries/testString')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Set up parameter values
        query_name = 'testString'
        created_by = '<username>@<domain>.com'
        description = 'query to get expense data'
        query_string = 'select expenses from expenditure'
        created_on = '1608437933'
        engine_id = 'sampleEngine123'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "query_name": query_name,
            "created_by": created_by,
            "description": description,
            "query_string": query_string,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.save_query(**req_copy)

    def test_save_query_value_error_with_retries(self):
        # Enable retries and run test_save_query_value_error.
        _service.enable_retries()
        self.test_save_query_value_error()

        # Disable retries and run test_save_query_value_error.
        _service.disable_retries()
        self.test_save_query_value_error()


class TestDeleteQuery:
    """
    Test Class for delete_query
    """

    @responses.activate
    def test_delete_query_all_params(self):
        """
        delete_query()
        """
        # Set up mock
        url = preprocess_url('/queries/testString')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        query_name = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.delete_query(
            query_name,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_delete_query_all_params_with_retries(self):
        # Enable retries and run test_delete_query_all_params.
        _service.enable_retries()
        self.test_delete_query_all_params()

        # Disable retries and run test_delete_query_all_params.
        _service.disable_retries()
        self.test_delete_query_all_params()

    @responses.activate
    def test_delete_query_required_params(self):
        """
        test_delete_query_required_params()
        """
        # Set up mock
        url = preprocess_url('/queries/testString')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        query_name = 'testString'

        # Invoke method
        response = _service.delete_query(
            query_name,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_delete_query_required_params_with_retries(self):
        # Enable retries and run test_delete_query_required_params.
        _service.enable_retries()
        self.test_delete_query_required_params()

        # Disable retries and run test_delete_query_required_params.
        _service.disable_retries()
        self.test_delete_query_required_params()

    @responses.activate
    def test_delete_query_value_error(self):
        """
        test_delete_query_value_error()
        """
        # Set up mock
        url = preprocess_url('/queries/testString')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        query_name = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "query_name": query_name,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_query(**req_copy)

    def test_delete_query_value_error_with_retries(self):
        # Enable retries and run test_delete_query_value_error.
        _service.enable_retries()
        self.test_delete_query_value_error()

        # Disable retries and run test_delete_query_value_error.
        _service.disable_retries()
        self.test_delete_query_value_error()


class TestUpdateQuery:
    """
    Test Class for update_query
    """

    @responses.activate
    def test_update_query_all_params(self):
        """
        update_query()
        """
        # Set up mock
        url = preprocess_url('/queries/testString')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        query_name = 'testString'
        query_string = 'testString'
        description = 'testString'
        new_query_name = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.update_query(
            query_name,
            query_string,
            description,
            new_query_name,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['query_string'] == 'testString'
        assert req_body['description'] == 'testString'
        assert req_body['new_query_name'] == 'testString'

    def test_update_query_all_params_with_retries(self):
        # Enable retries and run test_update_query_all_params.
        _service.enable_retries()
        self.test_update_query_all_params()

        # Disable retries and run test_update_query_all_params.
        _service.disable_retries()
        self.test_update_query_all_params()

    @responses.activate
    def test_update_query_required_params(self):
        """
        test_update_query_required_params()
        """
        # Set up mock
        url = preprocess_url('/queries/testString')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        query_name = 'testString'
        query_string = 'testString'
        description = 'testString'
        new_query_name = 'testString'

        # Invoke method
        response = _service.update_query(
            query_name,
            query_string,
            description,
            new_query_name,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['query_string'] == 'testString'
        assert req_body['description'] == 'testString'
        assert req_body['new_query_name'] == 'testString'

    def test_update_query_required_params_with_retries(self):
        # Enable retries and run test_update_query_required_params.
        _service.enable_retries()
        self.test_update_query_required_params()

        # Disable retries and run test_update_query_required_params.
        _service.disable_retries()
        self.test_update_query_required_params()

    @responses.activate
    def test_update_query_value_error(self):
        """
        test_update_query_value_error()
        """
        # Set up mock
        url = preprocess_url('/queries/testString')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        query_name = 'testString'
        query_string = 'testString'
        description = 'testString'
        new_query_name = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "query_name": query_name,
            "query_string": query_string,
            "description": description,
            "new_query_name": new_query_name,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.update_query(**req_copy)

    def test_update_query_value_error_with_retries(self):
        # Enable retries and run test_update_query_value_error.
        _service.enable_retries()
        self.test_update_query_value_error()

        # Disable retries and run test_update_query_value_error.
        _service.disable_retries()
        self.test_update_query_value_error()


class TestGetQueries:
    """
    Test Class for get_queries
    """

    @responses.activate
    def test_get_queries_all_params(self):
        """
        get_queries()
        """
        # Set up mock
        url = preprocess_url('/queries')
        mock_response = '{"queries": [{"created_by": "<username>@<domain>.com", "created_on": "1608437933", "description": "query to get expense data", "engine_id": "sampleEngine123", "query_name": "new_query_name", "query_string": "select expenses from expenditure"}], "response": {"_messageCode_": "<message code>", "message": "Success"}}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.get_queries(
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_queries_all_params_with_retries(self):
        # Enable retries and run test_get_queries_all_params.
        _service.enable_retries()
        self.test_get_queries_all_params()

        # Disable retries and run test_get_queries_all_params.
        _service.disable_retries()
        self.test_get_queries_all_params()

    @responses.activate
    def test_get_queries_required_params(self):
        """
        test_get_queries_required_params()
        """
        # Set up mock
        url = preprocess_url('/queries')
        mock_response = '{"queries": [{"created_by": "<username>@<domain>.com", "created_on": "1608437933", "description": "query to get expense data", "engine_id": "sampleEngine123", "query_name": "new_query_name", "query_string": "select expenses from expenditure"}], "response": {"_messageCode_": "<message code>", "message": "Success"}}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Invoke method
        response = _service.get_queries()

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_queries_required_params_with_retries(self):
        # Enable retries and run test_get_queries_required_params.
        _service.enable_retries()
        self.test_get_queries_required_params()

        # Disable retries and run test_get_queries_required_params.
        _service.disable_retries()
        self.test_get_queries_required_params()


# endregion
##############################################################################
# End of Service: Queries
##############################################################################

##############################################################################
# Start of Service: Schemas
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ['TEST_SERVICE_AUTH_TYPE'] = 'noAuth'

        service = WatsonxDataV1.new_instance(
            service_name='TEST_SERVICE',
        )

        assert service is not None
        assert isinstance(service, WatsonxDataV1)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match='authenticator must be provided'):
            service = WatsonxDataV1.new_instance(
                service_name='TEST_SERVICE_NOT_FOUND',
            )


class TestCreateSchema:
    """
    Test Class for create_schema
    """

    @responses.activate
    def test_create_schema_all_params(self):
        """
        create_schema()
        """
        # Set up mock
        url = preprocess_url('/schemas/schema')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Set up parameter values
        catalog_name = 'sampleCatalog'
        engine_id = 'sampleEngine123'
        schema_name = 'new_schema'
        bucket_name = 'sample-bucket'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.create_schema(
            catalog_name,
            engine_id,
            schema_name,
            bucket_name=bucket_name,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['catalog_name'] == 'sampleCatalog'
        assert req_body['engine_id'] == 'sampleEngine123'
        assert req_body['schema_name'] == 'new_schema'
        assert req_body['bucket_name'] == 'sample-bucket'

    def test_create_schema_all_params_with_retries(self):
        # Enable retries and run test_create_schema_all_params.
        _service.enable_retries()
        self.test_create_schema_all_params()

        # Disable retries and run test_create_schema_all_params.
        _service.disable_retries()
        self.test_create_schema_all_params()

    @responses.activate
    def test_create_schema_required_params(self):
        """
        test_create_schema_required_params()
        """
        # Set up mock
        url = preprocess_url('/schemas/schema')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Set up parameter values
        catalog_name = 'sampleCatalog'
        engine_id = 'sampleEngine123'
        schema_name = 'new_schema'
        bucket_name = 'sample-bucket'

        # Invoke method
        response = _service.create_schema(
            catalog_name,
            engine_id,
            schema_name,
            bucket_name=bucket_name,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['catalog_name'] == 'sampleCatalog'
        assert req_body['engine_id'] == 'sampleEngine123'
        assert req_body['schema_name'] == 'new_schema'
        assert req_body['bucket_name'] == 'sample-bucket'

    def test_create_schema_required_params_with_retries(self):
        # Enable retries and run test_create_schema_required_params.
        _service.enable_retries()
        self.test_create_schema_required_params()

        # Disable retries and run test_create_schema_required_params.
        _service.disable_retries()
        self.test_create_schema_required_params()

    @responses.activate
    def test_create_schema_value_error(self):
        """
        test_create_schema_value_error()
        """
        # Set up mock
        url = preprocess_url('/schemas/schema')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Set up parameter values
        catalog_name = 'sampleCatalog'
        engine_id = 'sampleEngine123'
        schema_name = 'new_schema'
        bucket_name = 'sample-bucket'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "catalog_name": catalog_name,
            "engine_id": engine_id,
            "schema_name": schema_name,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_schema(**req_copy)

    def test_create_schema_value_error_with_retries(self):
        # Enable retries and run test_create_schema_value_error.
        _service.enable_retries()
        self.test_create_schema_value_error()

        # Disable retries and run test_create_schema_value_error.
        _service.disable_retries()
        self.test_create_schema_value_error()


class TestDeleteSchema:
    """
    Test Class for delete_schema
    """

    @responses.activate
    def test_delete_schema_all_params(self):
        """
        delete_schema()
        """
        # Set up mock
        url = preprocess_url('/schemas/schema')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        catalog_name = 'sampleCatalog'
        engine_id = 'sampleEngine123'
        schema_name = 'new_schema'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.delete_schema(
            catalog_name,
            engine_id,
            schema_name,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['catalog_name'] == 'sampleCatalog'
        assert req_body['engine_id'] == 'sampleEngine123'
        assert req_body['schema_name'] == 'new_schema'

    def test_delete_schema_all_params_with_retries(self):
        # Enable retries and run test_delete_schema_all_params.
        _service.enable_retries()
        self.test_delete_schema_all_params()

        # Disable retries and run test_delete_schema_all_params.
        _service.disable_retries()
        self.test_delete_schema_all_params()

    @responses.activate
    def test_delete_schema_required_params(self):
        """
        test_delete_schema_required_params()
        """
        # Set up mock
        url = preprocess_url('/schemas/schema')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        catalog_name = 'sampleCatalog'
        engine_id = 'sampleEngine123'
        schema_name = 'new_schema'

        # Invoke method
        response = _service.delete_schema(
            catalog_name,
            engine_id,
            schema_name,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['catalog_name'] == 'sampleCatalog'
        assert req_body['engine_id'] == 'sampleEngine123'
        assert req_body['schema_name'] == 'new_schema'

    def test_delete_schema_required_params_with_retries(self):
        # Enable retries and run test_delete_schema_required_params.
        _service.enable_retries()
        self.test_delete_schema_required_params()

        # Disable retries and run test_delete_schema_required_params.
        _service.disable_retries()
        self.test_delete_schema_required_params()

    @responses.activate
    def test_delete_schema_value_error(self):
        """
        test_delete_schema_value_error()
        """
        # Set up mock
        url = preprocess_url('/schemas/schema')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        catalog_name = 'sampleCatalog'
        engine_id = 'sampleEngine123'
        schema_name = 'new_schema'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "catalog_name": catalog_name,
            "engine_id": engine_id,
            "schema_name": schema_name,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_schema(**req_copy)

    def test_delete_schema_value_error_with_retries(self):
        # Enable retries and run test_delete_schema_value_error.
        _service.enable_retries()
        self.test_delete_schema_value_error()

        # Disable retries and run test_delete_schema_value_error.
        _service.disable_retries()
        self.test_delete_schema_value_error()


class TestGetSchemas:
    """
    Test Class for get_schemas
    """

    @responses.activate
    def test_get_schemas_all_params(self):
        """
        get_schemas()
        """
        # Set up mock
        url = preprocess_url('/schemas')
        mock_response = '{"response": {"_messageCode_": "<message code>", "message": "Success"}, "schemas": ["schemas"]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        engine_id = 'testString'
        catalog_name = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.get_schemas(
            engine_id,
            catalog_name,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'engine_id={}'.format(engine_id) in query_string
        assert 'catalog_name={}'.format(catalog_name) in query_string

    def test_get_schemas_all_params_with_retries(self):
        # Enable retries and run test_get_schemas_all_params.
        _service.enable_retries()
        self.test_get_schemas_all_params()

        # Disable retries and run test_get_schemas_all_params.
        _service.disable_retries()
        self.test_get_schemas_all_params()

    @responses.activate
    def test_get_schemas_required_params(self):
        """
        test_get_schemas_required_params()
        """
        # Set up mock
        url = preprocess_url('/schemas')
        mock_response = '{"response": {"_messageCode_": "<message code>", "message": "Success"}, "schemas": ["schemas"]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        engine_id = 'testString'
        catalog_name = 'testString'

        # Invoke method
        response = _service.get_schemas(
            engine_id,
            catalog_name,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'engine_id={}'.format(engine_id) in query_string
        assert 'catalog_name={}'.format(catalog_name) in query_string

    def test_get_schemas_required_params_with_retries(self):
        # Enable retries and run test_get_schemas_required_params.
        _service.enable_retries()
        self.test_get_schemas_required_params()

        # Disable retries and run test_get_schemas_required_params.
        _service.disable_retries()
        self.test_get_schemas_required_params()

    @responses.activate
    def test_get_schemas_value_error(self):
        """
        test_get_schemas_value_error()
        """
        # Set up mock
        url = preprocess_url('/schemas')
        mock_response = '{"response": {"_messageCode_": "<message code>", "message": "Success"}, "schemas": ["schemas"]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        engine_id = 'testString'
        catalog_name = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "engine_id": engine_id,
            "catalog_name": catalog_name,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_schemas(**req_copy)

    def test_get_schemas_value_error_with_retries(self):
        # Enable retries and run test_get_schemas_value_error.
        _service.enable_retries()
        self.test_get_schemas_value_error()

        # Disable retries and run test_get_schemas_value_error.
        _service.disable_retries()
        self.test_get_schemas_value_error()


# endregion
##############################################################################
# End of Service: Schemas
##############################################################################

##############################################################################
# Start of Service: Statement
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ['TEST_SERVICE_AUTH_TYPE'] = 'noAuth'

        service = WatsonxDataV1.new_instance(
            service_name='TEST_SERVICE',
        )

        assert service is not None
        assert isinstance(service, WatsonxDataV1)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match='authenticator must be provided'):
            service = WatsonxDataV1.new_instance(
                service_name='TEST_SERVICE_NOT_FOUND',
            )


class TestPostQuery:
    """
    Test Class for post_query
    """

    @responses.activate
    def test_post_query_all_params(self):
        """
        post_query()
        """
        # Set up mock
        url = preprocess_url('/v1/statement')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=200,
        )

        # Set up parameter values
        engine = 'testString'
        catalog = 'testString'
        schema = 'testString'
        sql_query = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.post_query(
            engine,
            catalog,
            schema,
            sql_query,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'engine={}'.format(engine) in query_string

    def test_post_query_all_params_with_retries(self):
        # Enable retries and run test_post_query_all_params.
        _service.enable_retries()
        self.test_post_query_all_params()

        # Disable retries and run test_post_query_all_params.
        _service.disable_retries()
        self.test_post_query_all_params()

    @responses.activate
    def test_post_query_required_params(self):
        """
        test_post_query_required_params()
        """
        # Set up mock
        url = preprocess_url('/v1/statement')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=200,
        )

        # Set up parameter values
        engine = 'testString'
        catalog = 'testString'
        schema = 'testString'
        sql_query = 'testString'

        # Invoke method
        response = _service.post_query(
            engine,
            catalog,
            schema,
            sql_query,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'engine={}'.format(engine) in query_string

    def test_post_query_required_params_with_retries(self):
        # Enable retries and run test_post_query_required_params.
        _service.enable_retries()
        self.test_post_query_required_params()

        # Disable retries and run test_post_query_required_params.
        _service.disable_retries()
        self.test_post_query_required_params()

    @responses.activate
    def test_post_query_value_error(self):
        """
        test_post_query_value_error()
        """
        # Set up mock
        url = preprocess_url('/v1/statement')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=200,
        )

        # Set up parameter values
        engine = 'testString'
        catalog = 'testString'
        schema = 'testString'
        sql_query = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "engine": engine,
            "catalog": catalog,
            "schema": schema,
            "sql_query": sql_query,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.post_query(**req_copy)

    def test_post_query_value_error_with_retries(self):
        # Enable retries and run test_post_query_value_error.
        _service.enable_retries()
        self.test_post_query_value_error()

        # Disable retries and run test_post_query_value_error.
        _service.disable_retries()
        self.test_post_query_value_error()


# endregion
##############################################################################
# End of Service: Statement
##############################################################################

##############################################################################
# Start of Service: Tables
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ['TEST_SERVICE_AUTH_TYPE'] = 'noAuth'

        service = WatsonxDataV1.new_instance(
            service_name='TEST_SERVICE',
        )

        assert service is not None
        assert isinstance(service, WatsonxDataV1)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match='authenticator must be provided'):
            service = WatsonxDataV1.new_instance(
                service_name='TEST_SERVICE_NOT_FOUND',
            )


class TestDeleteTable:
    """
    Test Class for delete_table
    """

    @responses.activate
    def test_delete_table_all_params(self):
        """
        delete_table()
        """
        # Set up mock
        url = preprocess_url('/tables/table')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Construct a dict representation of a DeleteTableBodyDeleteTablesItems model
        delete_table_body_delete_tables_items_model = {}
        delete_table_body_delete_tables_items_model['catalog_name'] = 'sampleCatalog'
        delete_table_body_delete_tables_items_model['schema_name'] = 'new_schema'
        delete_table_body_delete_tables_items_model['table_name'] = 'new_table'

        # Set up parameter values
        delete_tables = [delete_table_body_delete_tables_items_model]
        engine_id = 'sampleEngine123'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.delete_table(
            delete_tables,
            engine_id,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['delete_tables'] == [delete_table_body_delete_tables_items_model]
        assert req_body['engine_id'] == 'sampleEngine123'

    def test_delete_table_all_params_with_retries(self):
        # Enable retries and run test_delete_table_all_params.
        _service.enable_retries()
        self.test_delete_table_all_params()

        # Disable retries and run test_delete_table_all_params.
        _service.disable_retries()
        self.test_delete_table_all_params()

    @responses.activate
    def test_delete_table_required_params(self):
        """
        test_delete_table_required_params()
        """
        # Set up mock
        url = preprocess_url('/tables/table')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Construct a dict representation of a DeleteTableBodyDeleteTablesItems model
        delete_table_body_delete_tables_items_model = {}
        delete_table_body_delete_tables_items_model['catalog_name'] = 'sampleCatalog'
        delete_table_body_delete_tables_items_model['schema_name'] = 'new_schema'
        delete_table_body_delete_tables_items_model['table_name'] = 'new_table'

        # Set up parameter values
        delete_tables = [delete_table_body_delete_tables_items_model]
        engine_id = 'sampleEngine123'

        # Invoke method
        response = _service.delete_table(
            delete_tables,
            engine_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['delete_tables'] == [delete_table_body_delete_tables_items_model]
        assert req_body['engine_id'] == 'sampleEngine123'

    def test_delete_table_required_params_with_retries(self):
        # Enable retries and run test_delete_table_required_params.
        _service.enable_retries()
        self.test_delete_table_required_params()

        # Disable retries and run test_delete_table_required_params.
        _service.disable_retries()
        self.test_delete_table_required_params()

    @responses.activate
    def test_delete_table_value_error(self):
        """
        test_delete_table_value_error()
        """
        # Set up mock
        url = preprocess_url('/tables/table')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Construct a dict representation of a DeleteTableBodyDeleteTablesItems model
        delete_table_body_delete_tables_items_model = {}
        delete_table_body_delete_tables_items_model['catalog_name'] = 'sampleCatalog'
        delete_table_body_delete_tables_items_model['schema_name'] = 'new_schema'
        delete_table_body_delete_tables_items_model['table_name'] = 'new_table'

        # Set up parameter values
        delete_tables = [delete_table_body_delete_tables_items_model]
        engine_id = 'sampleEngine123'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "delete_tables": delete_tables,
            "engine_id": engine_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_table(**req_copy)

    def test_delete_table_value_error_with_retries(self):
        # Enable retries and run test_delete_table_value_error.
        _service.enable_retries()
        self.test_delete_table_value_error()

        # Disable retries and run test_delete_table_value_error.
        _service.disable_retries()
        self.test_delete_table_value_error()


class TestUpdateTable:
    """
    Test Class for update_table
    """

    @responses.activate
    def test_update_table_all_params(self):
        """
        update_table()
        """
        # Set up mock
        url = preprocess_url('/tables/table')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='*/*',
            status=200,
        )

        # Construct a dict representation of a UpdateTableBodyAddColumnsItems model
        update_table_body_add_columns_items_model = {}
        update_table_body_add_columns_items_model['column_comment'] = 'income column'
        update_table_body_add_columns_items_model['column_name'] = 'income'
        update_table_body_add_columns_items_model['data_type'] = 'varchar'

        # Construct a dict representation of a UpdateTableBodyDropColumnsItems model
        update_table_body_drop_columns_items_model = {}
        update_table_body_drop_columns_items_model['column_name'] = 'expenditure'

        # Construct a dict representation of a UpdateTableBodyRenameColumnsItems model
        update_table_body_rename_columns_items_model = {}
        update_table_body_rename_columns_items_model['column_name'] = 'expenditure'
        update_table_body_rename_columns_items_model['new_column_name'] = 'expenses'

        # Set up parameter values
        engine_id = 'testString'
        catalog_name = 'testString'
        schema_name = 'testString'
        table_name = 'testString'
        add_columns = [update_table_body_add_columns_items_model]
        drop_columns = [update_table_body_drop_columns_items_model]
        new_table_name = 'updated_table_name'
        rename_columns = [update_table_body_rename_columns_items_model]
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.update_table(
            engine_id,
            catalog_name,
            schema_name,
            table_name,
            add_columns=add_columns,
            drop_columns=drop_columns,
            new_table_name=new_table_name,
            rename_columns=rename_columns,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'engine_id={}'.format(engine_id) in query_string
        assert 'catalog_name={}'.format(catalog_name) in query_string
        assert 'schema_name={}'.format(schema_name) in query_string
        assert 'table_name={}'.format(table_name) in query_string
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['add_columns'] == [update_table_body_add_columns_items_model]
        assert req_body['drop_columns'] == [update_table_body_drop_columns_items_model]
        assert req_body['new_table_name'] == 'updated_table_name'
        assert req_body['rename_columns'] == [update_table_body_rename_columns_items_model]

    def test_update_table_all_params_with_retries(self):
        # Enable retries and run test_update_table_all_params.
        _service.enable_retries()
        self.test_update_table_all_params()

        # Disable retries and run test_update_table_all_params.
        _service.disable_retries()
        self.test_update_table_all_params()

    @responses.activate
    def test_update_table_required_params(self):
        """
        test_update_table_required_params()
        """
        # Set up mock
        url = preprocess_url('/tables/table')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='*/*',
            status=200,
        )

        # Construct a dict representation of a UpdateTableBodyAddColumnsItems model
        update_table_body_add_columns_items_model = {}
        update_table_body_add_columns_items_model['column_comment'] = 'income column'
        update_table_body_add_columns_items_model['column_name'] = 'income'
        update_table_body_add_columns_items_model['data_type'] = 'varchar'

        # Construct a dict representation of a UpdateTableBodyDropColumnsItems model
        update_table_body_drop_columns_items_model = {}
        update_table_body_drop_columns_items_model['column_name'] = 'expenditure'

        # Construct a dict representation of a UpdateTableBodyRenameColumnsItems model
        update_table_body_rename_columns_items_model = {}
        update_table_body_rename_columns_items_model['column_name'] = 'expenditure'
        update_table_body_rename_columns_items_model['new_column_name'] = 'expenses'

        # Set up parameter values
        engine_id = 'testString'
        catalog_name = 'testString'
        schema_name = 'testString'
        table_name = 'testString'
        add_columns = [update_table_body_add_columns_items_model]
        drop_columns = [update_table_body_drop_columns_items_model]
        new_table_name = 'updated_table_name'
        rename_columns = [update_table_body_rename_columns_items_model]

        # Invoke method
        response = _service.update_table(
            engine_id,
            catalog_name,
            schema_name,
            table_name,
            add_columns=add_columns,
            drop_columns=drop_columns,
            new_table_name=new_table_name,
            rename_columns=rename_columns,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'engine_id={}'.format(engine_id) in query_string
        assert 'catalog_name={}'.format(catalog_name) in query_string
        assert 'schema_name={}'.format(schema_name) in query_string
        assert 'table_name={}'.format(table_name) in query_string
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['add_columns'] == [update_table_body_add_columns_items_model]
        assert req_body['drop_columns'] == [update_table_body_drop_columns_items_model]
        assert req_body['new_table_name'] == 'updated_table_name'
        assert req_body['rename_columns'] == [update_table_body_rename_columns_items_model]

    def test_update_table_required_params_with_retries(self):
        # Enable retries and run test_update_table_required_params.
        _service.enable_retries()
        self.test_update_table_required_params()

        # Disable retries and run test_update_table_required_params.
        _service.disable_retries()
        self.test_update_table_required_params()

    @responses.activate
    def test_update_table_value_error(self):
        """
        test_update_table_value_error()
        """
        # Set up mock
        url = preprocess_url('/tables/table')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='*/*',
            status=200,
        )

        # Construct a dict representation of a UpdateTableBodyAddColumnsItems model
        update_table_body_add_columns_items_model = {}
        update_table_body_add_columns_items_model['column_comment'] = 'income column'
        update_table_body_add_columns_items_model['column_name'] = 'income'
        update_table_body_add_columns_items_model['data_type'] = 'varchar'

        # Construct a dict representation of a UpdateTableBodyDropColumnsItems model
        update_table_body_drop_columns_items_model = {}
        update_table_body_drop_columns_items_model['column_name'] = 'expenditure'

        # Construct a dict representation of a UpdateTableBodyRenameColumnsItems model
        update_table_body_rename_columns_items_model = {}
        update_table_body_rename_columns_items_model['column_name'] = 'expenditure'
        update_table_body_rename_columns_items_model['new_column_name'] = 'expenses'

        # Set up parameter values
        engine_id = 'testString'
        catalog_name = 'testString'
        schema_name = 'testString'
        table_name = 'testString'
        add_columns = [update_table_body_add_columns_items_model]
        drop_columns = [update_table_body_drop_columns_items_model]
        new_table_name = 'updated_table_name'
        rename_columns = [update_table_body_rename_columns_items_model]

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "engine_id": engine_id,
            "catalog_name": catalog_name,
            "schema_name": schema_name,
            "table_name": table_name,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.update_table(**req_copy)

    def test_update_table_value_error_with_retries(self):
        # Enable retries and run test_update_table_value_error.
        _service.enable_retries()
        self.test_update_table_value_error()

        # Disable retries and run test_update_table_value_error.
        _service.disable_retries()
        self.test_update_table_value_error()


class TestGetTableSnapshots:
    """
    Test Class for get_table_snapshots
    """

    @responses.activate
    def test_get_table_snapshots_all_params(self):
        """
        get_table_snapshots()
        """
        # Set up mock
        url = preprocess_url('/tables/table/snapshots')
        mock_response = '{"response": {"_messageCode_": "<message code>", "message": "Success"}, "snapshots": [{"operation": "alter", "snapshot_id": "2332342122211222", "summary": {"anyKey": "anyValue"}, "committed_at": "1609379392"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        engine_id = 'testString'
        catalog_name = 'testString'
        schema_name = 'testString'
        table_name = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.get_table_snapshots(
            engine_id,
            catalog_name,
            schema_name,
            table_name,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'engine_id={}'.format(engine_id) in query_string
        assert 'catalog_name={}'.format(catalog_name) in query_string
        assert 'schema_name={}'.format(schema_name) in query_string
        assert 'table_name={}'.format(table_name) in query_string

    def test_get_table_snapshots_all_params_with_retries(self):
        # Enable retries and run test_get_table_snapshots_all_params.
        _service.enable_retries()
        self.test_get_table_snapshots_all_params()

        # Disable retries and run test_get_table_snapshots_all_params.
        _service.disable_retries()
        self.test_get_table_snapshots_all_params()

    @responses.activate
    def test_get_table_snapshots_required_params(self):
        """
        test_get_table_snapshots_required_params()
        """
        # Set up mock
        url = preprocess_url('/tables/table/snapshots')
        mock_response = '{"response": {"_messageCode_": "<message code>", "message": "Success"}, "snapshots": [{"operation": "alter", "snapshot_id": "2332342122211222", "summary": {"anyKey": "anyValue"}, "committed_at": "1609379392"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        engine_id = 'testString'
        catalog_name = 'testString'
        schema_name = 'testString'
        table_name = 'testString'

        # Invoke method
        response = _service.get_table_snapshots(
            engine_id,
            catalog_name,
            schema_name,
            table_name,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'engine_id={}'.format(engine_id) in query_string
        assert 'catalog_name={}'.format(catalog_name) in query_string
        assert 'schema_name={}'.format(schema_name) in query_string
        assert 'table_name={}'.format(table_name) in query_string

    def test_get_table_snapshots_required_params_with_retries(self):
        # Enable retries and run test_get_table_snapshots_required_params.
        _service.enable_retries()
        self.test_get_table_snapshots_required_params()

        # Disable retries and run test_get_table_snapshots_required_params.
        _service.disable_retries()
        self.test_get_table_snapshots_required_params()

    @responses.activate
    def test_get_table_snapshots_value_error(self):
        """
        test_get_table_snapshots_value_error()
        """
        # Set up mock
        url = preprocess_url('/tables/table/snapshots')
        mock_response = '{"response": {"_messageCode_": "<message code>", "message": "Success"}, "snapshots": [{"operation": "alter", "snapshot_id": "2332342122211222", "summary": {"anyKey": "anyValue"}, "committed_at": "1609379392"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        engine_id = 'testString'
        catalog_name = 'testString'
        schema_name = 'testString'
        table_name = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "engine_id": engine_id,
            "catalog_name": catalog_name,
            "schema_name": schema_name,
            "table_name": table_name,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_table_snapshots(**req_copy)

    def test_get_table_snapshots_value_error_with_retries(self):
        # Enable retries and run test_get_table_snapshots_value_error.
        _service.enable_retries()
        self.test_get_table_snapshots_value_error()

        # Disable retries and run test_get_table_snapshots_value_error.
        _service.disable_retries()
        self.test_get_table_snapshots_value_error()


class TestRollbackSnapshot:
    """
    Test Class for rollback_snapshot
    """

    @responses.activate
    def test_rollback_snapshot_all_params(self):
        """
        rollback_snapshot()
        """
        # Set up mock
        url = preprocess_url('/tables/table/rollback')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Set up parameter values
        engine_id = 'testString'
        catalog_name = 'testString'
        schema_name = 'testString'
        snapshot_id = '2332342122211222'
        table_name = 'new_table'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.rollback_snapshot(
            engine_id,
            catalog_name,
            schema_name,
            snapshot_id,
            table_name,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'engine_id={}'.format(engine_id) in query_string
        assert 'catalog_name={}'.format(catalog_name) in query_string
        assert 'schema_name={}'.format(schema_name) in query_string
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['snapshot_id'] == '2332342122211222'
        assert req_body['table_name'] == 'new_table'

    def test_rollback_snapshot_all_params_with_retries(self):
        # Enable retries and run test_rollback_snapshot_all_params.
        _service.enable_retries()
        self.test_rollback_snapshot_all_params()

        # Disable retries and run test_rollback_snapshot_all_params.
        _service.disable_retries()
        self.test_rollback_snapshot_all_params()

    @responses.activate
    def test_rollback_snapshot_required_params(self):
        """
        test_rollback_snapshot_required_params()
        """
        # Set up mock
        url = preprocess_url('/tables/table/rollback')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Set up parameter values
        engine_id = 'testString'
        catalog_name = 'testString'
        schema_name = 'testString'
        snapshot_id = '2332342122211222'
        table_name = 'new_table'

        # Invoke method
        response = _service.rollback_snapshot(
            engine_id,
            catalog_name,
            schema_name,
            snapshot_id,
            table_name,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'engine_id={}'.format(engine_id) in query_string
        assert 'catalog_name={}'.format(catalog_name) in query_string
        assert 'schema_name={}'.format(schema_name) in query_string
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['snapshot_id'] == '2332342122211222'
        assert req_body['table_name'] == 'new_table'

    def test_rollback_snapshot_required_params_with_retries(self):
        # Enable retries and run test_rollback_snapshot_required_params.
        _service.enable_retries()
        self.test_rollback_snapshot_required_params()

        # Disable retries and run test_rollback_snapshot_required_params.
        _service.disable_retries()
        self.test_rollback_snapshot_required_params()

    @responses.activate
    def test_rollback_snapshot_value_error(self):
        """
        test_rollback_snapshot_value_error()
        """
        # Set up mock
        url = preprocess_url('/tables/table/rollback')
        mock_response = '{"_messageCode_": "<message code>", "message": "Success"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Set up parameter values
        engine_id = 'testString'
        catalog_name = 'testString'
        schema_name = 'testString'
        snapshot_id = '2332342122211222'
        table_name = 'new_table'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "engine_id": engine_id,
            "catalog_name": catalog_name,
            "schema_name": schema_name,
            "snapshot_id": snapshot_id,
            "table_name": table_name,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.rollback_snapshot(**req_copy)

    def test_rollback_snapshot_value_error_with_retries(self):
        # Enable retries and run test_rollback_snapshot_value_error.
        _service.enable_retries()
        self.test_rollback_snapshot_value_error()

        # Disable retries and run test_rollback_snapshot_value_error.
        _service.disable_retries()
        self.test_rollback_snapshot_value_error()


class TestGetTables:
    """
    Test Class for get_tables
    """

    @responses.activate
    def test_get_tables_all_params(self):
        """
        get_tables()
        """
        # Set up mock
        url = preprocess_url('/tables')
        mock_response = '{"response": {"_messageCode_": "<message code>", "message": "Success"}, "tables": ["tables"]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        engine_id = 'testString'
        catalog_name = 'testString'
        schema_name = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.get_tables(
            engine_id,
            catalog_name,
            schema_name,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'engine_id={}'.format(engine_id) in query_string
        assert 'catalog_name={}'.format(catalog_name) in query_string
        assert 'schema_name={}'.format(schema_name) in query_string

    def test_get_tables_all_params_with_retries(self):
        # Enable retries and run test_get_tables_all_params.
        _service.enable_retries()
        self.test_get_tables_all_params()

        # Disable retries and run test_get_tables_all_params.
        _service.disable_retries()
        self.test_get_tables_all_params()

    @responses.activate
    def test_get_tables_required_params(self):
        """
        test_get_tables_required_params()
        """
        # Set up mock
        url = preprocess_url('/tables')
        mock_response = '{"response": {"_messageCode_": "<message code>", "message": "Success"}, "tables": ["tables"]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        engine_id = 'testString'
        catalog_name = 'testString'
        schema_name = 'testString'

        # Invoke method
        response = _service.get_tables(
            engine_id,
            catalog_name,
            schema_name,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'engine_id={}'.format(engine_id) in query_string
        assert 'catalog_name={}'.format(catalog_name) in query_string
        assert 'schema_name={}'.format(schema_name) in query_string

    def test_get_tables_required_params_with_retries(self):
        # Enable retries and run test_get_tables_required_params.
        _service.enable_retries()
        self.test_get_tables_required_params()

        # Disable retries and run test_get_tables_required_params.
        _service.disable_retries()
        self.test_get_tables_required_params()

    @responses.activate
    def test_get_tables_value_error(self):
        """
        test_get_tables_value_error()
        """
        # Set up mock
        url = preprocess_url('/tables')
        mock_response = '{"response": {"_messageCode_": "<message code>", "message": "Success"}, "tables": ["tables"]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        engine_id = 'testString'
        catalog_name = 'testString'
        schema_name = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "engine_id": engine_id,
            "catalog_name": catalog_name,
            "schema_name": schema_name,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_tables(**req_copy)

    def test_get_tables_value_error_with_retries(self):
        # Enable retries and run test_get_tables_value_error.
        _service.enable_retries()
        self.test_get_tables_value_error()

        # Disable retries and run test_get_tables_value_error.
        _service.disable_retries()
        self.test_get_tables_value_error()


class TestParseCsv:
    """
    Test Class for parse_csv
    """

    @responses.activate
    def test_parse_csv_all_params(self):
        """
        parse_csv()
        """
        # Set up mock
        url = preprocess_url('/parse/csv')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=200,
        )

        # Set up parameter values
        engine = 'testString'
        parse_file = 'testString'
        file_type = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.parse_csv(
            engine,
            parse_file,
            file_type,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'engine={}'.format(engine) in query_string

    def test_parse_csv_all_params_with_retries(self):
        # Enable retries and run test_parse_csv_all_params.
        _service.enable_retries()
        self.test_parse_csv_all_params()

        # Disable retries and run test_parse_csv_all_params.
        _service.disable_retries()
        self.test_parse_csv_all_params()

    @responses.activate
    def test_parse_csv_required_params(self):
        """
        test_parse_csv_required_params()
        """
        # Set up mock
        url = preprocess_url('/parse/csv')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=200,
        )

        # Set up parameter values
        engine = 'testString'
        parse_file = 'testString'
        file_type = 'testString'

        # Invoke method
        response = _service.parse_csv(
            engine,
            parse_file,
            file_type,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'engine={}'.format(engine) in query_string

    def test_parse_csv_required_params_with_retries(self):
        # Enable retries and run test_parse_csv_required_params.
        _service.enable_retries()
        self.test_parse_csv_required_params()

        # Disable retries and run test_parse_csv_required_params.
        _service.disable_retries()
        self.test_parse_csv_required_params()

    @responses.activate
    def test_parse_csv_value_error(self):
        """
        test_parse_csv_value_error()
        """
        # Set up mock
        url = preprocess_url('/parse/csv')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=200,
        )

        # Set up parameter values
        engine = 'testString'
        parse_file = 'testString'
        file_type = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "engine": engine,
            "parse_file": parse_file,
            "file_type": file_type,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.parse_csv(**req_copy)

    def test_parse_csv_value_error_with_retries(self):
        # Enable retries and run test_parse_csv_value_error.
        _service.enable_retries()
        self.test_parse_csv_value_error()

        # Disable retries and run test_parse_csv_value_error.
        _service.disable_retries()
        self.test_parse_csv_value_error()


class TestUplaodCsv:
    """
    Test Class for uplaod_csv
    """

    @responses.activate
    def test_uplaod_csv_all_params(self):
        """
        uplaod_csv()
        """
        # Set up mock
        url = preprocess_url('/v2/upload/csv')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=200,
        )

        # Set up parameter values
        engine = 'testString'
        catalog = 'testString'
        schema = 'testString'
        table_name = 'testString'
        ingestion_job_name = 'testString'
        scheduled = 'testString'
        created_by = 'testString'
        target_table = 'testString'
        headers_ = 'testString'
        csv = 'testString'
        auth_instance_id = 'testString'

        # Invoke method
        response = _service.uplaod_csv(
            engine,
            catalog,
            schema,
            table_name,
            ingestion_job_name,
            scheduled,
            created_by,
            target_table,
            headers_,
            csv,
            auth_instance_id=auth_instance_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'engine={}'.format(engine) in query_string

    def test_uplaod_csv_all_params_with_retries(self):
        # Enable retries and run test_uplaod_csv_all_params.
        _service.enable_retries()
        self.test_uplaod_csv_all_params()

        # Disable retries and run test_uplaod_csv_all_params.
        _service.disable_retries()
        self.test_uplaod_csv_all_params()

    @responses.activate
    def test_uplaod_csv_required_params(self):
        """
        test_uplaod_csv_required_params()
        """
        # Set up mock
        url = preprocess_url('/v2/upload/csv')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=200,
        )

        # Set up parameter values
        engine = 'testString'
        catalog = 'testString'
        schema = 'testString'
        table_name = 'testString'
        ingestion_job_name = 'testString'
        scheduled = 'testString'
        created_by = 'testString'
        target_table = 'testString'
        headers_ = 'testString'
        csv = 'testString'

        # Invoke method
        response = _service.uplaod_csv(
            engine,
            catalog,
            schema,
            table_name,
            ingestion_job_name,
            scheduled,
            created_by,
            target_table,
            headers_,
            csv,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'engine={}'.format(engine) in query_string

    def test_uplaod_csv_required_params_with_retries(self):
        # Enable retries and run test_uplaod_csv_required_params.
        _service.enable_retries()
        self.test_uplaod_csv_required_params()

        # Disable retries and run test_uplaod_csv_required_params.
        _service.disable_retries()
        self.test_uplaod_csv_required_params()

    @responses.activate
    def test_uplaod_csv_value_error(self):
        """
        test_uplaod_csv_value_error()
        """
        # Set up mock
        url = preprocess_url('/v2/upload/csv')
        mock_response = 'This is a mock binary response.'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='*/*',
            status=200,
        )

        # Set up parameter values
        engine = 'testString'
        catalog = 'testString'
        schema = 'testString'
        table_name = 'testString'
        ingestion_job_name = 'testString'
        scheduled = 'testString'
        created_by = 'testString'
        target_table = 'testString'
        headers_ = 'testString'
        csv = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "engine": engine,
            "catalog": catalog,
            "schema": schema,
            "table_name": table_name,
            "ingestion_job_name": ingestion_job_name,
            "scheduled": scheduled,
            "created_by": created_by,
            "target_table": target_table,
            "headers_": headers_,
            "csv": csv,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.uplaod_csv(**req_copy)

    def test_uplaod_csv_value_error_with_retries(self):
        # Enable retries and run test_uplaod_csv_value_error.
        _service.enable_retries()
        self.test_uplaod_csv_value_error()

        # Disable retries and run test_uplaod_csv_value_error.
        _service.disable_retries()
        self.test_uplaod_csv_value_error()


# endregion
##############################################################################
# End of Service: Tables
##############################################################################


##############################################################################
# Start of Model Tests
##############################################################################
# region


class TestModel_Bucket:
    """
    Test Class for Bucket
    """

    def test_bucket_serialization(self):
        """
        Test serialization/deserialization for Bucket
        """

        # Construct a json representation of a Bucket model
        bucket_model_json = {}
        bucket_model_json['created_by'] = '<username>@<domain>.com'
        bucket_model_json['created_on'] = '1686120645'
        bucket_model_json['description'] = 'COS bucket for customer data'
        bucket_model_json['endpoint'] = 'https://s3.<region>.cloud-object-storage.appdomain.cloud/'
        bucket_model_json['managed_by'] = 'IBM'
        bucket_model_json['state'] = 'active'
        bucket_model_json['tags'] = ['testbucket', 'userbucket']
        bucket_model_json['associated_catalogs'] = ['samplecatalog1', 'samplecatalog2']
        bucket_model_json['bucket_display_name'] = 'sample-bucket-displayname'
        bucket_model_json['bucket_id'] = 'samplebucket123'
        bucket_model_json['bucket_name'] = 'sample-bucket'
        bucket_model_json['bucket_type'] = 'ibm_cos'
        bucket_model_json['actions'] = ['read', 'update']

        # Construct a model instance of Bucket by calling from_dict on the json representation
        bucket_model = Bucket.from_dict(bucket_model_json)
        assert bucket_model != False

        # Construct a model instance of Bucket by calling from_dict on the json representation
        bucket_model_dict = Bucket.from_dict(bucket_model_json).__dict__
        bucket_model2 = Bucket(**bucket_model_dict)

        # Verify the model instances are equivalent
        assert bucket_model == bucket_model2

        # Convert model instance back to dict and verify no loss of data
        bucket_model_json2 = bucket_model.to_dict()
        assert bucket_model_json2 == bucket_model_json


class TestModel_BucketDbConnGroupsMetadata:
    """
    Test Class for BucketDbConnGroupsMetadata
    """

    def test_bucket_db_conn_groups_metadata_serialization(self):
        """
        Test serialization/deserialization for BucketDbConnGroupsMetadata
        """

        # Construct a json representation of a BucketDbConnGroupsMetadata model
        bucket_db_conn_groups_metadata_model_json = {}
        bucket_db_conn_groups_metadata_model_json['group_id'] = 'testString'
        bucket_db_conn_groups_metadata_model_json['permission'] = 'can_administer'

        # Construct a model instance of BucketDbConnGroupsMetadata by calling from_dict on the json representation
        bucket_db_conn_groups_metadata_model = BucketDbConnGroupsMetadata.from_dict(bucket_db_conn_groups_metadata_model_json)
        assert bucket_db_conn_groups_metadata_model != False

        # Construct a model instance of BucketDbConnGroupsMetadata by calling from_dict on the json representation
        bucket_db_conn_groups_metadata_model_dict = BucketDbConnGroupsMetadata.from_dict(bucket_db_conn_groups_metadata_model_json).__dict__
        bucket_db_conn_groups_metadata_model2 = BucketDbConnGroupsMetadata(**bucket_db_conn_groups_metadata_model_dict)

        # Verify the model instances are equivalent
        assert bucket_db_conn_groups_metadata_model == bucket_db_conn_groups_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        bucket_db_conn_groups_metadata_model_json2 = bucket_db_conn_groups_metadata_model.to_dict()
        assert bucket_db_conn_groups_metadata_model_json2 == bucket_db_conn_groups_metadata_model_json


class TestModel_BucketDbConnUsersMetadata:
    """
    Test Class for BucketDbConnUsersMetadata
    """

    def test_bucket_db_conn_users_metadata_serialization(self):
        """
        Test serialization/deserialization for BucketDbConnUsersMetadata
        """

        # Construct a json representation of a BucketDbConnUsersMetadata model
        bucket_db_conn_users_metadata_model_json = {}
        bucket_db_conn_users_metadata_model_json['user_name'] = 'testString'
        bucket_db_conn_users_metadata_model_json['permission'] = 'can_administer'

        # Construct a model instance of BucketDbConnUsersMetadata by calling from_dict on the json representation
        bucket_db_conn_users_metadata_model = BucketDbConnUsersMetadata.from_dict(bucket_db_conn_users_metadata_model_json)
        assert bucket_db_conn_users_metadata_model != False

        # Construct a model instance of BucketDbConnUsersMetadata by calling from_dict on the json representation
        bucket_db_conn_users_metadata_model_dict = BucketDbConnUsersMetadata.from_dict(bucket_db_conn_users_metadata_model_json).__dict__
        bucket_db_conn_users_metadata_model2 = BucketDbConnUsersMetadata(**bucket_db_conn_users_metadata_model_dict)

        # Verify the model instances are equivalent
        assert bucket_db_conn_users_metadata_model == bucket_db_conn_users_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        bucket_db_conn_users_metadata_model_json2 = bucket_db_conn_users_metadata_model.to_dict()
        assert bucket_db_conn_users_metadata_model_json2 == bucket_db_conn_users_metadata_model_json


class TestModel_BucketDetails:
    """
    Test Class for BucketDetails
    """

    def test_bucket_details_serialization(self):
        """
        Test serialization/deserialization for BucketDetails
        """

        # Construct a json representation of a BucketDetails model
        bucket_details_model_json = {}
        bucket_details_model_json['access_key'] = '<access_key>'
        bucket_details_model_json['bucket_name'] = 'sample-bucket'
        bucket_details_model_json['endpoint'] = 'https://s3.<region>.cloud-object-storage.appdomain.cloud/'
        bucket_details_model_json['secret_key'] = '<secret_key>'

        # Construct a model instance of BucketDetails by calling from_dict on the json representation
        bucket_details_model = BucketDetails.from_dict(bucket_details_model_json)
        assert bucket_details_model != False

        # Construct a model instance of BucketDetails by calling from_dict on the json representation
        bucket_details_model_dict = BucketDetails.from_dict(bucket_details_model_json).__dict__
        bucket_details_model2 = BucketDetails(**bucket_details_model_dict)

        # Verify the model instances are equivalent
        assert bucket_details_model == bucket_details_model2

        # Convert model instance back to dict and verify no loss of data
        bucket_details_model_json2 = bucket_details_model.to_dict()
        assert bucket_details_model_json2 == bucket_details_model_json


class TestModel_BucketPolicies:
    """
    Test Class for BucketPolicies
    """

    def test_bucket_policies_serialization(self):
        """
        Test serialization/deserialization for BucketPolicies
        """

        # Construct a json representation of a BucketPolicies model
        bucket_policies_model_json = {}
        bucket_policies_model_json['policy_version'] = 'testString'
        bucket_policies_model_json['policy_name'] = 'testString'

        # Construct a model instance of BucketPolicies by calling from_dict on the json representation
        bucket_policies_model = BucketPolicies.from_dict(bucket_policies_model_json)
        assert bucket_policies_model != False

        # Construct a model instance of BucketPolicies by calling from_dict on the json representation
        bucket_policies_model_dict = BucketPolicies.from_dict(bucket_policies_model_json).__dict__
        bucket_policies_model2 = BucketPolicies(**bucket_policies_model_dict)

        # Verify the model instances are equivalent
        assert bucket_policies_model == bucket_policies_model2

        # Convert model instance back to dict and verify no loss of data
        bucket_policies_model_json2 = bucket_policies_model.to_dict()
        assert bucket_policies_model_json2 == bucket_policies_model_json


class TestModel_CatalogGroupsMetadata:
    """
    Test Class for CatalogGroupsMetadata
    """

    def test_catalog_groups_metadata_serialization(self):
        """
        Test serialization/deserialization for CatalogGroupsMetadata
        """

        # Construct a json representation of a CatalogGroupsMetadata model
        catalog_groups_metadata_model_json = {}
        catalog_groups_metadata_model_json['group_id'] = 'testString'
        catalog_groups_metadata_model_json['permission'] = 'can_administer'

        # Construct a model instance of CatalogGroupsMetadata by calling from_dict on the json representation
        catalog_groups_metadata_model = CatalogGroupsMetadata.from_dict(catalog_groups_metadata_model_json)
        assert catalog_groups_metadata_model != False

        # Construct a model instance of CatalogGroupsMetadata by calling from_dict on the json representation
        catalog_groups_metadata_model_dict = CatalogGroupsMetadata.from_dict(catalog_groups_metadata_model_json).__dict__
        catalog_groups_metadata_model2 = CatalogGroupsMetadata(**catalog_groups_metadata_model_dict)

        # Verify the model instances are equivalent
        assert catalog_groups_metadata_model == catalog_groups_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        catalog_groups_metadata_model_json2 = catalog_groups_metadata_model.to_dict()
        assert catalog_groups_metadata_model_json2 == catalog_groups_metadata_model_json


class TestModel_CatalogPolicies:
    """
    Test Class for CatalogPolicies
    """

    def test_catalog_policies_serialization(self):
        """
        Test serialization/deserialization for CatalogPolicies
        """

        # Construct a json representation of a CatalogPolicies model
        catalog_policies_model_json = {}
        catalog_policies_model_json['policy_name'] = 'testString'
        catalog_policies_model_json['policy_version'] = 'testString'

        # Construct a model instance of CatalogPolicies by calling from_dict on the json representation
        catalog_policies_model = CatalogPolicies.from_dict(catalog_policies_model_json)
        assert catalog_policies_model != False

        # Construct a model instance of CatalogPolicies by calling from_dict on the json representation
        catalog_policies_model_dict = CatalogPolicies.from_dict(catalog_policies_model_json).__dict__
        catalog_policies_model2 = CatalogPolicies(**catalog_policies_model_dict)

        # Verify the model instances are equivalent
        assert catalog_policies_model == catalog_policies_model2

        # Convert model instance back to dict and verify no loss of data
        catalog_policies_model_json2 = catalog_policies_model.to_dict()
        assert catalog_policies_model_json2 == catalog_policies_model_json


class TestModel_CatalogUsersMetadata:
    """
    Test Class for CatalogUsersMetadata
    """

    def test_catalog_users_metadata_serialization(self):
        """
        Test serialization/deserialization for CatalogUsersMetadata
        """

        # Construct a json representation of a CatalogUsersMetadata model
        catalog_users_metadata_model_json = {}
        catalog_users_metadata_model_json['permission'] = 'can_administer'
        catalog_users_metadata_model_json['user_name'] = 'testString'

        # Construct a model instance of CatalogUsersMetadata by calling from_dict on the json representation
        catalog_users_metadata_model = CatalogUsersMetadata.from_dict(catalog_users_metadata_model_json)
        assert catalog_users_metadata_model != False

        # Construct a model instance of CatalogUsersMetadata by calling from_dict on the json representation
        catalog_users_metadata_model_dict = CatalogUsersMetadata.from_dict(catalog_users_metadata_model_json).__dict__
        catalog_users_metadata_model2 = CatalogUsersMetadata(**catalog_users_metadata_model_dict)

        # Verify the model instances are equivalent
        assert catalog_users_metadata_model == catalog_users_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        catalog_users_metadata_model_json2 = catalog_users_metadata_model.to_dict()
        assert catalog_users_metadata_model_json2 == catalog_users_metadata_model_json


class TestModel_CreateDataPolicyCreatedBody:
    """
    Test Class for CreateDataPolicyCreatedBody
    """

    def test_create_data_policy_created_body_serialization(self):
        """
        Test serialization/deserialization for CreateDataPolicyCreatedBody
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rule_grantee_model = {}  # RuleGrantee
        rule_grantee_model['value'] = 'testString'
        rule_grantee_model['key'] = 'user_name'
        rule_grantee_model['type'] = 'user_identity'

        rule_model = {}  # Rule
        rule_model['actions'] = ['all']
        rule_model['effect'] = 'allow'
        rule_model['grantee'] = rule_grantee_model

        create_data_policy_schema_model = {}  # CreateDataPolicySchema
        create_data_policy_schema_model['catalog_name'] = 'testString'
        create_data_policy_schema_model['data_artifact'] = 'schema1/table1/(column1|column2)'
        create_data_policy_schema_model['description'] = 'testString'
        create_data_policy_schema_model['policy_name'] = 'testString'
        create_data_policy_schema_model['rules'] = [rule_model]
        create_data_policy_schema_model['status'] = 'active'

        data_policy_metadata_model = {}  # DataPolicyMetadata
        data_policy_metadata_model['creator'] = 'testString'
        data_policy_metadata_model['description'] = 'testString'
        data_policy_metadata_model['modifier'] = 'testString'
        data_policy_metadata_model['pid'] = 'testString'
        data_policy_metadata_model['policy_name'] = 'testString'
        data_policy_metadata_model['updated_at'] = 'testString'
        data_policy_metadata_model['version'] = 'testString'
        data_policy_metadata_model['created_at'] = 'testString'

        success_response_model = {}  # SuccessResponse
        success_response_model['_messageCode_'] = '<message code>'
        success_response_model['message'] = 'Success'

        # Construct a json representation of a CreateDataPolicyCreatedBody model
        create_data_policy_created_body_model_json = {}
        create_data_policy_created_body_model_json['data_policy'] = create_data_policy_schema_model
        create_data_policy_created_body_model_json['metadata'] = data_policy_metadata_model
        create_data_policy_created_body_model_json['response'] = success_response_model

        # Construct a model instance of CreateDataPolicyCreatedBody by calling from_dict on the json representation
        create_data_policy_created_body_model = CreateDataPolicyCreatedBody.from_dict(create_data_policy_created_body_model_json)
        assert create_data_policy_created_body_model != False

        # Construct a model instance of CreateDataPolicyCreatedBody by calling from_dict on the json representation
        create_data_policy_created_body_model_dict = CreateDataPolicyCreatedBody.from_dict(create_data_policy_created_body_model_json).__dict__
        create_data_policy_created_body_model2 = CreateDataPolicyCreatedBody(**create_data_policy_created_body_model_dict)

        # Verify the model instances are equivalent
        assert create_data_policy_created_body_model == create_data_policy_created_body_model2

        # Convert model instance back to dict and verify no loss of data
        create_data_policy_created_body_model_json2 = create_data_policy_created_body_model.to_dict()
        assert create_data_policy_created_body_model_json2 == create_data_policy_created_body_model_json


class TestModel_CreateDataPolicySchema:
    """
    Test Class for CreateDataPolicySchema
    """

    def test_create_data_policy_schema_serialization(self):
        """
        Test serialization/deserialization for CreateDataPolicySchema
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rule_grantee_model = {}  # RuleGrantee
        rule_grantee_model['value'] = 'testString'
        rule_grantee_model['key'] = 'user_name'
        rule_grantee_model['type'] = 'user_identity'

        rule_model = {}  # Rule
        rule_model['actions'] = ['all']
        rule_model['effect'] = 'allow'
        rule_model['grantee'] = rule_grantee_model

        # Construct a json representation of a CreateDataPolicySchema model
        create_data_policy_schema_model_json = {}
        create_data_policy_schema_model_json['catalog_name'] = 'testString'
        create_data_policy_schema_model_json['data_artifact'] = 'schema1/table1/(column1|column2)'
        create_data_policy_schema_model_json['description'] = 'testString'
        create_data_policy_schema_model_json['policy_name'] = 'testString'
        create_data_policy_schema_model_json['rules'] = [rule_model]
        create_data_policy_schema_model_json['status'] = 'active'

        # Construct a model instance of CreateDataPolicySchema by calling from_dict on the json representation
        create_data_policy_schema_model = CreateDataPolicySchema.from_dict(create_data_policy_schema_model_json)
        assert create_data_policy_schema_model != False

        # Construct a model instance of CreateDataPolicySchema by calling from_dict on the json representation
        create_data_policy_schema_model_dict = CreateDataPolicySchema.from_dict(create_data_policy_schema_model_json).__dict__
        create_data_policy_schema_model2 = CreateDataPolicySchema(**create_data_policy_schema_model_dict)

        # Verify the model instances are equivalent
        assert create_data_policy_schema_model == create_data_policy_schema_model2

        # Convert model instance back to dict and verify no loss of data
        create_data_policy_schema_model_json2 = create_data_policy_schema_model.to_dict()
        assert create_data_policy_schema_model_json2 == create_data_policy_schema_model_json


class TestModel_DataPolicies:
    """
    Test Class for DataPolicies
    """

    def test_data_policies_serialization(self):
        """
        Test serialization/deserialization for DataPolicies
        """

        # Construct a json representation of a DataPolicies model
        data_policies_model_json = {}
        data_policies_model_json['associate_catalog'] = 'testString'
        data_policies_model_json['policy_name'] = 'testString'
        data_policies_model_json['policy_version'] = 'testString'

        # Construct a model instance of DataPolicies by calling from_dict on the json representation
        data_policies_model = DataPolicies.from_dict(data_policies_model_json)
        assert data_policies_model != False

        # Construct a model instance of DataPolicies by calling from_dict on the json representation
        data_policies_model_dict = DataPolicies.from_dict(data_policies_model_json).__dict__
        data_policies_model2 = DataPolicies(**data_policies_model_dict)

        # Verify the model instances are equivalent
        assert data_policies_model == data_policies_model2

        # Convert model instance back to dict and verify no loss of data
        data_policies_model_json2 = data_policies_model.to_dict()
        assert data_policies_model_json2 == data_policies_model_json


class TestModel_DataPolicyMetadata:
    """
    Test Class for DataPolicyMetadata
    """

    def test_data_policy_metadata_serialization(self):
        """
        Test serialization/deserialization for DataPolicyMetadata
        """

        # Construct a json representation of a DataPolicyMetadata model
        data_policy_metadata_model_json = {}
        data_policy_metadata_model_json['creator'] = 'testString'
        data_policy_metadata_model_json['description'] = 'testString'
        data_policy_metadata_model_json['modifier'] = 'testString'
        data_policy_metadata_model_json['pid'] = 'testString'
        data_policy_metadata_model_json['policy_name'] = 'testString'
        data_policy_metadata_model_json['updated_at'] = 'testString'
        data_policy_metadata_model_json['version'] = 'testString'
        data_policy_metadata_model_json['created_at'] = 'testString'

        # Construct a model instance of DataPolicyMetadata by calling from_dict on the json representation
        data_policy_metadata_model = DataPolicyMetadata.from_dict(data_policy_metadata_model_json)
        assert data_policy_metadata_model != False

        # Construct a model instance of DataPolicyMetadata by calling from_dict on the json representation
        data_policy_metadata_model_dict = DataPolicyMetadata.from_dict(data_policy_metadata_model_json).__dict__
        data_policy_metadata_model2 = DataPolicyMetadata(**data_policy_metadata_model_dict)

        # Verify the model instances are equivalent
        assert data_policy_metadata_model == data_policy_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        data_policy_metadata_model_json2 = data_policy_metadata_model.to_dict()
        assert data_policy_metadata_model_json2 == data_policy_metadata_model_json


class TestModel_DbConnPolicies:
    """
    Test Class for DbConnPolicies
    """

    def test_db_conn_policies_serialization(self):
        """
        Test serialization/deserialization for DbConnPolicies
        """

        # Construct a json representation of a DbConnPolicies model
        db_conn_policies_model_json = {}
        db_conn_policies_model_json['policy_name'] = 'testString'
        db_conn_policies_model_json['policy_version'] = 'testString'

        # Construct a model instance of DbConnPolicies by calling from_dict on the json representation
        db_conn_policies_model = DbConnPolicies.from_dict(db_conn_policies_model_json)
        assert db_conn_policies_model != False

        # Construct a model instance of DbConnPolicies by calling from_dict on the json representation
        db_conn_policies_model_dict = DbConnPolicies.from_dict(db_conn_policies_model_json).__dict__
        db_conn_policies_model2 = DbConnPolicies(**db_conn_policies_model_dict)

        # Verify the model instances are equivalent
        assert db_conn_policies_model == db_conn_policies_model2

        # Convert model instance back to dict and verify no loss of data
        db_conn_policies_model_json2 = db_conn_policies_model.to_dict()
        assert db_conn_policies_model_json2 == db_conn_policies_model_json


class TestModel_DefaultPolicySchema:
    """
    Test Class for DefaultPolicySchema
    """

    def test_default_policy_schema_serialization(self):
        """
        Test serialization/deserialization for DefaultPolicySchema
        """

        # Construct dict forms of any model objects needed in order to build this model.

        grouping_policy_metadata_model = {}  # GroupingPolicyMetadata
        grouping_policy_metadata_model['domain'] = 'testString'
        grouping_policy_metadata_model['inheritor'] = 'testString'
        grouping_policy_metadata_model['role'] = 'testString'

        policy_metadata_model = {}  # PolicyMetadata
        policy_metadata_model['subject'] = 'testString'
        policy_metadata_model['actions'] = ['testString']
        policy_metadata_model['domain'] = 'testString'
        policy_metadata_model['object'] = 'testString'

        # Construct a json representation of a DefaultPolicySchema model
        default_policy_schema_model_json = {}
        default_policy_schema_model_json['grouping_policies'] = [grouping_policy_metadata_model]
        default_policy_schema_model_json['model'] = 'testString'
        default_policy_schema_model_json['policies'] = [policy_metadata_model]

        # Construct a model instance of DefaultPolicySchema by calling from_dict on the json representation
        default_policy_schema_model = DefaultPolicySchema.from_dict(default_policy_schema_model_json)
        assert default_policy_schema_model != False

        # Construct a model instance of DefaultPolicySchema by calling from_dict on the json representation
        default_policy_schema_model_dict = DefaultPolicySchema.from_dict(default_policy_schema_model_json).__dict__
        default_policy_schema_model2 = DefaultPolicySchema(**default_policy_schema_model_dict)

        # Verify the model instances are equivalent
        assert default_policy_schema_model == default_policy_schema_model2

        # Convert model instance back to dict and verify no loss of data
        default_policy_schema_model_json2 = default_policy_schema_model.to_dict()
        assert default_policy_schema_model_json2 == default_policy_schema_model_json


class TestModel_DeleteTableBodyDeleteTablesItems:
    """
    Test Class for DeleteTableBodyDeleteTablesItems
    """

    def test_delete_table_body_delete_tables_items_serialization(self):
        """
        Test serialization/deserialization for DeleteTableBodyDeleteTablesItems
        """

        # Construct a json representation of a DeleteTableBodyDeleteTablesItems model
        delete_table_body_delete_tables_items_model_json = {}
        delete_table_body_delete_tables_items_model_json['catalog_name'] = 'sampleCatalog'
        delete_table_body_delete_tables_items_model_json['schema_name'] = 'new_schema'
        delete_table_body_delete_tables_items_model_json['table_name'] = 'new_table'

        # Construct a model instance of DeleteTableBodyDeleteTablesItems by calling from_dict on the json representation
        delete_table_body_delete_tables_items_model = DeleteTableBodyDeleteTablesItems.from_dict(delete_table_body_delete_tables_items_model_json)
        assert delete_table_body_delete_tables_items_model != False

        # Construct a model instance of DeleteTableBodyDeleteTablesItems by calling from_dict on the json representation
        delete_table_body_delete_tables_items_model_dict = DeleteTableBodyDeleteTablesItems.from_dict(delete_table_body_delete_tables_items_model_json).__dict__
        delete_table_body_delete_tables_items_model2 = DeleteTableBodyDeleteTablesItems(**delete_table_body_delete_tables_items_model_dict)

        # Verify the model instances are equivalent
        assert delete_table_body_delete_tables_items_model == delete_table_body_delete_tables_items_model2

        # Convert model instance back to dict and verify no loss of data
        delete_table_body_delete_tables_items_model_json2 = delete_table_body_delete_tables_items_model.to_dict()
        assert delete_table_body_delete_tables_items_model_json2 == delete_table_body_delete_tables_items_model_json


class TestModel_EngineDetail:
    """
    Test Class for EngineDetail
    """

    def test_engine_detail_serialization(self):
        """
        Test serialization/deserialization for EngineDetail
        """

        # Construct dict forms of any model objects needed in order to build this model.

        node_description_model = {}  # NodeDescription
        node_description_model['node_type'] = 'worker'
        node_description_model['quantity'] = 38

        # Construct a json representation of a EngineDetail model
        engine_detail_model_json = {}
        engine_detail_model_json['group_id'] = 'new_group_id'
        engine_detail_model_json['region'] = 'us-south'
        engine_detail_model_json['size_config'] = 'starter'
        engine_detail_model_json['created_on'] = 38
        engine_detail_model_json['engine_display_name'] = 'sampleEngine'
        engine_detail_model_json['origin'] = 'ibm'
        engine_detail_model_json['port'] = 38
        engine_detail_model_json['type'] = 'presto'
        engine_detail_model_json['version'] = '1.2.0'
        engine_detail_model_json['worker'] = node_description_model
        engine_detail_model_json['actions'] = ['update', 'delete']
        engine_detail_model_json['associated_catalogs'] = ['new_catalog_1', 'new_catalog_2']
        engine_detail_model_json['status'] = 'running'
        engine_detail_model_json['tags'] = ['tag1', 'tag2']
        engine_detail_model_json['coordinator'] = node_description_model
        engine_detail_model_json['created_by'] = '<username>@<domain>.com'
        engine_detail_model_json['host_name'] = 'ibm-lh-presto-svc.com'
        engine_detail_model_json['status_code'] = 38
        engine_detail_model_json['description'] = 'presto engine for running sql queries'
        engine_detail_model_json['engine_id'] = 'sampleEngine123'

        # Construct a model instance of EngineDetail by calling from_dict on the json representation
        engine_detail_model = EngineDetail.from_dict(engine_detail_model_json)
        assert engine_detail_model != False

        # Construct a model instance of EngineDetail by calling from_dict on the json representation
        engine_detail_model_dict = EngineDetail.from_dict(engine_detail_model_json).__dict__
        engine_detail_model2 = EngineDetail(**engine_detail_model_dict)

        # Verify the model instances are equivalent
        assert engine_detail_model == engine_detail_model2

        # Convert model instance back to dict and verify no loss of data
        engine_detail_model_json2 = engine_detail_model.to_dict()
        assert engine_detail_model_json2 == engine_detail_model_json


class TestModel_EngineDetailsBody:
    """
    Test Class for EngineDetailsBody
    """

    def test_engine_details_body_serialization(self):
        """
        Test serialization/deserialization for EngineDetailsBody
        """

        # Construct dict forms of any model objects needed in order to build this model.

        node_description_body_model = {}  # NodeDescriptionBody
        node_description_body_model['node_type'] = 'worker'
        node_description_body_model['quantity'] = 38

        # Construct a json representation of a EngineDetailsBody model
        engine_details_body_model_json = {}
        engine_details_body_model_json['worker'] = node_description_body_model
        engine_details_body_model_json['coordinator'] = node_description_body_model
        engine_details_body_model_json['size_config'] = 'starter'

        # Construct a model instance of EngineDetailsBody by calling from_dict on the json representation
        engine_details_body_model = EngineDetailsBody.from_dict(engine_details_body_model_json)
        assert engine_details_body_model != False

        # Construct a model instance of EngineDetailsBody by calling from_dict on the json representation
        engine_details_body_model_dict = EngineDetailsBody.from_dict(engine_details_body_model_json).__dict__
        engine_details_body_model2 = EngineDetailsBody(**engine_details_body_model_dict)

        # Verify the model instances are equivalent
        assert engine_details_body_model == engine_details_body_model2

        # Convert model instance back to dict and verify no loss of data
        engine_details_body_model_json2 = engine_details_body_model.to_dict()
        assert engine_details_body_model_json2 == engine_details_body_model_json


class TestModel_EngineGroupsMetadata:
    """
    Test Class for EngineGroupsMetadata
    """

    def test_engine_groups_metadata_serialization(self):
        """
        Test serialization/deserialization for EngineGroupsMetadata
        """

        # Construct a json representation of a EngineGroupsMetadata model
        engine_groups_metadata_model_json = {}
        engine_groups_metadata_model_json['group_id'] = 'testString'
        engine_groups_metadata_model_json['permission'] = 'can_administer'

        # Construct a model instance of EngineGroupsMetadata by calling from_dict on the json representation
        engine_groups_metadata_model = EngineGroupsMetadata.from_dict(engine_groups_metadata_model_json)
        assert engine_groups_metadata_model != False

        # Construct a model instance of EngineGroupsMetadata by calling from_dict on the json representation
        engine_groups_metadata_model_dict = EngineGroupsMetadata.from_dict(engine_groups_metadata_model_json).__dict__
        engine_groups_metadata_model2 = EngineGroupsMetadata(**engine_groups_metadata_model_dict)

        # Verify the model instances are equivalent
        assert engine_groups_metadata_model == engine_groups_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        engine_groups_metadata_model_json2 = engine_groups_metadata_model.to_dict()
        assert engine_groups_metadata_model_json2 == engine_groups_metadata_model_json


class TestModel_EnginePolicies:
    """
    Test Class for EnginePolicies
    """

    def test_engine_policies_serialization(self):
        """
        Test serialization/deserialization for EnginePolicies
        """

        # Construct a json representation of a EnginePolicies model
        engine_policies_model_json = {}
        engine_policies_model_json['policy_name'] = 'testString'
        engine_policies_model_json['policy_version'] = 'testString'

        # Construct a model instance of EnginePolicies by calling from_dict on the json representation
        engine_policies_model = EnginePolicies.from_dict(engine_policies_model_json)
        assert engine_policies_model != False

        # Construct a model instance of EnginePolicies by calling from_dict on the json representation
        engine_policies_model_dict = EnginePolicies.from_dict(engine_policies_model_json).__dict__
        engine_policies_model2 = EnginePolicies(**engine_policies_model_dict)

        # Verify the model instances are equivalent
        assert engine_policies_model == engine_policies_model2

        # Convert model instance back to dict and verify no loss of data
        engine_policies_model_json2 = engine_policies_model.to_dict()
        assert engine_policies_model_json2 == engine_policies_model_json


class TestModel_EngineUsersMetadata:
    """
    Test Class for EngineUsersMetadata
    """

    def test_engine_users_metadata_serialization(self):
        """
        Test serialization/deserialization for EngineUsersMetadata
        """

        # Construct a json representation of a EngineUsersMetadata model
        engine_users_metadata_model_json = {}
        engine_users_metadata_model_json['permission'] = 'can_administer'
        engine_users_metadata_model_json['user_name'] = 'testString'

        # Construct a model instance of EngineUsersMetadata by calling from_dict on the json representation
        engine_users_metadata_model = EngineUsersMetadata.from_dict(engine_users_metadata_model_json)
        assert engine_users_metadata_model != False

        # Construct a model instance of EngineUsersMetadata by calling from_dict on the json representation
        engine_users_metadata_model_dict = EngineUsersMetadata.from_dict(engine_users_metadata_model_json).__dict__
        engine_users_metadata_model2 = EngineUsersMetadata(**engine_users_metadata_model_dict)

        # Verify the model instances are equivalent
        assert engine_users_metadata_model == engine_users_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        engine_users_metadata_model_json2 = engine_users_metadata_model.to_dict()
        assert engine_users_metadata_model_json2 == engine_users_metadata_model_json


class TestModel_EvaluationResultSchema:
    """
    Test Class for EvaluationResultSchema
    """

    def test_evaluation_result_schema_serialization(self):
        """
        Test serialization/deserialization for EvaluationResultSchema
        """

        # Construct dict forms of any model objects needed in order to build this model.

        resource_with_result_model = {}  # ResourceWithResult
        resource_with_result_model['action'] = 'testString'
        resource_with_result_model['resource_name'] = 'testString'
        resource_with_result_model['resource_type'] = 'testString'
        resource_with_result_model['result'] = True

        # Construct a json representation of a EvaluationResultSchema model
        evaluation_result_schema_model_json = {}
        evaluation_result_schema_model_json['resources'] = [resource_with_result_model]

        # Construct a model instance of EvaluationResultSchema by calling from_dict on the json representation
        evaluation_result_schema_model = EvaluationResultSchema.from_dict(evaluation_result_schema_model_json)
        assert evaluation_result_schema_model != False

        # Construct a model instance of EvaluationResultSchema by calling from_dict on the json representation
        evaluation_result_schema_model_dict = EvaluationResultSchema.from_dict(evaluation_result_schema_model_json).__dict__
        evaluation_result_schema_model2 = EvaluationResultSchema(**evaluation_result_schema_model_dict)

        # Verify the model instances are equivalent
        assert evaluation_result_schema_model == evaluation_result_schema_model2

        # Convert model instance back to dict and verify no loss of data
        evaluation_result_schema_model_json2 = evaluation_result_schema_model.to_dict()
        assert evaluation_result_schema_model_json2 == evaluation_result_schema_model_json


class TestModel_ExplainAnalyzeStatementCreatedBody:
    """
    Test Class for ExplainAnalyzeStatementCreatedBody
    """

    def test_explain_analyze_statement_created_body_serialization(self):
        """
        Test serialization/deserialization for ExplainAnalyzeStatementCreatedBody
        """

        # Construct dict forms of any model objects needed in order to build this model.

        success_response_model = {}  # SuccessResponse
        success_response_model['_messageCode_'] = '<message code>'
        success_response_model['message'] = 'Success'

        # Construct a json representation of a ExplainAnalyzeStatementCreatedBody model
        explain_analyze_statement_created_body_model_json = {}
        explain_analyze_statement_created_body_model_json['response'] = success_response_model
        explain_analyze_statement_created_body_model_json['result'] = 'testString'

        # Construct a model instance of ExplainAnalyzeStatementCreatedBody by calling from_dict on the json representation
        explain_analyze_statement_created_body_model = ExplainAnalyzeStatementCreatedBody.from_dict(explain_analyze_statement_created_body_model_json)
        assert explain_analyze_statement_created_body_model != False

        # Construct a model instance of ExplainAnalyzeStatementCreatedBody by calling from_dict on the json representation
        explain_analyze_statement_created_body_model_dict = ExplainAnalyzeStatementCreatedBody.from_dict(explain_analyze_statement_created_body_model_json).__dict__
        explain_analyze_statement_created_body_model2 = ExplainAnalyzeStatementCreatedBody(**explain_analyze_statement_created_body_model_dict)

        # Verify the model instances are equivalent
        assert explain_analyze_statement_created_body_model == explain_analyze_statement_created_body_model2

        # Convert model instance back to dict and verify no loss of data
        explain_analyze_statement_created_body_model_json2 = explain_analyze_statement_created_body_model.to_dict()
        assert explain_analyze_statement_created_body_model_json2 == explain_analyze_statement_created_body_model_json


class TestModel_ExplainStatementCreatedBody:
    """
    Test Class for ExplainStatementCreatedBody
    """

    def test_explain_statement_created_body_serialization(self):
        """
        Test serialization/deserialization for ExplainStatementCreatedBody
        """

        # Construct dict forms of any model objects needed in order to build this model.

        success_response_model = {}  # SuccessResponse
        success_response_model['_messageCode_'] = '<message code>'
        success_response_model['message'] = 'Success'

        # Construct a json representation of a ExplainStatementCreatedBody model
        explain_statement_created_body_model_json = {}
        explain_statement_created_body_model_json['response'] = success_response_model
        explain_statement_created_body_model_json['result'] = 'testString'

        # Construct a model instance of ExplainStatementCreatedBody by calling from_dict on the json representation
        explain_statement_created_body_model = ExplainStatementCreatedBody.from_dict(explain_statement_created_body_model_json)
        assert explain_statement_created_body_model != False

        # Construct a model instance of ExplainStatementCreatedBody by calling from_dict on the json representation
        explain_statement_created_body_model_dict = ExplainStatementCreatedBody.from_dict(explain_statement_created_body_model_json).__dict__
        explain_statement_created_body_model2 = ExplainStatementCreatedBody(**explain_statement_created_body_model_dict)

        # Verify the model instances are equivalent
        assert explain_statement_created_body_model == explain_statement_created_body_model2

        # Convert model instance back to dict and verify no loss of data
        explain_statement_created_body_model_json2 = explain_statement_created_body_model.to_dict()
        assert explain_statement_created_body_model_json2 == explain_statement_created_body_model_json


class TestModel_GetBucketObjectsOKBody:
    """
    Test Class for GetBucketObjectsOKBody
    """

    def test_get_bucket_objects_ok_body_serialization(self):
        """
        Test serialization/deserialization for GetBucketObjectsOKBody
        """

        # Construct dict forms of any model objects needed in order to build this model.

        success_response_model = {}  # SuccessResponse
        success_response_model['_messageCode_'] = '<message code>'
        success_response_model['message'] = 'Success'

        # Construct a json representation of a GetBucketObjectsOKBody model
        get_bucket_objects_ok_body_model_json = {}
        get_bucket_objects_ok_body_model_json['objects'] = ['object_1']
        get_bucket_objects_ok_body_model_json['response'] = success_response_model

        # Construct a model instance of GetBucketObjectsOKBody by calling from_dict on the json representation
        get_bucket_objects_ok_body_model = GetBucketObjectsOKBody.from_dict(get_bucket_objects_ok_body_model_json)
        assert get_bucket_objects_ok_body_model != False

        # Construct a model instance of GetBucketObjectsOKBody by calling from_dict on the json representation
        get_bucket_objects_ok_body_model_dict = GetBucketObjectsOKBody.from_dict(get_bucket_objects_ok_body_model_json).__dict__
        get_bucket_objects_ok_body_model2 = GetBucketObjectsOKBody(**get_bucket_objects_ok_body_model_dict)

        # Verify the model instances are equivalent
        assert get_bucket_objects_ok_body_model == get_bucket_objects_ok_body_model2

        # Convert model instance back to dict and verify no loss of data
        get_bucket_objects_ok_body_model_json2 = get_bucket_objects_ok_body_model.to_dict()
        assert get_bucket_objects_ok_body_model_json2 == get_bucket_objects_ok_body_model_json


class TestModel_GetBucketUsersSchema:
    """
    Test Class for GetBucketUsersSchema
    """

    def test_get_bucket_users_schema_serialization(self):
        """
        Test serialization/deserialization for GetBucketUsersSchema
        """

        # Construct dict forms of any model objects needed in order to build this model.

        bucket_db_conn_groups_metadata_model = {}  # BucketDbConnGroupsMetadata
        bucket_db_conn_groups_metadata_model['group_id'] = 'testString'
        bucket_db_conn_groups_metadata_model['permission'] = 'can_administer'

        bucket_db_conn_users_metadata_model = {}  # BucketDbConnUsersMetadata
        bucket_db_conn_users_metadata_model['user_name'] = 'testString'
        bucket_db_conn_users_metadata_model['permission'] = 'can_administer'

        # Construct a json representation of a GetBucketUsersSchema model
        get_bucket_users_schema_model_json = {}
        get_bucket_users_schema_model_json['bucket_id'] = 'testString'
        get_bucket_users_schema_model_json['groups'] = [bucket_db_conn_groups_metadata_model]
        get_bucket_users_schema_model_json['total_count'] = 38
        get_bucket_users_schema_model_json['users'] = [bucket_db_conn_users_metadata_model]

        # Construct a model instance of GetBucketUsersSchema by calling from_dict on the json representation
        get_bucket_users_schema_model = GetBucketUsersSchema.from_dict(get_bucket_users_schema_model_json)
        assert get_bucket_users_schema_model != False

        # Construct a model instance of GetBucketUsersSchema by calling from_dict on the json representation
        get_bucket_users_schema_model_dict = GetBucketUsersSchema.from_dict(get_bucket_users_schema_model_json).__dict__
        get_bucket_users_schema_model2 = GetBucketUsersSchema(**get_bucket_users_schema_model_dict)

        # Verify the model instances are equivalent
        assert get_bucket_users_schema_model == get_bucket_users_schema_model2

        # Convert model instance back to dict and verify no loss of data
        get_bucket_users_schema_model_json2 = get_bucket_users_schema_model.to_dict()
        assert get_bucket_users_schema_model_json2 == get_bucket_users_schema_model_json


class TestModel_GetBucketsOKBody:
    """
    Test Class for GetBucketsOKBody
    """

    def test_get_buckets_ok_body_serialization(self):
        """
        Test serialization/deserialization for GetBucketsOKBody
        """

        # Construct dict forms of any model objects needed in order to build this model.

        bucket_model = {}  # Bucket
        bucket_model['created_by'] = '<username>@<domain>.com'
        bucket_model['created_on'] = '1686120645'
        bucket_model['description'] = 'COS bucket for customer data'
        bucket_model['endpoint'] = 'https://s3.<region>.cloud-object-storage.appdomain.cloud/'
        bucket_model['managed_by'] = 'IBM'
        bucket_model['state'] = 'active'
        bucket_model['tags'] = ['testbucket', 'userbucket']
        bucket_model['associated_catalogs'] = ['samplecatalog1', 'samplecatalog2']
        bucket_model['bucket_display_name'] = 'sample-bucket-displayname'
        bucket_model['bucket_id'] = 'samplebucket123'
        bucket_model['bucket_name'] = 'sample-bucket'
        bucket_model['bucket_type'] = 'ibm_cos'
        bucket_model['actions'] = ['read', 'update']

        success_response_model = {}  # SuccessResponse
        success_response_model['_messageCode_'] = '<message code>'
        success_response_model['message'] = 'Success'

        # Construct a json representation of a GetBucketsOKBody model
        get_buckets_ok_body_model_json = {}
        get_buckets_ok_body_model_json['buckets'] = [bucket_model]
        get_buckets_ok_body_model_json['response'] = success_response_model

        # Construct a model instance of GetBucketsOKBody by calling from_dict on the json representation
        get_buckets_ok_body_model = GetBucketsOKBody.from_dict(get_buckets_ok_body_model_json)
        assert get_buckets_ok_body_model != False

        # Construct a model instance of GetBucketsOKBody by calling from_dict on the json representation
        get_buckets_ok_body_model_dict = GetBucketsOKBody.from_dict(get_buckets_ok_body_model_json).__dict__
        get_buckets_ok_body_model2 = GetBucketsOKBody(**get_buckets_ok_body_model_dict)

        # Verify the model instances are equivalent
        assert get_buckets_ok_body_model == get_buckets_ok_body_model2

        # Convert model instance back to dict and verify no loss of data
        get_buckets_ok_body_model_json2 = get_buckets_ok_body_model.to_dict()
        assert get_buckets_ok_body_model_json2 == get_buckets_ok_body_model_json


class TestModel_GetCatalogUsersSchema:
    """
    Test Class for GetCatalogUsersSchema
    """

    def test_get_catalog_users_schema_serialization(self):
        """
        Test serialization/deserialization for GetCatalogUsersSchema
        """

        # Construct dict forms of any model objects needed in order to build this model.

        catalog_users_metadata_model = {}  # CatalogUsersMetadata
        catalog_users_metadata_model['permission'] = 'can_administer'
        catalog_users_metadata_model['user_name'] = 'testString'

        catalog_groups_metadata_model = {}  # CatalogGroupsMetadata
        catalog_groups_metadata_model['group_id'] = 'testString'
        catalog_groups_metadata_model['permission'] = 'can_administer'

        # Construct a json representation of a GetCatalogUsersSchema model
        get_catalog_users_schema_model_json = {}
        get_catalog_users_schema_model_json['total_count'] = 38
        get_catalog_users_schema_model_json['users'] = [catalog_users_metadata_model]
        get_catalog_users_schema_model_json['catalog_name'] = 'testString'
        get_catalog_users_schema_model_json['groups'] = [catalog_groups_metadata_model]

        # Construct a model instance of GetCatalogUsersSchema by calling from_dict on the json representation
        get_catalog_users_schema_model = GetCatalogUsersSchema.from_dict(get_catalog_users_schema_model_json)
        assert get_catalog_users_schema_model != False

        # Construct a model instance of GetCatalogUsersSchema by calling from_dict on the json representation
        get_catalog_users_schema_model_dict = GetCatalogUsersSchema.from_dict(get_catalog_users_schema_model_json).__dict__
        get_catalog_users_schema_model2 = GetCatalogUsersSchema(**get_catalog_users_schema_model_dict)

        # Verify the model instances are equivalent
        assert get_catalog_users_schema_model == get_catalog_users_schema_model2

        # Convert model instance back to dict and verify no loss of data
        get_catalog_users_schema_model_json2 = get_catalog_users_schema_model.to_dict()
        assert get_catalog_users_schema_model_json2 == get_catalog_users_schema_model_json


class TestModel_GetDbConnUsersSchema:
    """
    Test Class for GetDbConnUsersSchema
    """

    def test_get_db_conn_users_schema_serialization(self):
        """
        Test serialization/deserialization for GetDbConnUsersSchema
        """

        # Construct dict forms of any model objects needed in order to build this model.

        bucket_db_conn_groups_metadata_model = {}  # BucketDbConnGroupsMetadata
        bucket_db_conn_groups_metadata_model['group_id'] = 'testString'
        bucket_db_conn_groups_metadata_model['permission'] = 'can_administer'

        bucket_db_conn_users_metadata_model = {}  # BucketDbConnUsersMetadata
        bucket_db_conn_users_metadata_model['user_name'] = 'testString'
        bucket_db_conn_users_metadata_model['permission'] = 'can_administer'

        # Construct a json representation of a GetDbConnUsersSchema model
        get_db_conn_users_schema_model_json = {}
        get_db_conn_users_schema_model_json['groups'] = [bucket_db_conn_groups_metadata_model]
        get_db_conn_users_schema_model_json['total_count'] = 38
        get_db_conn_users_schema_model_json['users'] = [bucket_db_conn_users_metadata_model]
        get_db_conn_users_schema_model_json['database_id'] = 'testString'

        # Construct a model instance of GetDbConnUsersSchema by calling from_dict on the json representation
        get_db_conn_users_schema_model = GetDbConnUsersSchema.from_dict(get_db_conn_users_schema_model_json)
        assert get_db_conn_users_schema_model != False

        # Construct a model instance of GetDbConnUsersSchema by calling from_dict on the json representation
        get_db_conn_users_schema_model_dict = GetDbConnUsersSchema.from_dict(get_db_conn_users_schema_model_json).__dict__
        get_db_conn_users_schema_model2 = GetDbConnUsersSchema(**get_db_conn_users_schema_model_dict)

        # Verify the model instances are equivalent
        assert get_db_conn_users_schema_model == get_db_conn_users_schema_model2

        # Convert model instance back to dict and verify no loss of data
        get_db_conn_users_schema_model_json2 = get_db_conn_users_schema_model.to_dict()
        assert get_db_conn_users_schema_model_json2 == get_db_conn_users_schema_model_json


class TestModel_GetEngineUsersSchema:
    """
    Test Class for GetEngineUsersSchema
    """

    def test_get_engine_users_schema_serialization(self):
        """
        Test serialization/deserialization for GetEngineUsersSchema
        """

        # Construct dict forms of any model objects needed in order to build this model.

        engine_groups_metadata_model = {}  # EngineGroupsMetadata
        engine_groups_metadata_model['group_id'] = 'testString'
        engine_groups_metadata_model['permission'] = 'can_administer'

        engine_users_metadata_model = {}  # EngineUsersMetadata
        engine_users_metadata_model['permission'] = 'can_administer'
        engine_users_metadata_model['user_name'] = 'testString'

        # Construct a json representation of a GetEngineUsersSchema model
        get_engine_users_schema_model_json = {}
        get_engine_users_schema_model_json['engine_id'] = 'testString'
        get_engine_users_schema_model_json['groups'] = [engine_groups_metadata_model]
        get_engine_users_schema_model_json['total_count'] = 38
        get_engine_users_schema_model_json['users'] = [engine_users_metadata_model]

        # Construct a model instance of GetEngineUsersSchema by calling from_dict on the json representation
        get_engine_users_schema_model = GetEngineUsersSchema.from_dict(get_engine_users_schema_model_json)
        assert get_engine_users_schema_model != False

        # Construct a model instance of GetEngineUsersSchema by calling from_dict on the json representation
        get_engine_users_schema_model_dict = GetEngineUsersSchema.from_dict(get_engine_users_schema_model_json).__dict__
        get_engine_users_schema_model2 = GetEngineUsersSchema(**get_engine_users_schema_model_dict)

        # Verify the model instances are equivalent
        assert get_engine_users_schema_model == get_engine_users_schema_model2

        # Convert model instance back to dict and verify no loss of data
        get_engine_users_schema_model_json2 = get_engine_users_schema_model.to_dict()
        assert get_engine_users_schema_model_json2 == get_engine_users_schema_model_json


class TestModel_GetEnginesOKBody:
    """
    Test Class for GetEnginesOKBody
    """

    def test_get_engines_ok_body_serialization(self):
        """
        Test serialization/deserialization for GetEnginesOKBody
        """

        # Construct dict forms of any model objects needed in order to build this model.

        node_description_model = {}  # NodeDescription
        node_description_model['node_type'] = 'worker'
        node_description_model['quantity'] = 38

        engine_detail_model = {}  # EngineDetail
        engine_detail_model['group_id'] = 'new_group_id'
        engine_detail_model['region'] = 'us-south'
        engine_detail_model['size_config'] = 'starter'
        engine_detail_model['created_on'] = 38
        engine_detail_model['engine_display_name'] = 'sampleEngine'
        engine_detail_model['origin'] = 'ibm'
        engine_detail_model['port'] = 38
        engine_detail_model['type'] = 'presto'
        engine_detail_model['version'] = '1.2.0'
        engine_detail_model['worker'] = node_description_model
        engine_detail_model['actions'] = ['update', 'delete']
        engine_detail_model['associated_catalogs'] = ['new_catalog_1', 'new_catalog_2']
        engine_detail_model['status'] = 'running'
        engine_detail_model['tags'] = ['tag1', 'tag2']
        engine_detail_model['coordinator'] = node_description_model
        engine_detail_model['created_by'] = '<username>@<domain>.com'
        engine_detail_model['host_name'] = 'ibm-lh-presto-svc.com'
        engine_detail_model['status_code'] = 38
        engine_detail_model['description'] = 'presto engine for running sql queries'
        engine_detail_model['engine_id'] = 'sampleEngine123'

        success_response_model = {}  # SuccessResponse
        success_response_model['_messageCode_'] = '<message code>'
        success_response_model['message'] = 'Success'

        # Construct a json representation of a GetEnginesOKBody model
        get_engines_ok_body_model_json = {}
        get_engines_ok_body_model_json['engines'] = [engine_detail_model]
        get_engines_ok_body_model_json['response'] = success_response_model

        # Construct a model instance of GetEnginesOKBody by calling from_dict on the json representation
        get_engines_ok_body_model = GetEnginesOKBody.from_dict(get_engines_ok_body_model_json)
        assert get_engines_ok_body_model != False

        # Construct a model instance of GetEnginesOKBody by calling from_dict on the json representation
        get_engines_ok_body_model_dict = GetEnginesOKBody.from_dict(get_engines_ok_body_model_json).__dict__
        get_engines_ok_body_model2 = GetEnginesOKBody(**get_engines_ok_body_model_dict)

        # Verify the model instances are equivalent
        assert get_engines_ok_body_model == get_engines_ok_body_model2

        # Convert model instance back to dict and verify no loss of data
        get_engines_ok_body_model_json2 = get_engines_ok_body_model.to_dict()
        assert get_engines_ok_body_model_json2 == get_engines_ok_body_model_json


class TestModel_GetMetastoreUsersSchema:
    """
    Test Class for GetMetastoreUsersSchema
    """

    def test_get_metastore_users_schema_serialization(self):
        """
        Test serialization/deserialization for GetMetastoreUsersSchema
        """

        # Construct dict forms of any model objects needed in order to build this model.

        groups_metadata_model = {}  # GroupsMetadata
        groups_metadata_model['group_id'] = 'testString'
        groups_metadata_model['permission'] = 'can_administer'

        users_metadata_model = {}  # UsersMetadata
        users_metadata_model['permission'] = 'can_administer'
        users_metadata_model['user_name'] = 'testString'

        # Construct a json representation of a GetMetastoreUsersSchema model
        get_metastore_users_schema_model_json = {}
        get_metastore_users_schema_model_json['groups'] = [groups_metadata_model]
        get_metastore_users_schema_model_json['metastore_name'] = 'testString'
        get_metastore_users_schema_model_json['total_count'] = 38
        get_metastore_users_schema_model_json['users'] = [users_metadata_model]

        # Construct a model instance of GetMetastoreUsersSchema by calling from_dict on the json representation
        get_metastore_users_schema_model = GetMetastoreUsersSchema.from_dict(get_metastore_users_schema_model_json)
        assert get_metastore_users_schema_model != False

        # Construct a model instance of GetMetastoreUsersSchema by calling from_dict on the json representation
        get_metastore_users_schema_model_dict = GetMetastoreUsersSchema.from_dict(get_metastore_users_schema_model_json).__dict__
        get_metastore_users_schema_model2 = GetMetastoreUsersSchema(**get_metastore_users_schema_model_dict)

        # Verify the model instances are equivalent
        assert get_metastore_users_schema_model == get_metastore_users_schema_model2

        # Convert model instance back to dict and verify no loss of data
        get_metastore_users_schema_model_json2 = get_metastore_users_schema_model.to_dict()
        assert get_metastore_users_schema_model_json2 == get_metastore_users_schema_model_json


class TestModel_GetMetastoresOKBody:
    """
    Test Class for GetMetastoresOKBody
    """

    def test_get_metastores_ok_body_serialization(self):
        """
        Test serialization/deserialization for GetMetastoresOKBody
        """

        # Construct dict forms of any model objects needed in order to build this model.

        metastore_model = {}  # Metastore
        metastore_model['catalog_name'] = 'sampleCatalog'
        metastore_model['hostname'] = 's3a://samplehost.com'
        metastore_model['managed_by'] = 'ibm'
        metastore_model['status'] = 'running'
        metastore_model['tags'] = ['tag1', 'tag2']
        metastore_model['actions'] = ['update', 'delete']
        metastore_model['associated_buckets'] = ['bucket_1', 'bucket_2']
        metastore_model['created_by'] = '<username>@<domain>.com'
        metastore_model['thrift_uri'] = 'thrift://samplehost-metastore:4354'
        metastore_model['catalog_type'] = 'iceberg'
        metastore_model['description'] = 'Iceberg catalog description'
        metastore_model['associated_databases'] = ['database_1', 'database_2']
        metastore_model['associated_engines'] = ['engine_1', 'engine_2']
        metastore_model['created_on'] = '1602839833'
        metastore_model['port'] = '3232'

        success_response_model = {}  # SuccessResponse
        success_response_model['_messageCode_'] = '<message code>'
        success_response_model['message'] = 'Success'

        # Construct a json representation of a GetMetastoresOKBody model
        get_metastores_ok_body_model_json = {}
        get_metastores_ok_body_model_json['catalogs'] = [metastore_model]
        get_metastores_ok_body_model_json['response'] = success_response_model

        # Construct a model instance of GetMetastoresOKBody by calling from_dict on the json representation
        get_metastores_ok_body_model = GetMetastoresOKBody.from_dict(get_metastores_ok_body_model_json)
        assert get_metastores_ok_body_model != False

        # Construct a model instance of GetMetastoresOKBody by calling from_dict on the json representation
        get_metastores_ok_body_model_dict = GetMetastoresOKBody.from_dict(get_metastores_ok_body_model_json).__dict__
        get_metastores_ok_body_model2 = GetMetastoresOKBody(**get_metastores_ok_body_model_dict)

        # Verify the model instances are equivalent
        assert get_metastores_ok_body_model == get_metastores_ok_body_model2

        # Convert model instance back to dict and verify no loss of data
        get_metastores_ok_body_model_json2 = get_metastores_ok_body_model.to_dict()
        assert get_metastores_ok_body_model_json2 == get_metastores_ok_body_model_json


class TestModel_GetQueriesOKBody:
    """
    Test Class for GetQueriesOKBody
    """

    def test_get_queries_ok_body_serialization(self):
        """
        Test serialization/deserialization for GetQueriesOKBody
        """

        # Construct dict forms of any model objects needed in order to build this model.

        query_model = {}  # Query
        query_model['created_by'] = '<username>@<domain>.com'
        query_model['created_on'] = '1608437933'
        query_model['description'] = 'query to get expense data'
        query_model['engine_id'] = 'sampleEngine123'
        query_model['query_name'] = 'new_query_name'
        query_model['query_string'] = 'select expenses from expenditure'

        success_response_model = {}  # SuccessResponse
        success_response_model['_messageCode_'] = '<message code>'
        success_response_model['message'] = 'Success'

        # Construct a json representation of a GetQueriesOKBody model
        get_queries_ok_body_model_json = {}
        get_queries_ok_body_model_json['queries'] = [query_model]
        get_queries_ok_body_model_json['response'] = success_response_model

        # Construct a model instance of GetQueriesOKBody by calling from_dict on the json representation
        get_queries_ok_body_model = GetQueriesOKBody.from_dict(get_queries_ok_body_model_json)
        assert get_queries_ok_body_model != False

        # Construct a model instance of GetQueriesOKBody by calling from_dict on the json representation
        get_queries_ok_body_model_dict = GetQueriesOKBody.from_dict(get_queries_ok_body_model_json).__dict__
        get_queries_ok_body_model2 = GetQueriesOKBody(**get_queries_ok_body_model_dict)

        # Verify the model instances are equivalent
        assert get_queries_ok_body_model == get_queries_ok_body_model2

        # Convert model instance back to dict and verify no loss of data
        get_queries_ok_body_model_json2 = get_queries_ok_body_model.to_dict()
        assert get_queries_ok_body_model_json2 == get_queries_ok_body_model_json


class TestModel_GetSchemasOKBody:
    """
    Test Class for GetSchemasOKBody
    """

    def test_get_schemas_ok_body_serialization(self):
        """
        Test serialization/deserialization for GetSchemasOKBody
        """

        # Construct dict forms of any model objects needed in order to build this model.

        success_response_model = {}  # SuccessResponse
        success_response_model['_messageCode_'] = '<message code>'
        success_response_model['message'] = 'Success'

        # Construct a json representation of a GetSchemasOKBody model
        get_schemas_ok_body_model_json = {}
        get_schemas_ok_body_model_json['response'] = success_response_model
        get_schemas_ok_body_model_json['schemas'] = ['testString']

        # Construct a model instance of GetSchemasOKBody by calling from_dict on the json representation
        get_schemas_ok_body_model = GetSchemasOKBody.from_dict(get_schemas_ok_body_model_json)
        assert get_schemas_ok_body_model != False

        # Construct a model instance of GetSchemasOKBody by calling from_dict on the json representation
        get_schemas_ok_body_model_dict = GetSchemasOKBody.from_dict(get_schemas_ok_body_model_json).__dict__
        get_schemas_ok_body_model2 = GetSchemasOKBody(**get_schemas_ok_body_model_dict)

        # Verify the model instances are equivalent
        assert get_schemas_ok_body_model == get_schemas_ok_body_model2

        # Convert model instance back to dict and verify no loss of data
        get_schemas_ok_body_model_json2 = get_schemas_ok_body_model.to_dict()
        assert get_schemas_ok_body_model_json2 == get_schemas_ok_body_model_json


class TestModel_GetTableSnapshotsOKBody:
    """
    Test Class for GetTableSnapshotsOKBody
    """

    def test_get_table_snapshots_ok_body_serialization(self):
        """
        Test serialization/deserialization for GetTableSnapshotsOKBody
        """

        # Construct dict forms of any model objects needed in order to build this model.

        success_response_model = {}  # SuccessResponse
        success_response_model['_messageCode_'] = '<message code>'
        success_response_model['message'] = 'Success'

        table_snapshot_model = {}  # TableSnapshot
        table_snapshot_model['operation'] = 'alter'
        table_snapshot_model['snapshot_id'] = '2332342122211222'
        table_snapshot_model['summary'] = {'anyKey': 'anyValue'}
        table_snapshot_model['committed_at'] = '1609379392'

        # Construct a json representation of a GetTableSnapshotsOKBody model
        get_table_snapshots_ok_body_model_json = {}
        get_table_snapshots_ok_body_model_json['response'] = success_response_model
        get_table_snapshots_ok_body_model_json['snapshots'] = [table_snapshot_model]

        # Construct a model instance of GetTableSnapshotsOKBody by calling from_dict on the json representation
        get_table_snapshots_ok_body_model = GetTableSnapshotsOKBody.from_dict(get_table_snapshots_ok_body_model_json)
        assert get_table_snapshots_ok_body_model != False

        # Construct a model instance of GetTableSnapshotsOKBody by calling from_dict on the json representation
        get_table_snapshots_ok_body_model_dict = GetTableSnapshotsOKBody.from_dict(get_table_snapshots_ok_body_model_json).__dict__
        get_table_snapshots_ok_body_model2 = GetTableSnapshotsOKBody(**get_table_snapshots_ok_body_model_dict)

        # Verify the model instances are equivalent
        assert get_table_snapshots_ok_body_model == get_table_snapshots_ok_body_model2

        # Convert model instance back to dict and verify no loss of data
        get_table_snapshots_ok_body_model_json2 = get_table_snapshots_ok_body_model.to_dict()
        assert get_table_snapshots_ok_body_model_json2 == get_table_snapshots_ok_body_model_json


class TestModel_GetTablesOKBody:
    """
    Test Class for GetTablesOKBody
    """

    def test_get_tables_ok_body_serialization(self):
        """
        Test serialization/deserialization for GetTablesOKBody
        """

        # Construct dict forms of any model objects needed in order to build this model.

        success_response_model = {}  # SuccessResponse
        success_response_model['_messageCode_'] = '<message code>'
        success_response_model['message'] = 'Success'

        # Construct a json representation of a GetTablesOKBody model
        get_tables_ok_body_model_json = {}
        get_tables_ok_body_model_json['response'] = success_response_model
        get_tables_ok_body_model_json['tables'] = ['table1', 'table2']

        # Construct a model instance of GetTablesOKBody by calling from_dict on the json representation
        get_tables_ok_body_model = GetTablesOKBody.from_dict(get_tables_ok_body_model_json)
        assert get_tables_ok_body_model != False

        # Construct a model instance of GetTablesOKBody by calling from_dict on the json representation
        get_tables_ok_body_model_dict = GetTablesOKBody.from_dict(get_tables_ok_body_model_json).__dict__
        get_tables_ok_body_model2 = GetTablesOKBody(**get_tables_ok_body_model_dict)

        # Verify the model instances are equivalent
        assert get_tables_ok_body_model == get_tables_ok_body_model2

        # Convert model instance back to dict and verify no loss of data
        get_tables_ok_body_model_json2 = get_tables_ok_body_model.to_dict()
        assert get_tables_ok_body_model_json2 == get_tables_ok_body_model_json


class TestModel_GroupingPolicyMetadata:
    """
    Test Class for GroupingPolicyMetadata
    """

    def test_grouping_policy_metadata_serialization(self):
        """
        Test serialization/deserialization for GroupingPolicyMetadata
        """

        # Construct a json representation of a GroupingPolicyMetadata model
        grouping_policy_metadata_model_json = {}
        grouping_policy_metadata_model_json['domain'] = 'testString'
        grouping_policy_metadata_model_json['inheritor'] = 'testString'
        grouping_policy_metadata_model_json['role'] = 'testString'

        # Construct a model instance of GroupingPolicyMetadata by calling from_dict on the json representation
        grouping_policy_metadata_model = GroupingPolicyMetadata.from_dict(grouping_policy_metadata_model_json)
        assert grouping_policy_metadata_model != False

        # Construct a model instance of GroupingPolicyMetadata by calling from_dict on the json representation
        grouping_policy_metadata_model_dict = GroupingPolicyMetadata.from_dict(grouping_policy_metadata_model_json).__dict__
        grouping_policy_metadata_model2 = GroupingPolicyMetadata(**grouping_policy_metadata_model_dict)

        # Verify the model instances are equivalent
        assert grouping_policy_metadata_model == grouping_policy_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        grouping_policy_metadata_model_json2 = grouping_policy_metadata_model.to_dict()
        assert grouping_policy_metadata_model_json2 == grouping_policy_metadata_model_json


class TestModel_GroupsMetadata:
    """
    Test Class for GroupsMetadata
    """

    def test_groups_metadata_serialization(self):
        """
        Test serialization/deserialization for GroupsMetadata
        """

        # Construct a json representation of a GroupsMetadata model
        groups_metadata_model_json = {}
        groups_metadata_model_json['group_id'] = 'testString'
        groups_metadata_model_json['permission'] = 'can_administer'

        # Construct a model instance of GroupsMetadata by calling from_dict on the json representation
        groups_metadata_model = GroupsMetadata.from_dict(groups_metadata_model_json)
        assert groups_metadata_model != False

        # Construct a model instance of GroupsMetadata by calling from_dict on the json representation
        groups_metadata_model_dict = GroupsMetadata.from_dict(groups_metadata_model_json).__dict__
        groups_metadata_model2 = GroupsMetadata(**groups_metadata_model_dict)

        # Verify the model instances are equivalent
        assert groups_metadata_model == groups_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        groups_metadata_model_json2 = groups_metadata_model.to_dict()
        assert groups_metadata_model_json2 == groups_metadata_model_json


class TestModel_Metastore:
    """
    Test Class for Metastore
    """

    def test_metastore_serialization(self):
        """
        Test serialization/deserialization for Metastore
        """

        # Construct a json representation of a Metastore model
        metastore_model_json = {}
        metastore_model_json['catalog_name'] = 'sampleCatalog'
        metastore_model_json['hostname'] = 's3a://samplehost.com'
        metastore_model_json['managed_by'] = 'ibm'
        metastore_model_json['status'] = 'running'
        metastore_model_json['tags'] = ['tag1', 'tag2']
        metastore_model_json['actions'] = ['update', 'delete']
        metastore_model_json['associated_buckets'] = ['bucket_1', 'bucket_2']
        metastore_model_json['created_by'] = '<username>@<domain>.com'
        metastore_model_json['thrift_uri'] = 'thrift://samplehost-metastore:4354'
        metastore_model_json['catalog_type'] = 'iceberg'
        metastore_model_json['description'] = 'Iceberg catalog description'
        metastore_model_json['associated_databases'] = ['database_1', 'database_2']
        metastore_model_json['associated_engines'] = ['engine_1', 'engine_2']
        metastore_model_json['created_on'] = '1602839833'
        metastore_model_json['port'] = '3232'

        # Construct a model instance of Metastore by calling from_dict on the json representation
        metastore_model = Metastore.from_dict(metastore_model_json)
        assert metastore_model != False

        # Construct a model instance of Metastore by calling from_dict on the json representation
        metastore_model_dict = Metastore.from_dict(metastore_model_json).__dict__
        metastore_model2 = Metastore(**metastore_model_dict)

        # Verify the model instances are equivalent
        assert metastore_model == metastore_model2

        # Convert model instance back to dict and verify no loss of data
        metastore_model_json2 = metastore_model.to_dict()
        assert metastore_model_json2 == metastore_model_json


class TestModel_NodeDescription:
    """
    Test Class for NodeDescription
    """

    def test_node_description_serialization(self):
        """
        Test serialization/deserialization for NodeDescription
        """

        # Construct a json representation of a NodeDescription model
        node_description_model_json = {}
        node_description_model_json['node_type'] = 'worker'
        node_description_model_json['quantity'] = 38

        # Construct a model instance of NodeDescription by calling from_dict on the json representation
        node_description_model = NodeDescription.from_dict(node_description_model_json)
        assert node_description_model != False

        # Construct a model instance of NodeDescription by calling from_dict on the json representation
        node_description_model_dict = NodeDescription.from_dict(node_description_model_json).__dict__
        node_description_model2 = NodeDescription(**node_description_model_dict)

        # Verify the model instances are equivalent
        assert node_description_model == node_description_model2

        # Convert model instance back to dict and verify no loss of data
        node_description_model_json2 = node_description_model.to_dict()
        assert node_description_model_json2 == node_description_model_json


class TestModel_NodeDescriptionBody:
    """
    Test Class for NodeDescriptionBody
    """

    def test_node_description_body_serialization(self):
        """
        Test serialization/deserialization for NodeDescriptionBody
        """

        # Construct a json representation of a NodeDescriptionBody model
        node_description_body_model_json = {}
        node_description_body_model_json['node_type'] = 'worker'
        node_description_body_model_json['quantity'] = 38

        # Construct a model instance of NodeDescriptionBody by calling from_dict on the json representation
        node_description_body_model = NodeDescriptionBody.from_dict(node_description_body_model_json)
        assert node_description_body_model != False

        # Construct a model instance of NodeDescriptionBody by calling from_dict on the json representation
        node_description_body_model_dict = NodeDescriptionBody.from_dict(node_description_body_model_json).__dict__
        node_description_body_model2 = NodeDescriptionBody(**node_description_body_model_dict)

        # Verify the model instances are equivalent
        assert node_description_body_model == node_description_body_model2

        # Convert model instance back to dict and verify no loss of data
        node_description_body_model_json2 = node_description_body_model.to_dict()
        assert node_description_body_model_json2 == node_description_body_model_json


class TestModel_PauseEngineCreatedBody:
    """
    Test Class for PauseEngineCreatedBody
    """

    def test_pause_engine_created_body_serialization(self):
        """
        Test serialization/deserialization for PauseEngineCreatedBody
        """

        # Construct dict forms of any model objects needed in order to build this model.

        success_response_model = {}  # SuccessResponse
        success_response_model['_messageCode_'] = '<message code>'
        success_response_model['message'] = 'Success'

        # Construct a json representation of a PauseEngineCreatedBody model
        pause_engine_created_body_model_json = {}
        pause_engine_created_body_model_json['response'] = success_response_model

        # Construct a model instance of PauseEngineCreatedBody by calling from_dict on the json representation
        pause_engine_created_body_model = PauseEngineCreatedBody.from_dict(pause_engine_created_body_model_json)
        assert pause_engine_created_body_model != False

        # Construct a model instance of PauseEngineCreatedBody by calling from_dict on the json representation
        pause_engine_created_body_model_dict = PauseEngineCreatedBody.from_dict(pause_engine_created_body_model_json).__dict__
        pause_engine_created_body_model2 = PauseEngineCreatedBody(**pause_engine_created_body_model_dict)

        # Verify the model instances are equivalent
        assert pause_engine_created_body_model == pause_engine_created_body_model2

        # Convert model instance back to dict and verify no loss of data
        pause_engine_created_body_model_json2 = pause_engine_created_body_model.to_dict()
        assert pause_engine_created_body_model_json2 == pause_engine_created_body_model_json


class TestModel_PolicyListSchema:
    """
    Test Class for PolicyListSchema
    """

    def test_policy_list_schema_serialization(self):
        """
        Test serialization/deserialization for PolicyListSchema
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rule_grantee_model = {}  # RuleGrantee
        rule_grantee_model['value'] = 'testString'
        rule_grantee_model['key'] = 'user_name'
        rule_grantee_model['type'] = 'user_identity'

        rule_model = {}  # Rule
        rule_model['actions'] = ['all']
        rule_model['effect'] = 'allow'
        rule_model['grantee'] = rule_grantee_model

        data_policy_metadata_model = {}  # DataPolicyMetadata
        data_policy_metadata_model['creator'] = 'testString'
        data_policy_metadata_model['description'] = 'testString'
        data_policy_metadata_model['modifier'] = 'testString'
        data_policy_metadata_model['pid'] = 'testString'
        data_policy_metadata_model['policy_name'] = 'testString'
        data_policy_metadata_model['updated_at'] = 'testString'
        data_policy_metadata_model['version'] = 'testString'
        data_policy_metadata_model['created_at'] = 'testString'

        policy_schema_model = {}  # PolicySchema
        policy_schema_model['rule_count'] = 38
        policy_schema_model['rules'] = [rule_model]
        policy_schema_model['status'] = 'active'
        policy_schema_model['catalog_name'] = 'testString'
        policy_schema_model['data_artifact'] = 'schema1/table1/(column1|column2)'
        policy_schema_model['metadata'] = data_policy_metadata_model
        policy_schema_model['policy_name'] = 'testString'

        # Construct a json representation of a PolicyListSchema model
        policy_list_schema_model_json = {}
        policy_list_schema_model_json['policies'] = [policy_schema_model]
        policy_list_schema_model_json['total_count'] = 38

        # Construct a model instance of PolicyListSchema by calling from_dict on the json representation
        policy_list_schema_model = PolicyListSchema.from_dict(policy_list_schema_model_json)
        assert policy_list_schema_model != False

        # Construct a model instance of PolicyListSchema by calling from_dict on the json representation
        policy_list_schema_model_dict = PolicyListSchema.from_dict(policy_list_schema_model_json).__dict__
        policy_list_schema_model2 = PolicyListSchema(**policy_list_schema_model_dict)

        # Verify the model instances are equivalent
        assert policy_list_schema_model == policy_list_schema_model2

        # Convert model instance back to dict and verify no loss of data
        policy_list_schema_model_json2 = policy_list_schema_model.to_dict()
        assert policy_list_schema_model_json2 == policy_list_schema_model_json


class TestModel_PolicyMetadata:
    """
    Test Class for PolicyMetadata
    """

    def test_policy_metadata_serialization(self):
        """
        Test serialization/deserialization for PolicyMetadata
        """

        # Construct a json representation of a PolicyMetadata model
        policy_metadata_model_json = {}
        policy_metadata_model_json['subject'] = 'testString'
        policy_metadata_model_json['actions'] = ['testString']
        policy_metadata_model_json['domain'] = 'testString'
        policy_metadata_model_json['object'] = 'testString'

        # Construct a model instance of PolicyMetadata by calling from_dict on the json representation
        policy_metadata_model = PolicyMetadata.from_dict(policy_metadata_model_json)
        assert policy_metadata_model != False

        # Construct a model instance of PolicyMetadata by calling from_dict on the json representation
        policy_metadata_model_dict = PolicyMetadata.from_dict(policy_metadata_model_json).__dict__
        policy_metadata_model2 = PolicyMetadata(**policy_metadata_model_dict)

        # Verify the model instances are equivalent
        assert policy_metadata_model == policy_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        policy_metadata_model_json2 = policy_metadata_model.to_dict()
        assert policy_metadata_model_json2 == policy_metadata_model_json


class TestModel_PolicySchema:
    """
    Test Class for PolicySchema
    """

    def test_policy_schema_serialization(self):
        """
        Test serialization/deserialization for PolicySchema
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rule_grantee_model = {}  # RuleGrantee
        rule_grantee_model['value'] = 'testString'
        rule_grantee_model['key'] = 'user_name'
        rule_grantee_model['type'] = 'user_identity'

        rule_model = {}  # Rule
        rule_model['actions'] = ['all']
        rule_model['effect'] = 'allow'
        rule_model['grantee'] = rule_grantee_model

        data_policy_metadata_model = {}  # DataPolicyMetadata
        data_policy_metadata_model['creator'] = 'testString'
        data_policy_metadata_model['description'] = 'testString'
        data_policy_metadata_model['modifier'] = 'testString'
        data_policy_metadata_model['pid'] = 'testString'
        data_policy_metadata_model['policy_name'] = 'testString'
        data_policy_metadata_model['updated_at'] = 'testString'
        data_policy_metadata_model['version'] = 'testString'
        data_policy_metadata_model['created_at'] = 'testString'

        # Construct a json representation of a PolicySchema model
        policy_schema_model_json = {}
        policy_schema_model_json['rule_count'] = 38
        policy_schema_model_json['rules'] = [rule_model]
        policy_schema_model_json['status'] = 'active'
        policy_schema_model_json['catalog_name'] = 'testString'
        policy_schema_model_json['data_artifact'] = 'schema1/table1/(column1|column2)'
        policy_schema_model_json['metadata'] = data_policy_metadata_model
        policy_schema_model_json['policy_name'] = 'testString'

        # Construct a model instance of PolicySchema by calling from_dict on the json representation
        policy_schema_model = PolicySchema.from_dict(policy_schema_model_json)
        assert policy_schema_model != False

        # Construct a model instance of PolicySchema by calling from_dict on the json representation
        policy_schema_model_dict = PolicySchema.from_dict(policy_schema_model_json).__dict__
        policy_schema_model2 = PolicySchema(**policy_schema_model_dict)

        # Verify the model instances are equivalent
        assert policy_schema_model == policy_schema_model2

        # Convert model instance back to dict and verify no loss of data
        policy_schema_model_json2 = policy_schema_model.to_dict()
        assert policy_schema_model_json2 == policy_schema_model_json


class TestModel_PolicySchemaList:
    """
    Test Class for PolicySchemaList
    """

    def test_policy_schema_list_serialization(self):
        """
        Test serialization/deserialization for PolicySchemaList
        """

        # Construct dict forms of any model objects needed in order to build this model.

        catalog_users_metadata_model = {}  # CatalogUsersMetadata
        catalog_users_metadata_model['permission'] = 'can_administer'
        catalog_users_metadata_model['user_name'] = 'testString'

        catalog_groups_metadata_model = {}  # CatalogGroupsMetadata
        catalog_groups_metadata_model['group_id'] = 'testString'
        catalog_groups_metadata_model['permission'] = 'can_administer'

        get_catalog_users_schema_model = {}  # GetCatalogUsersSchema
        get_catalog_users_schema_model['total_count'] = 38
        get_catalog_users_schema_model['users'] = [catalog_users_metadata_model]
        get_catalog_users_schema_model['catalog_name'] = 'testString'
        get_catalog_users_schema_model['groups'] = [catalog_groups_metadata_model]

        rule_grantee_model = {}  # RuleGrantee
        rule_grantee_model['value'] = 'testString'
        rule_grantee_model['key'] = 'user_name'
        rule_grantee_model['type'] = 'user_identity'

        rule_model = {}  # Rule
        rule_model['actions'] = ['all']
        rule_model['effect'] = 'allow'
        rule_model['grantee'] = rule_grantee_model

        data_policy_metadata_model = {}  # DataPolicyMetadata
        data_policy_metadata_model['creator'] = 'testString'
        data_policy_metadata_model['description'] = 'testString'
        data_policy_metadata_model['modifier'] = 'testString'
        data_policy_metadata_model['pid'] = 'testString'
        data_policy_metadata_model['policy_name'] = 'testString'
        data_policy_metadata_model['updated_at'] = 'testString'
        data_policy_metadata_model['version'] = 'testString'
        data_policy_metadata_model['created_at'] = 'testString'

        policy_schema_model = {}  # PolicySchema
        policy_schema_model['rule_count'] = 38
        policy_schema_model['rules'] = [rule_model]
        policy_schema_model['status'] = 'active'
        policy_schema_model['catalog_name'] = 'testString'
        policy_schema_model['data_artifact'] = 'schema1/table1/(column1|column2)'
        policy_schema_model['metadata'] = data_policy_metadata_model
        policy_schema_model['policy_name'] = 'testString'

        engine_groups_metadata_model = {}  # EngineGroupsMetadata
        engine_groups_metadata_model['group_id'] = 'testString'
        engine_groups_metadata_model['permission'] = 'can_administer'

        engine_users_metadata_model = {}  # EngineUsersMetadata
        engine_users_metadata_model['permission'] = 'can_administer'
        engine_users_metadata_model['user_name'] = 'testString'

        get_engine_users_schema_model = {}  # GetEngineUsersSchema
        get_engine_users_schema_model['engine_id'] = 'testString'
        get_engine_users_schema_model['groups'] = [engine_groups_metadata_model]
        get_engine_users_schema_model['total_count'] = 38
        get_engine_users_schema_model['users'] = [engine_users_metadata_model]

        # Construct a json representation of a PolicySchemaList model
        policy_schema_list_model_json = {}
        policy_schema_list_model_json['catalog_policies'] = [get_catalog_users_schema_model]
        policy_schema_list_model_json['data_policies'] = [policy_schema_model]
        policy_schema_list_model_json['engine_policies'] = [get_engine_users_schema_model]

        # Construct a model instance of PolicySchemaList by calling from_dict on the json representation
        policy_schema_list_model = PolicySchemaList.from_dict(policy_schema_list_model_json)
        assert policy_schema_list_model != False

        # Construct a model instance of PolicySchemaList by calling from_dict on the json representation
        policy_schema_list_model_dict = PolicySchemaList.from_dict(policy_schema_list_model_json).__dict__
        policy_schema_list_model2 = PolicySchemaList(**policy_schema_list_model_dict)

        # Verify the model instances are equivalent
        assert policy_schema_list_model == policy_schema_list_model2

        # Convert model instance back to dict and verify no loss of data
        policy_schema_list_model_json2 = policy_schema_list_model.to_dict()
        assert policy_schema_list_model_json2 == policy_schema_list_model_json


class TestModel_PolicyVersionResultSchema:
    """
    Test Class for PolicyVersionResultSchema
    """

    def test_policy_version_result_schema_serialization(self):
        """
        Test serialization/deserialization for PolicyVersionResultSchema
        """

        # Construct dict forms of any model objects needed in order to build this model.

        catalog_policies_model = {}  # CatalogPolicies
        catalog_policies_model['policy_name'] = 'testString'
        catalog_policies_model['policy_version'] = 'testString'

        data_policies_model = {}  # DataPolicies
        data_policies_model['associate_catalog'] = 'testString'
        data_policies_model['policy_name'] = 'testString'
        data_policies_model['policy_version'] = 'testString'

        db_conn_policies_model = {}  # DbConnPolicies
        db_conn_policies_model['policy_name'] = 'testString'
        db_conn_policies_model['policy_version'] = 'testString'

        engine_policies_model = {}  # EnginePolicies
        engine_policies_model['policy_name'] = 'testString'
        engine_policies_model['policy_version'] = 'testString'

        bucket_policies_model = {}  # BucketPolicies
        bucket_policies_model['policy_version'] = 'testString'
        bucket_policies_model['policy_name'] = 'testString'

        # Construct a json representation of a PolicyVersionResultSchema model
        policy_version_result_schema_model_json = {}
        policy_version_result_schema_model_json['catalog_policies'] = [catalog_policies_model]
        policy_version_result_schema_model_json['data_policies'] = [data_policies_model]
        policy_version_result_schema_model_json['database_policies'] = [db_conn_policies_model]
        policy_version_result_schema_model_json['engine_policies'] = [engine_policies_model]
        policy_version_result_schema_model_json['bucket_policies'] = [bucket_policies_model]

        # Construct a model instance of PolicyVersionResultSchema by calling from_dict on the json representation
        policy_version_result_schema_model = PolicyVersionResultSchema.from_dict(policy_version_result_schema_model_json)
        assert policy_version_result_schema_model != False

        # Construct a model instance of PolicyVersionResultSchema by calling from_dict on the json representation
        policy_version_result_schema_model_dict = PolicyVersionResultSchema.from_dict(policy_version_result_schema_model_json).__dict__
        policy_version_result_schema_model2 = PolicyVersionResultSchema(**policy_version_result_schema_model_dict)

        # Verify the model instances are equivalent
        assert policy_version_result_schema_model == policy_version_result_schema_model2

        # Convert model instance back to dict and verify no loss of data
        policy_version_result_schema_model_json2 = policy_version_result_schema_model.to_dict()
        assert policy_version_result_schema_model_json2 == policy_version_result_schema_model_json


class TestModel_Query:
    """
    Test Class for Query
    """

    def test_query_serialization(self):
        """
        Test serialization/deserialization for Query
        """

        # Construct a json representation of a Query model
        query_model_json = {}
        query_model_json['created_by'] = '<username>@<domain>.com'
        query_model_json['created_on'] = '1608437933'
        query_model_json['description'] = 'query to get expense data'
        query_model_json['engine_id'] = 'sampleEngine123'
        query_model_json['query_name'] = 'new_query_name'
        query_model_json['query_string'] = 'select expenses from expenditure'

        # Construct a model instance of Query by calling from_dict on the json representation
        query_model = Query.from_dict(query_model_json)
        assert query_model != False

        # Construct a model instance of Query by calling from_dict on the json representation
        query_model_dict = Query.from_dict(query_model_json).__dict__
        query_model2 = Query(**query_model_dict)

        # Verify the model instances are equivalent
        assert query_model == query_model2

        # Convert model instance back to dict and verify no loss of data
        query_model_json2 = query_model.to_dict()
        assert query_model_json2 == query_model_json


class TestModel_RegisterBucketCreatedBody:
    """
    Test Class for RegisterBucketCreatedBody
    """

    def test_register_bucket_created_body_serialization(self):
        """
        Test serialization/deserialization for RegisterBucketCreatedBody
        """

        # Construct dict forms of any model objects needed in order to build this model.

        register_bucket_created_body_bucket_model = {}  # RegisterBucketCreatedBodyBucket
        register_bucket_created_body_bucket_model['bucket_display_name'] = 'testString'
        register_bucket_created_body_bucket_model['bucket_id'] = 'testString'

        success_response_model = {}  # SuccessResponse
        success_response_model['_messageCode_'] = '<message code>'
        success_response_model['message'] = 'Success'

        # Construct a json representation of a RegisterBucketCreatedBody model
        register_bucket_created_body_model_json = {}
        register_bucket_created_body_model_json['bucket'] = register_bucket_created_body_bucket_model
        register_bucket_created_body_model_json['response'] = success_response_model

        # Construct a model instance of RegisterBucketCreatedBody by calling from_dict on the json representation
        register_bucket_created_body_model = RegisterBucketCreatedBody.from_dict(register_bucket_created_body_model_json)
        assert register_bucket_created_body_model != False

        # Construct a model instance of RegisterBucketCreatedBody by calling from_dict on the json representation
        register_bucket_created_body_model_dict = RegisterBucketCreatedBody.from_dict(register_bucket_created_body_model_json).__dict__
        register_bucket_created_body_model2 = RegisterBucketCreatedBody(**register_bucket_created_body_model_dict)

        # Verify the model instances are equivalent
        assert register_bucket_created_body_model == register_bucket_created_body_model2

        # Convert model instance back to dict and verify no loss of data
        register_bucket_created_body_model_json2 = register_bucket_created_body_model.to_dict()
        assert register_bucket_created_body_model_json2 == register_bucket_created_body_model_json


class TestModel_RegisterBucketCreatedBodyBucket:
    """
    Test Class for RegisterBucketCreatedBodyBucket
    """

    def test_register_bucket_created_body_bucket_serialization(self):
        """
        Test serialization/deserialization for RegisterBucketCreatedBodyBucket
        """

        # Construct a json representation of a RegisterBucketCreatedBodyBucket model
        register_bucket_created_body_bucket_model_json = {}
        register_bucket_created_body_bucket_model_json['bucket_display_name'] = 'testString'
        register_bucket_created_body_bucket_model_json['bucket_id'] = 'testString'

        # Construct a model instance of RegisterBucketCreatedBodyBucket by calling from_dict on the json representation
        register_bucket_created_body_bucket_model = RegisterBucketCreatedBodyBucket.from_dict(register_bucket_created_body_bucket_model_json)
        assert register_bucket_created_body_bucket_model != False

        # Construct a model instance of RegisterBucketCreatedBodyBucket by calling from_dict on the json representation
        register_bucket_created_body_bucket_model_dict = RegisterBucketCreatedBodyBucket.from_dict(register_bucket_created_body_bucket_model_json).__dict__
        register_bucket_created_body_bucket_model2 = RegisterBucketCreatedBodyBucket(**register_bucket_created_body_bucket_model_dict)

        # Verify the model instances are equivalent
        assert register_bucket_created_body_bucket_model == register_bucket_created_body_bucket_model2

        # Convert model instance back to dict and verify no loss of data
        register_bucket_created_body_bucket_model_json2 = register_bucket_created_body_bucket_model.to_dict()
        assert register_bucket_created_body_bucket_model_json2 == register_bucket_created_body_bucket_model_json


class TestModel_RegisterDatabaseCatalogBodyDatabaseDetails:
    """
    Test Class for RegisterDatabaseCatalogBodyDatabaseDetails
    """

    def test_register_database_catalog_body_database_details_serialization(self):
        """
        Test serialization/deserialization for RegisterDatabaseCatalogBodyDatabaseDetails
        """

        # Construct a json representation of a RegisterDatabaseCatalogBodyDatabaseDetails model
        register_database_catalog_body_database_details_model_json = {}
        register_database_catalog_body_database_details_model_json['password'] = 'samplepassword'
        register_database_catalog_body_database_details_model_json['port'] = '4553'
        register_database_catalog_body_database_details_model_json['ssl'] = True
        register_database_catalog_body_database_details_model_json['tables'] = 'kafka_table_name'
        register_database_catalog_body_database_details_model_json['username'] = 'sampleuser'
        register_database_catalog_body_database_details_model_json['database_name'] = 'new_database'
        register_database_catalog_body_database_details_model_json['hostname'] = 'db2@<hostname>.com'

        # Construct a model instance of RegisterDatabaseCatalogBodyDatabaseDetails by calling from_dict on the json representation
        register_database_catalog_body_database_details_model = RegisterDatabaseCatalogBodyDatabaseDetails.from_dict(register_database_catalog_body_database_details_model_json)
        assert register_database_catalog_body_database_details_model != False

        # Construct a model instance of RegisterDatabaseCatalogBodyDatabaseDetails by calling from_dict on the json representation
        register_database_catalog_body_database_details_model_dict = RegisterDatabaseCatalogBodyDatabaseDetails.from_dict(register_database_catalog_body_database_details_model_json).__dict__
        register_database_catalog_body_database_details_model2 = RegisterDatabaseCatalogBodyDatabaseDetails(**register_database_catalog_body_database_details_model_dict)

        # Verify the model instances are equivalent
        assert register_database_catalog_body_database_details_model == register_database_catalog_body_database_details_model2

        # Convert model instance back to dict and verify no loss of data
        register_database_catalog_body_database_details_model_json2 = register_database_catalog_body_database_details_model.to_dict()
        assert register_database_catalog_body_database_details_model_json2 == register_database_catalog_body_database_details_model_json


class TestModel_ReplaceDataPolicyCreatedBody:
    """
    Test Class for ReplaceDataPolicyCreatedBody
    """

    def test_replace_data_policy_created_body_serialization(self):
        """
        Test serialization/deserialization for ReplaceDataPolicyCreatedBody
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rule_grantee_model = {}  # RuleGrantee
        rule_grantee_model['value'] = 'testString'
        rule_grantee_model['key'] = 'user_name'
        rule_grantee_model['type'] = 'user_identity'

        rule_model = {}  # Rule
        rule_model['actions'] = ['all']
        rule_model['effect'] = 'allow'
        rule_model['grantee'] = rule_grantee_model

        replace_data_policy_schema_model = {}  # ReplaceDataPolicySchema
        replace_data_policy_schema_model['catalog_name'] = 'testString'
        replace_data_policy_schema_model['data_artifact'] = 'schema1/table1/(column1|column2)'
        replace_data_policy_schema_model['description'] = 'testString'
        replace_data_policy_schema_model['rules'] = [rule_model]
        replace_data_policy_schema_model['status'] = 'active'

        data_policy_metadata_model = {}  # DataPolicyMetadata
        data_policy_metadata_model['creator'] = 'testString'
        data_policy_metadata_model['description'] = 'testString'
        data_policy_metadata_model['modifier'] = 'testString'
        data_policy_metadata_model['pid'] = 'testString'
        data_policy_metadata_model['policy_name'] = 'testString'
        data_policy_metadata_model['updated_at'] = 'testString'
        data_policy_metadata_model['version'] = 'testString'
        data_policy_metadata_model['created_at'] = 'testString'

        success_response_model = {}  # SuccessResponse
        success_response_model['_messageCode_'] = '<message code>'
        success_response_model['message'] = 'Success'

        # Construct a json representation of a ReplaceDataPolicyCreatedBody model
        replace_data_policy_created_body_model_json = {}
        replace_data_policy_created_body_model_json['data_policy'] = replace_data_policy_schema_model
        replace_data_policy_created_body_model_json['metadata'] = data_policy_metadata_model
        replace_data_policy_created_body_model_json['response'] = success_response_model

        # Construct a model instance of ReplaceDataPolicyCreatedBody by calling from_dict on the json representation
        replace_data_policy_created_body_model = ReplaceDataPolicyCreatedBody.from_dict(replace_data_policy_created_body_model_json)
        assert replace_data_policy_created_body_model != False

        # Construct a model instance of ReplaceDataPolicyCreatedBody by calling from_dict on the json representation
        replace_data_policy_created_body_model_dict = ReplaceDataPolicyCreatedBody.from_dict(replace_data_policy_created_body_model_json).__dict__
        replace_data_policy_created_body_model2 = ReplaceDataPolicyCreatedBody(**replace_data_policy_created_body_model_dict)

        # Verify the model instances are equivalent
        assert replace_data_policy_created_body_model == replace_data_policy_created_body_model2

        # Convert model instance back to dict and verify no loss of data
        replace_data_policy_created_body_model_json2 = replace_data_policy_created_body_model.to_dict()
        assert replace_data_policy_created_body_model_json2 == replace_data_policy_created_body_model_json


class TestModel_ReplaceDataPolicySchema:
    """
    Test Class for ReplaceDataPolicySchema
    """

    def test_replace_data_policy_schema_serialization(self):
        """
        Test serialization/deserialization for ReplaceDataPolicySchema
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rule_grantee_model = {}  # RuleGrantee
        rule_grantee_model['value'] = 'testString'
        rule_grantee_model['key'] = 'user_name'
        rule_grantee_model['type'] = 'user_identity'

        rule_model = {}  # Rule
        rule_model['actions'] = ['all']
        rule_model['effect'] = 'allow'
        rule_model['grantee'] = rule_grantee_model

        # Construct a json representation of a ReplaceDataPolicySchema model
        replace_data_policy_schema_model_json = {}
        replace_data_policy_schema_model_json['catalog_name'] = 'testString'
        replace_data_policy_schema_model_json['data_artifact'] = 'schema1/table1/(column1|column2)'
        replace_data_policy_schema_model_json['description'] = 'testString'
        replace_data_policy_schema_model_json['rules'] = [rule_model]
        replace_data_policy_schema_model_json['status'] = 'active'

        # Construct a model instance of ReplaceDataPolicySchema by calling from_dict on the json representation
        replace_data_policy_schema_model = ReplaceDataPolicySchema.from_dict(replace_data_policy_schema_model_json)
        assert replace_data_policy_schema_model != False

        # Construct a model instance of ReplaceDataPolicySchema by calling from_dict on the json representation
        replace_data_policy_schema_model_dict = ReplaceDataPolicySchema.from_dict(replace_data_policy_schema_model_json).__dict__
        replace_data_policy_schema_model2 = ReplaceDataPolicySchema(**replace_data_policy_schema_model_dict)

        # Verify the model instances are equivalent
        assert replace_data_policy_schema_model == replace_data_policy_schema_model2

        # Convert model instance back to dict and verify no loss of data
        replace_data_policy_schema_model_json2 = replace_data_policy_schema_model.to_dict()
        assert replace_data_policy_schema_model_json2 == replace_data_policy_schema_model_json


class TestModel_ResourceWithResult:
    """
    Test Class for ResourceWithResult
    """

    def test_resource_with_result_serialization(self):
        """
        Test serialization/deserialization for ResourceWithResult
        """

        # Construct a json representation of a ResourceWithResult model
        resource_with_result_model_json = {}
        resource_with_result_model_json['action'] = 'testString'
        resource_with_result_model_json['resource_name'] = 'testString'
        resource_with_result_model_json['resource_type'] = 'testString'
        resource_with_result_model_json['result'] = True

        # Construct a model instance of ResourceWithResult by calling from_dict on the json representation
        resource_with_result_model = ResourceWithResult.from_dict(resource_with_result_model_json)
        assert resource_with_result_model != False

        # Construct a model instance of ResourceWithResult by calling from_dict on the json representation
        resource_with_result_model_dict = ResourceWithResult.from_dict(resource_with_result_model_json).__dict__
        resource_with_result_model2 = ResourceWithResult(**resource_with_result_model_dict)

        # Verify the model instances are equivalent
        assert resource_with_result_model == resource_with_result_model2

        # Convert model instance back to dict and verify no loss of data
        resource_with_result_model_json2 = resource_with_result_model.to_dict()
        assert resource_with_result_model_json2 == resource_with_result_model_json


class TestModel_ResourcesMetadata:
    """
    Test Class for ResourcesMetadata
    """

    def test_resources_metadata_serialization(self):
        """
        Test serialization/deserialization for ResourcesMetadata
        """

        # Construct a json representation of a ResourcesMetadata model
        resources_metadata_model_json = {}
        resources_metadata_model_json['action'] = 'testString'
        resources_metadata_model_json['resource_name'] = 'testString'
        resources_metadata_model_json['resource_type'] = 'engine'

        # Construct a model instance of ResourcesMetadata by calling from_dict on the json representation
        resources_metadata_model = ResourcesMetadata.from_dict(resources_metadata_model_json)
        assert resources_metadata_model != False

        # Construct a model instance of ResourcesMetadata by calling from_dict on the json representation
        resources_metadata_model_dict = ResourcesMetadata.from_dict(resources_metadata_model_json).__dict__
        resources_metadata_model2 = ResourcesMetadata(**resources_metadata_model_dict)

        # Verify the model instances are equivalent
        assert resources_metadata_model == resources_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        resources_metadata_model_json2 = resources_metadata_model.to_dict()
        assert resources_metadata_model_json2 == resources_metadata_model_json


class TestModel_ResumeEngineCreatedBody:
    """
    Test Class for ResumeEngineCreatedBody
    """

    def test_resume_engine_created_body_serialization(self):
        """
        Test serialization/deserialization for ResumeEngineCreatedBody
        """

        # Construct dict forms of any model objects needed in order to build this model.

        success_response_model = {}  # SuccessResponse
        success_response_model['_messageCode_'] = '<message code>'
        success_response_model['message'] = 'Success'

        # Construct a json representation of a ResumeEngineCreatedBody model
        resume_engine_created_body_model_json = {}
        resume_engine_created_body_model_json['response'] = success_response_model

        # Construct a model instance of ResumeEngineCreatedBody by calling from_dict on the json representation
        resume_engine_created_body_model = ResumeEngineCreatedBody.from_dict(resume_engine_created_body_model_json)
        assert resume_engine_created_body_model != False

        # Construct a model instance of ResumeEngineCreatedBody by calling from_dict on the json representation
        resume_engine_created_body_model_dict = ResumeEngineCreatedBody.from_dict(resume_engine_created_body_model_json).__dict__
        resume_engine_created_body_model2 = ResumeEngineCreatedBody(**resume_engine_created_body_model_dict)

        # Verify the model instances are equivalent
        assert resume_engine_created_body_model == resume_engine_created_body_model2

        # Convert model instance back to dict and verify no loss of data
        resume_engine_created_body_model_json2 = resume_engine_created_body_model.to_dict()
        assert resume_engine_created_body_model_json2 == resume_engine_created_body_model_json


class TestModel_Rule:
    """
    Test Class for Rule
    """

    def test_rule_serialization(self):
        """
        Test serialization/deserialization for Rule
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rule_grantee_model = {}  # RuleGrantee
        rule_grantee_model['value'] = 'testString'
        rule_grantee_model['key'] = 'user_name'
        rule_grantee_model['type'] = 'user_identity'

        # Construct a json representation of a Rule model
        rule_model_json = {}
        rule_model_json['actions'] = ['all']
        rule_model_json['effect'] = 'allow'
        rule_model_json['grantee'] = rule_grantee_model

        # Construct a model instance of Rule by calling from_dict on the json representation
        rule_model = Rule.from_dict(rule_model_json)
        assert rule_model != False

        # Construct a model instance of Rule by calling from_dict on the json representation
        rule_model_dict = Rule.from_dict(rule_model_json).__dict__
        rule_model2 = Rule(**rule_model_dict)

        # Verify the model instances are equivalent
        assert rule_model == rule_model2

        # Convert model instance back to dict and verify no loss of data
        rule_model_json2 = rule_model.to_dict()
        assert rule_model_json2 == rule_model_json


class TestModel_RuleGrantee:
    """
    Test Class for RuleGrantee
    """

    def test_rule_grantee_serialization(self):
        """
        Test serialization/deserialization for RuleGrantee
        """

        # Construct a json representation of a RuleGrantee model
        rule_grantee_model_json = {}
        rule_grantee_model_json['value'] = 'testString'
        rule_grantee_model_json['key'] = 'user_name'
        rule_grantee_model_json['type'] = 'user_identity'

        # Construct a model instance of RuleGrantee by calling from_dict on the json representation
        rule_grantee_model = RuleGrantee.from_dict(rule_grantee_model_json)
        assert rule_grantee_model != False

        # Construct a model instance of RuleGrantee by calling from_dict on the json representation
        rule_grantee_model_dict = RuleGrantee.from_dict(rule_grantee_model_json).__dict__
        rule_grantee_model2 = RuleGrantee(**rule_grantee_model_dict)

        # Verify the model instances are equivalent
        assert rule_grantee_model == rule_grantee_model2

        # Convert model instance back to dict and verify no loss of data
        rule_grantee_model_json2 = rule_grantee_model.to_dict()
        assert rule_grantee_model_json2 == rule_grantee_model_json


class TestModel_SuccessResponse:
    """
    Test Class for SuccessResponse
    """

    def test_success_response_serialization(self):
        """
        Test serialization/deserialization for SuccessResponse
        """

        # Construct a json representation of a SuccessResponse model
        success_response_model_json = {}
        success_response_model_json['_messageCode_'] = '<message code>'
        success_response_model_json['message'] = 'Success'

        # Construct a model instance of SuccessResponse by calling from_dict on the json representation
        success_response_model = SuccessResponse.from_dict(success_response_model_json)
        assert success_response_model != False

        # Construct a model instance of SuccessResponse by calling from_dict on the json representation
        success_response_model_dict = SuccessResponse.from_dict(success_response_model_json).__dict__
        success_response_model2 = SuccessResponse(**success_response_model_dict)

        # Verify the model instances are equivalent
        assert success_response_model == success_response_model2

        # Convert model instance back to dict and verify no loss of data
        success_response_model_json2 = success_response_model.to_dict()
        assert success_response_model_json2 == success_response_model_json


class TestModel_TableSnapshot:
    """
    Test Class for TableSnapshot
    """

    def test_table_snapshot_serialization(self):
        """
        Test serialization/deserialization for TableSnapshot
        """

        # Construct a json representation of a TableSnapshot model
        table_snapshot_model_json = {}
        table_snapshot_model_json['operation'] = 'alter'
        table_snapshot_model_json['snapshot_id'] = '2332342122211222'
        table_snapshot_model_json['summary'] = {'anyKey': 'anyValue'}
        table_snapshot_model_json['committed_at'] = '1609379392'

        # Construct a model instance of TableSnapshot by calling from_dict on the json representation
        table_snapshot_model = TableSnapshot.from_dict(table_snapshot_model_json)
        assert table_snapshot_model != False

        # Construct a model instance of TableSnapshot by calling from_dict on the json representation
        table_snapshot_model_dict = TableSnapshot.from_dict(table_snapshot_model_json).__dict__
        table_snapshot_model2 = TableSnapshot(**table_snapshot_model_dict)

        # Verify the model instances are equivalent
        assert table_snapshot_model == table_snapshot_model2

        # Convert model instance back to dict and verify no loss of data
        table_snapshot_model_json2 = table_snapshot_model.to_dict()
        assert table_snapshot_model_json2 == table_snapshot_model_json


class TestModel_UpdateDatabaseBodyDatabaseDetails:
    """
    Test Class for UpdateDatabaseBodyDatabaseDetails
    """

    def test_update_database_body_database_details_serialization(self):
        """
        Test serialization/deserialization for UpdateDatabaseBodyDatabaseDetails
        """

        # Construct a json representation of a UpdateDatabaseBodyDatabaseDetails model
        update_database_body_database_details_model_json = {}
        update_database_body_database_details_model_json['password'] = 'samplepassword'
        update_database_body_database_details_model_json['username'] = 'sampleuser'

        # Construct a model instance of UpdateDatabaseBodyDatabaseDetails by calling from_dict on the json representation
        update_database_body_database_details_model = UpdateDatabaseBodyDatabaseDetails.from_dict(update_database_body_database_details_model_json)
        assert update_database_body_database_details_model != False

        # Construct a model instance of UpdateDatabaseBodyDatabaseDetails by calling from_dict on the json representation
        update_database_body_database_details_model_dict = UpdateDatabaseBodyDatabaseDetails.from_dict(update_database_body_database_details_model_json).__dict__
        update_database_body_database_details_model2 = UpdateDatabaseBodyDatabaseDetails(**update_database_body_database_details_model_dict)

        # Verify the model instances are equivalent
        assert update_database_body_database_details_model == update_database_body_database_details_model2

        # Convert model instance back to dict and verify no loss of data
        update_database_body_database_details_model_json2 = update_database_body_database_details_model.to_dict()
        assert update_database_body_database_details_model_json2 == update_database_body_database_details_model_json


class TestModel_UpdateTableBodyAddColumnsItems:
    """
    Test Class for UpdateTableBodyAddColumnsItems
    """

    def test_update_table_body_add_columns_items_serialization(self):
        """
        Test serialization/deserialization for UpdateTableBodyAddColumnsItems
        """

        # Construct a json representation of a UpdateTableBodyAddColumnsItems model
        update_table_body_add_columns_items_model_json = {}
        update_table_body_add_columns_items_model_json['column_comment'] = 'income column'
        update_table_body_add_columns_items_model_json['column_name'] = 'income'
        update_table_body_add_columns_items_model_json['data_type'] = 'varchar'

        # Construct a model instance of UpdateTableBodyAddColumnsItems by calling from_dict on the json representation
        update_table_body_add_columns_items_model = UpdateTableBodyAddColumnsItems.from_dict(update_table_body_add_columns_items_model_json)
        assert update_table_body_add_columns_items_model != False

        # Construct a model instance of UpdateTableBodyAddColumnsItems by calling from_dict on the json representation
        update_table_body_add_columns_items_model_dict = UpdateTableBodyAddColumnsItems.from_dict(update_table_body_add_columns_items_model_json).__dict__
        update_table_body_add_columns_items_model2 = UpdateTableBodyAddColumnsItems(**update_table_body_add_columns_items_model_dict)

        # Verify the model instances are equivalent
        assert update_table_body_add_columns_items_model == update_table_body_add_columns_items_model2

        # Convert model instance back to dict and verify no loss of data
        update_table_body_add_columns_items_model_json2 = update_table_body_add_columns_items_model.to_dict()
        assert update_table_body_add_columns_items_model_json2 == update_table_body_add_columns_items_model_json


class TestModel_UpdateTableBodyDropColumnsItems:
    """
    Test Class for UpdateTableBodyDropColumnsItems
    """

    def test_update_table_body_drop_columns_items_serialization(self):
        """
        Test serialization/deserialization for UpdateTableBodyDropColumnsItems
        """

        # Construct a json representation of a UpdateTableBodyDropColumnsItems model
        update_table_body_drop_columns_items_model_json = {}
        update_table_body_drop_columns_items_model_json['column_name'] = 'expenditure'

        # Construct a model instance of UpdateTableBodyDropColumnsItems by calling from_dict on the json representation
        update_table_body_drop_columns_items_model = UpdateTableBodyDropColumnsItems.from_dict(update_table_body_drop_columns_items_model_json)
        assert update_table_body_drop_columns_items_model != False

        # Construct a model instance of UpdateTableBodyDropColumnsItems by calling from_dict on the json representation
        update_table_body_drop_columns_items_model_dict = UpdateTableBodyDropColumnsItems.from_dict(update_table_body_drop_columns_items_model_json).__dict__
        update_table_body_drop_columns_items_model2 = UpdateTableBodyDropColumnsItems(**update_table_body_drop_columns_items_model_dict)

        # Verify the model instances are equivalent
        assert update_table_body_drop_columns_items_model == update_table_body_drop_columns_items_model2

        # Convert model instance back to dict and verify no loss of data
        update_table_body_drop_columns_items_model_json2 = update_table_body_drop_columns_items_model.to_dict()
        assert update_table_body_drop_columns_items_model_json2 == update_table_body_drop_columns_items_model_json


class TestModel_UpdateTableBodyRenameColumnsItems:
    """
    Test Class for UpdateTableBodyRenameColumnsItems
    """

    def test_update_table_body_rename_columns_items_serialization(self):
        """
        Test serialization/deserialization for UpdateTableBodyRenameColumnsItems
        """

        # Construct a json representation of a UpdateTableBodyRenameColumnsItems model
        update_table_body_rename_columns_items_model_json = {}
        update_table_body_rename_columns_items_model_json['column_name'] = 'expenditure'
        update_table_body_rename_columns_items_model_json['new_column_name'] = 'expenses'

        # Construct a model instance of UpdateTableBodyRenameColumnsItems by calling from_dict on the json representation
        update_table_body_rename_columns_items_model = UpdateTableBodyRenameColumnsItems.from_dict(update_table_body_rename_columns_items_model_json)
        assert update_table_body_rename_columns_items_model != False

        # Construct a model instance of UpdateTableBodyRenameColumnsItems by calling from_dict on the json representation
        update_table_body_rename_columns_items_model_dict = UpdateTableBodyRenameColumnsItems.from_dict(update_table_body_rename_columns_items_model_json).__dict__
        update_table_body_rename_columns_items_model2 = UpdateTableBodyRenameColumnsItems(**update_table_body_rename_columns_items_model_dict)

        # Verify the model instances are equivalent
        assert update_table_body_rename_columns_items_model == update_table_body_rename_columns_items_model2

        # Convert model instance back to dict and verify no loss of data
        update_table_body_rename_columns_items_model_json2 = update_table_body_rename_columns_items_model.to_dict()
        assert update_table_body_rename_columns_items_model_json2 == update_table_body_rename_columns_items_model_json


class TestModel_UsersMetadata:
    """
    Test Class for UsersMetadata
    """

    def test_users_metadata_serialization(self):
        """
        Test serialization/deserialization for UsersMetadata
        """

        # Construct a json representation of a UsersMetadata model
        users_metadata_model_json = {}
        users_metadata_model_json['permission'] = 'can_administer'
        users_metadata_model_json['user_name'] = 'testString'

        # Construct a model instance of UsersMetadata by calling from_dict on the json representation
        users_metadata_model = UsersMetadata.from_dict(users_metadata_model_json)
        assert users_metadata_model != False

        # Construct a model instance of UsersMetadata by calling from_dict on the json representation
        users_metadata_model_dict = UsersMetadata.from_dict(users_metadata_model_json).__dict__
        users_metadata_model2 = UsersMetadata(**users_metadata_model_dict)

        # Verify the model instances are equivalent
        assert users_metadata_model == users_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        users_metadata_model_json2 = users_metadata_model.to_dict()
        assert users_metadata_model_json2 == users_metadata_model_json


# endregion
##############################################################################
# End of Model Tests
##############################################################################
