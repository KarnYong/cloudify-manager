#########
# Copyright (c) 2015 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.

from os import path

from nose.plugins.attrib import attr

from manager_rest.test import base_test
from manager_rest.test.security.security_test_base import SecurityTestBase
from cloudify_rest_client.exceptions import UserUnauthorizedError

RUNNING_EXECUTIONS_MESSAGE = 'There are running executions for this deployment'
UNAUTHORIZED_ERROR_MESSAGE = '401: user unauthorized'


@attr(client_min_version=1, client_max_version=base_test.LATEST_API_VERSION)
class AuthorizationTests(SecurityTestBase):

    def setUp(self):
        super(AuthorizationTests, self).setUp()
        self.blueprint_path = path.join(
            self.get_blueprint_path('mock_blueprint'), 'empty_blueprint.yaml')

        self.admin_client = self._get_client_by_password('alice',
                                                         'alice_password')
        self.deployer_client = self._get_client_by_password('bob',
                                                            'bob_password')
        self.viewer_client = self._get_client_by_password('clair',
                                                          'clair_password')
        self.simple_user_client = self._get_client_by_password('dave',
                                                               'dave_password')

    def test_blueprint_operations(self):
        # test
        blueprint_ids = self._test_upload_blueprints()
        self._test_list_blueprints(blueprint_ids)
        self._test_get_blueprints(public_blueprint_id=blueprint_ids[0],
                                  private_blueprint_id=blueprint_ids[1])
        self._test_delete_blueprints(blueprint_ids[0])

        # cleanup
        # item 0 was deleted by _test_delete_blueprints
        for blueprint_id in blueprint_ids[1:]:
            self.admin_client.blueprints.delete(blueprint_id)

    def test_deployment_operations(self):
        blueprint_id = 'test_deployment_blueprint_1'
        # setup
        self.admin_client.blueprints.upload(self.blueprint_path, blueprint_id)

        # test
        deployment_ids = self._test_create_deployments(blueprint_id)
        self._test_list_deployments(deployment_ids)
        self._test_get_deployments(deployment_ids[0])
        self._test_delete_deployments(deployment_ids[0])

        # cleanup
        # item 0 was deleted by _test_delete_deployments
        for deployment in deployment_ids[1:]:
            self.admin_client.deployments.delete(deployment)
        self.admin_client.blueprints.delete(blueprint_id)

    def test_execution_operations(self):
        blueprint_ids = ['test_execution_blueprint_1',
                         'test_execution_blueprint_2']
        deployment_ids = ['test_execution_deployment_1',
                          'test_execution_deployment_2']

        # setup
        self.admin_client.blueprints.upload(
            self.blueprint_path, blueprint_ids[0])
        self.admin_client.blueprints.upload(
            self.blueprint_path, blueprint_ids[1])
        # creating the deployments generate 1 execution per deployment
        self.admin_client.deployments.create(
            blueprint_ids[0], deployment_ids[0])
        self.admin_client.deployments.create(
            blueprint_ids[1], deployment_ids[1])

        # test
        executions = self._test_start_executions(deployment_ids)
        # to the number of "install" executions we must add the 2 deployment
        # env creations executed above
        self._test_list_executions(len(executions) + 2)
        self._test_get_executions(executions[0])
        self._test_update_executions(executions[0])
        self._test_cancel_executions(executions)

    def test_node_operations(self):
        blueprint_id = 'blueprint_1'
        deployment_id = 'deployment_1'

        # setup
        self.admin_client.blueprints.upload(
            self.blueprint_path, blueprint_id)
        self.admin_client.deployments.create(blueprint_id, deployment_id)

        # test
        self._test_list_nodes(expected_nodes_num=1)
        self._test_get_nodes(blueprint_id, deployment_id)

    def test_node_instance_operations(self):
        # setup
        blueprint_id = 'test_node_instance_blueprint_1'
        deployment_id = 'deployment_1'
        self.admin_client.blueprints.upload(self.blueprint_path, blueprint_id)
        self.admin_client.deployments.create(blueprint_id, deployment_id)

        # test
        node_instances = self._test_list_node_instances()
        instance_id = self._test_get_node_instance(node_instances[0]['id'])
        self._test_update_node_instances(instance_id)

    def test_token_client_is_not_breaching(self):
        admin_token_client, deployer_token_client, viewer_token_client = \
            self._test_get_token()
        blueprint_ids = self._test_blueprint_upload_with_token(
            admin_token_client, deployer_token_client, viewer_token_client)
        self._test_get_blueprint_with_token(admin_token_client,
                                            deployer_token_client,
                                            viewer_token_client,
                                            blueprint_ids[0])
        self._test_blueprint_list_with_token(admin_token_client,
                                             deployer_token_client,
                                             viewer_token_client,
                                             blueprint_ids)
        self._test_blueprint_delete_with_token(admin_token_client,
                                               deployer_token_client,
                                               viewer_token_client,
                                               blueprint_ids[0])
        # cleanup
        # item 0 was deleted by _test_blueprint_delete_with_token
        for blueprint_id in blueprint_ids[1:]:
            self.admin_client.blueprints.delete(blueprint_id)

    ##################
    # token methods
    ##################
    def _test_blueprint_upload_with_token(self,
                                          admin_token_client,
                                          deployer_token_client,
                                          viewer_token_client):
        # admins and deployers should be able to upload blueprints...
        token_bp1_id = 'token_bp1'
        token_bp2_id = 'token_bp2'
        uploaded_token_bp = admin_token_client.blueprints.upload(
            self.blueprint_path, token_bp1_id)
        self._assert_resource_id(token_bp1_id, uploaded_token_bp)
        uploaded_token_bp = deployer_token_client.blueprints.upload(
            self.blueprint_path, token_bp2_id)
        self._assert_resource_id(token_bp2_id, uploaded_token_bp)
        # ...but viewers should not
        self._assert_unauthorized(viewer_token_client.blueprints.upload,
                                  self.blueprint_path, 'token_dummy_bp')

        return token_bp1_id, token_bp2_id

    def _test_get_token(self):
        # admins, deployers and viewers should be able to get a token...
        admin_token = self.admin_client.tokens.get().value
        admin_token_client = self._get_client_by_token(admin_token)
        deployer_token = self.deployer_client.tokens.get().value
        deployer_token_client = self._get_client_by_token(deployer_token)
        viewer_token = self.viewer_client.tokens.get().value
        viewer_token_client = self._get_client_by_token(viewer_token)

        # ... but simple users should not be able to get a token
        self._assert_unauthorized(self.simple_user_client.tokens.get)

        return admin_token_client, deployer_token_client, viewer_token_client

    def _test_blueprint_list_with_token(self,
                                        admin_token_client,
                                        deployer_token_client,
                                        viewer_token_client,
                                        expected_ids):
        # admins, deployers and viewers should be able so list blueprints
        blueprints_list = admin_token_client.blueprints.list()
        self._assert_resources_list_ids(expected_ids, blueprints_list)
        blueprints_list = deployer_token_client.blueprints.list()
        self._assert_resources_list_ids(expected_ids, blueprints_list)
        blueprints_list = viewer_token_client.blueprints.list()
        self._assert_resources_list_ids(expected_ids, blueprints_list)

    def _test_get_blueprint_with_token(self,
                                       admin_token_client,
                                       deployer_token_client,
                                       viewer_token_client,
                                       blueprint_id):
        # admins, deployers and viewers should be able so list blueprints
        found_blueprint = admin_token_client.blueprints.get(blueprint_id)
        self._assert_resource_id(blueprint_id, found_blueprint)
        found_blueprint = deployer_token_client.blueprints.get(blueprint_id)
        self._assert_resource_id(blueprint_id, found_blueprint)
        found_blueprint = viewer_token_client.blueprints.get(blueprint_id)
        self._assert_resource_id(blueprint_id, found_blueprint)

    def _test_blueprint_delete_with_token(self,
                                          admin_token_client,
                                          deployer_token_client,
                                          viewer_token_client,
                                          blueprint_id):
        # admins should be able to delete a blueprint...
        admin_token_client.blueprints.delete(blueprint_id)

        # ...but deployers and viewers should not
        self._assert_unauthorized(deployer_token_client.blueprints.delete,
                                  blueprint_id)
        self._assert_unauthorized(viewer_token_client.blueprints.delete,
                                  blueprint_id)

    ####################
    # blueprint methods
    ####################
    def _test_upload_blueprints(self):
        # admins and deployers should be able to upload blueprints...
        blueprint_1 = self.admin_client.blueprints.upload(
            self.blueprint_path, 'blueprint_1')
        self._assert_resource_id('blueprint_1', blueprint_1)

        blueprint_2 = self.deployer_client.blueprints.upload(
            self.blueprint_path, 'blueprint_2')
        self._assert_resource_id('blueprint_2', blueprint_2)

        # ...but viewers and simple users should not
        self._assert_unauthorized(self.viewer_client.blueprints.upload,
                                  self.blueprint_path, 'dummy_bp')
        self._assert_unauthorized(self.simple_user_client.blueprints.upload,
                                  self.blueprint_path, 'dummy_bp')
        return blueprint_1['id'], blueprint_2['id']

    def _test_list_blueprints(self, expected_ids):
        # admins, deployers and viewers should be able so list blueprints...
        blueprints_list = self.admin_client.blueprints.list()
        self._assert_resources_list_ids(expected_ids, blueprints_list)
        blueprints_list = self.deployer_client.blueprints.list()
        self._assert_resources_list_ids(expected_ids, blueprints_list)
        blueprints_list = self.viewer_client.blueprints.list()
        self._assert_resources_list_ids(expected_ids, blueprints_list)

        # ...but dave should not
        self._assert_unauthorized(self.simple_user_client.blueprints.list)

    def _test_get_blueprints(self, public_blueprint_id, private_blueprint_id):
        # admins, deployers and viewers should be able to get blueprints
        found_blueprint = self.admin_client.blueprints.get(public_blueprint_id)
        self._assert_resource_id(public_blueprint_id, found_blueprint)
        found_blueprint = self.deployer_client.blueprints.get(
            public_blueprint_id)
        self._assert_resource_id(public_blueprint_id, found_blueprint)
        found_blueprint = self.viewer_client.blueprints.get(
            public_blueprint_id)
        self._assert_resource_id(public_blueprint_id, found_blueprint)

        # viewers should not be able to get blueprint_2
        self._assert_unauthorized(self.viewer_client.blueprints.get,
                                  private_blueprint_id)

        # simple users should not be able to get any blueprint
        self._assert_unauthorized(self.simple_user_client.blueprints.get,
                                  public_blueprint_id)

    def _test_delete_blueprints(self, blueprint_id):
        # admins should be able to delete blueprints...
        self.admin_client.blueprints.delete(blueprint_id)

        # ...but deployers, viewers and simple users should not
        self._assert_unauthorized(self.deployer_client.blueprints.delete,
                                  blueprint_id)
        self._assert_unauthorized(self.viewer_client.blueprints.delete,
                                  blueprint_id)
        self._assert_unauthorized(self.simple_user_client.blueprints.delete,
                                  blueprint_id)

    #####################
    # deployment methods
    #####################
    def _test_delete_deployments(self, deployment_id):
        # admins should be able to delete deployments...
        self.wait_for_deployment_creation(self.admin_client, deployment_id)
        self.admin_client.deployments.delete(deployment_id)

        # ...but but deployers, viewers and simple users should not
        self._assert_unauthorized(self.deployer_client.deployments.delete,
                                  deployment_id)
        self._assert_unauthorized(self.viewer_client.deployments.delete,
                                  deployment_id)
        self._assert_unauthorized(self.simple_user_client.deployments.delete,
                                  deployment_id)

    def _test_get_deployments(self, deployment_id):
        # admins, deployers and viewers should be able to get deployments...
        found_deployment = self.admin_client.deployments.get(deployment_id)
        self._assert_resource_id(deployment_id, found_deployment)
        found_deployment = self.deployer_client.deployments.get(deployment_id)
        self._assert_resource_id(deployment_id, found_deployment)
        found_deployment = self.viewer_client.deployments.get(deployment_id)
        self._assert_resource_id(deployment_id, found_deployment)

        # ...but simple users should not
        self._assert_unauthorized(self.simple_user_client.deployments.get,
                                  deployment_id)

    def _test_list_deployments(self, expected_ids):
        # admins, deployers and viewers should be able so list deployments
        deployments_list = self.admin_client.deployments.list()
        self._assert_resources_list_ids(expected_ids, deployments_list)
        deployments_list = self.deployer_client.deployments.list()
        self._assert_resources_list_ids(expected_ids, deployments_list)
        deployments_list = self.viewer_client.deployments.list()
        self._assert_resources_list_ids(expected_ids, deployments_list)

        # ...but simple users should not
        self._assert_unauthorized(self.simple_user_client.deployments.list)

    def _test_create_deployments(self, blueprint_id):
        # admins and deployers should be able to create deployments...
        deployment1_id = 'deployment1_id'
        deployment2_id = 'deployment2_id'
        self.admin_client.deployments.create(blueprint_id, deployment1_id)
        self.deployer_client.deployments.create(blueprint_id, deployment2_id)

        # ...but viewers and simple users should not
        self._assert_unauthorized(self.viewer_client.deployments.create,
                                  'dummy_bp', 'dummy_dp')
        self._assert_unauthorized(self.simple_user_client.deployments.create,
                                  'dummy_bp', 'dummy_dp')

        return deployment1_id, deployment2_id

    ####################
    # execution methods
    ####################
    def _test_start_executions(self, deployment_ids):
        # admins and deployers should be able to start executions...
        execution1 = self.admin_client.executions.start(
            deployment_id=deployment_ids[0], workflow_id='install')
        execution2 = self.deployer_client.executions.start(
            deployment_id=deployment_ids[1], workflow_id='install')

        # ...but viewers and simple users should not
        self._assert_unauthorized(self.viewer_client.executions.start,
                                  'dummy_dp', 'install')
        self._assert_unauthorized(self.simple_user_client.executions.start,
                                  'dummy_dp', 'install')

        self.wait_for_deployment_creation(self.admin_client, deployment_ids[0])
        self.wait_for_deployment_creation(self.admin_client, deployment_ids[1])

        return execution1, execution2

    def _test_list_executions(self, expected_num_of_executions):
        # admins, deployers and viewers should be able so list executions
        executions_list = self.admin_client.executions.list()
        self.assertEqual(len(executions_list), expected_num_of_executions)
        executions_list = self.deployer_client.executions.list()
        self.assertEqual(len(executions_list), expected_num_of_executions)
        executions_list = self.viewer_client.executions.list()
        self.assertEqual(len(executions_list), expected_num_of_executions)

        # ...but simple users should not
        self._assert_unauthorized(self.simple_user_client.executions.list)

    def _test_get_executions(self, wanted_execution):
        # admins, deployers and viewers should be able to get executions...
        found_execution = self.admin_client.executions.get(
            wanted_execution['id'])
        self._assert_execution(wanted_execution, found_execution)
        found_execution = self.deployer_client.executions.get(
            wanted_execution['id'])
        self._assert_execution(wanted_execution, found_execution)
        found_execution = self.viewer_client.executions.get(
            wanted_execution['id'])
        self._assert_execution(wanted_execution, found_execution)

        # ...but simple users should not
        self._assert_unauthorized(self.simple_user_client.executions.get,
                                  wanted_execution['id'])

    def _test_update_executions(self, execution):
        # admins and deployers should be able to update executions...
        updated_execution = self.admin_client.executions.update(
            execution['id'], 'dummy_status1')
        self._assert_execution(execution, updated_execution)
        self.assertEqual('dummy_status1', updated_execution['status'])

        updated_execution = self.deployer_client.executions.update(
            execution['id'], 'dummy_status2')
        self._assert_execution(execution, updated_execution)
        self.assertEqual('dummy_status2', updated_execution['status'])

        # ...but viewers and simple users should not
        self._assert_unauthorized(self.viewer_client.executions.update,
                                  execution['id'], 'dummy-status')
        self._assert_unauthorized(self.simple_user_client.executions.update,
                                  execution['id'], 'dummy-status')

    def _test_cancel_executions(self, executions):
        execution1_id = executions[0]['id']
        execution2_id = executions[1]['id']
        # preparing executions for delete - setting status to pending
        self.admin_client.executions.update(execution1_id, 'pending')
        self.admin_client.executions.update(execution2_id, 'pending')

        # admins and deployers should be able to cancel executions...
        self.admin_client.executions.cancel(execution1_id)
        self.deployer_client.executions.cancel(execution2_id)

        # ...but viewers and simple users should not
        self._assert_unauthorized(self.viewer_client.executions.cancel,
                                  execution1_id)
        self._assert_unauthorized(self.simple_user_client.executions.cancel,
                                  execution2_id)

    #################
    # node methods
    #################
    def _test_get_nodes(self, blueprint_id, deployment_id):
        # admins, deployers and viewers should be able to get nodes
        node_id = 'mock_node'
        node_type = 'cloudify.nodes.Root'
        found_node = self.admin_client.nodes.get(deployment_id=deployment_id,
                                                 node_id=node_id)
        self._assert_node(found_node, node_id, blueprint_id, deployment_id,
                          node_type, 1)

        found_node = self.deployer_client.nodes.get(
            deployment_id=deployment_id, node_id=node_id)
        self._assert_node(found_node, node_id, blueprint_id, deployment_id,
                          node_type, 1)

        found_node = self.viewer_client.nodes.get(deployment_id=deployment_id,
                                                  node_id=node_id)
        self._assert_node(found_node, node_id, blueprint_id, deployment_id,
                          node_type, 1)

        # but simple users should not
        self._assert_unauthorized(self.simple_user_client.nodes.get,
                                  deployment_id, node_id)

    def _test_list_nodes(self, expected_nodes_num):
        # admins, deployers and viewers should be able to list nodes...
        nodes_list = self.admin_client.nodes.list()
        self.assertEqual(expected_nodes_num, len(nodes_list))
        nodes_list = self.deployer_client.nodes.list()
        self.assertEqual(expected_nodes_num, len(nodes_list))
        nodes_list = self.viewer_client.nodes.list()
        self.assertEqual(expected_nodes_num, len(nodes_list))

        # ...but simple users should not
        self._assert_unauthorized(self.simple_user_client.nodes.list)

    #########################
    # node instance methods
    #########################
    def _test_update_node_instances(self, instance_id):
        expected_node_id = 'mock_node'
        expected_deployment_id = 'deployment_1'
        runtime_properties = {'prop1': 'value1'}
        node_instance_state = 'testing_state'

        # admins and deployers should be able to update nodes instances
        node_instance = self.admin_client.node_instances.update(
            instance_id, node_instance_state, runtime_properties)
        self._assert_node_instance(node_instance, expected_node_id,
                                   expected_deployment_id, node_instance_state,
                                   runtime_properties)

        node_instance = self.deployer_client.node_instances.update(
            instance_id, node_instance_state, runtime_properties)
        self._assert_node_instance(node_instance, expected_node_id,
                                   expected_deployment_id, node_instance_state)

        # ...but viewers and simple users should not
        self._assert_unauthorized(self.viewer_client.node_instances.update,
                                  instance_id, node_instance_state)
        self._assert_unauthorized(
            self.simple_user_client.node_instances.update, instance_id,
            node_instance_state)

    def _test_get_node_instance(self, instance_id):
        # admins, deployers and viewers should be able to get nodes instances..
        node_instance = self.admin_client.node_instances.get(instance_id)
        self._assert_node_instance(node_instance, 'mock_node',
                                   'deployment_1', 'uninitialized')
        node_instance = self.deployer_client.node_instances.get(instance_id)
        self._assert_node_instance(node_instance, 'mock_node',
                                   'deployment_1', 'uninitialized')
        node_instance = self.viewer_client.node_instances.get(instance_id)
        self._assert_node_instance(node_instance, 'mock_node',
                                   'deployment_1', 'uninitialized')

        # ...but simple users should not
        self._assert_unauthorized(self.simple_user_client.node_instances.get,
                                  instance_id)
        return instance_id

    def _test_list_node_instances(self):
        # admins, deployers and viewers should be able to list node instances..
        node_instances = self.admin_client.node_instances.list()
        self.assertEqual(len(node_instances), 1)
        node_instances = self.deployer_client.node_instances.list()
        self.assertEqual(len(node_instances), 1)
        node_instances = self.viewer_client.node_instances.list()
        self.assertEqual(len(node_instances), 1)

        # ...but simple users should not
        self._assert_unauthorized(self.simple_user_client.node_instances.list)
        return node_instances

    #############################
    # utility methods
    #############################
    def _assert_resource_id(self, expected_id, resource):
        self.assertEqual(expected_id, resource['id'])

    def _assert_resources_list_ids(self, expected_ids, resources_list):
        self.assertEquals(len(expected_ids), len(resources_list))
        resources_ids = [resource.id for resource in resources_list]
        self.assertEquals(set(expected_ids), set(resources_ids))

    def _assert_execution(self, expected_execution, found_execution):
        self.assertEqual(expected_execution['blueprint_id'],
                         found_execution['blueprint_id'])
        self.assertEqual(expected_execution['deployment_id'],
                         found_execution['deployment_id'])
        self.assertEqual(expected_execution['workflow_id'],
                         found_execution['workflow_id'])

    def _assert_node(self, node, expected_node_id, expected_blueprint_id,
                     expected_deployment_id, expected_node_type,
                     expected_num_of_instances):
        self.assertEqual(expected_node_id, node['id'])
        self.assertEqual(expected_blueprint_id, node['blueprint_id'])
        self.assertEqual(expected_deployment_id, node['deployment_id'])
        self.assertEqual(expected_node_type, node['type'])
        self.assertEqual(str(expected_num_of_instances),
                         node['number_of_instances'])

    def _assert_node_instance(self, node_instance, expected_node_id,
                              expected_deployment_id, expected_state,
                              expected_runtime_properties=None,
                              expected_version=None):
        self.assertEqual(expected_node_id, node_instance['node_id'])
        self.assertEqual(expected_deployment_id,
                         node_instance['deployment_id'])
        self.assertEqual(expected_state, node_instance['state'])
        if expected_runtime_properties:
            self.assertEqual(expected_runtime_properties,
                             node_instance.runtime_properties)
        if expected_version:
            self.assertEqual(expected_version, node_instance.version)

    def _assert_unauthorized(self, method, *args):
        self.assertRaisesRegexp(UserUnauthorizedError,
                                UNAUTHORIZED_ERROR_MESSAGE,
                                method,
                                *args)

    def _get_client_by_password(self, username, password):
        auth_header = SecurityTestBase.create_auth_header(username=username,
                                                          password=password)
        return self.create_client(headers=auth_header)

    def _get_client_by_token(self, token):
        token_header = SecurityTestBase.create_auth_header(token=token)
        return self.create_client(headers=token_header)
