#########
# Copyright (c) 2013 GigaSpaces Technologies Ltd. All rights reserved
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

import unittest
import json
import urllib
import urllib2
import tempfile
import time
import os
import types

from nose.tools import nottest
from nose.plugins.attrib import attr
from wagon.wagon import Wagon

from manager_rest import utils, config, storage_manager, archiving
from manager_rest.file_server import FileServer
from cloudify_rest_client import CloudifyClient
from cloudify_rest_client.client import HTTPClient
from cloudify_rest_client.executions import Execution

try:
    from cloudify_rest_client.client import \
        DEFAULT_API_VERSION as CLIENT_API_VERSION
except ImportError:
    CLIENT_API_VERSION = 'v1'


STORAGE_MANAGER_MODULE_NAME = 'manager_rest.file_storage_manager'
FILE_SERVER_PORT = 53229
FILE_SERVER_BLUEPRINTS_FOLDER = 'blueprints'
FILE_SERVER_UPLOADED_BLUEPRINTS_FOLDER = 'uploaded-blueprints'
FILE_SERVER_RESOURCES_URI = '/resources'
LATEST_API_VERSION = 2  # to be used by max_client_version test attribute


def build_query_string(query_params):
    query_string = ''
    if query_params and len(query_params) > 0:
        query_string += urllib.urlencode(query_params, True) + '&'
    return query_string


@nottest
def test_config(**kwargs):
    """
    decorator-generator that can be used on test functions to set
    key-value pairs that may later be injected into functions using the
    "inject_test_config" decorator
    :param kwargs: key-value pairs to be stored on the function object
    :return: a decorator for a test function, which stores with the test's
     config on the test function's object under the "test_config" attribute
    """
    def _test_config_decorator(test_func):
        test_func.test_config = kwargs
        return test_func
    return _test_config_decorator


@nottest
def inject_test_config(f):
    """
    decorator for injecting "test_config" into a test obj method.
    also see the "test_config" decorator
    :param f: a test obj method to be injected with the "test_config" parameter
    :return: the method augmented with the "test_config" parameter
    """
    def _wrapper(test_obj, *args, **kwargs):
        test_func = getattr(test_obj, test_obj.id().split('.')[-1])
        if hasattr(test_func, 'test_config'):
            kwargs['test_config'] = test_func.test_config
        return f(test_obj, *args, **kwargs)
    return _wrapper


class MockHTTPClient(HTTPClient):

    def __init__(self, app, headers=None):
        super(MockHTTPClient, self).__init__(host='localhost',
                                             headers=headers)
        self.app = app

    def do_request(self,
                   requests_method,
                   uri,
                   data=None,
                   params=None,
                   headers=None,
                   pagination=None,
                   sort=None,
                   expected_status_code=200,
                   stream=False):
        if CLIENT_API_VERSION == 'v1':
            # in v1, HTTPClient won't append the version part of the URL
            # on its own, so it's done here instead
            uri = '/api/{0}{1}'.format(CLIENT_API_VERSION, uri)

        return super(MockHTTPClient, self).do_request(
            requests_method=requests_method,
            uri=uri,
            data=data,
            params=params,
            headers=headers,
            expected_status_code=expected_status_code,
            stream=stream)

    def _do_request(self, requests_method, request_url, body, params, headers,
                    expected_status_code, stream, verify):
        if 'get' in requests_method.__name__:
            response = self.app.get(request_url,
                                    headers=headers,
                                    query_string=build_query_string(params))

        elif 'put' in requests_method.__name__:
            if isinstance(body, types.GeneratorType):
                body = ''.join(body)
            response = self.app.put(request_url,
                                    headers=headers,
                                    data=body,
                                    query_string=build_query_string(params))
        elif 'post' in requests_method.__name__:
            response = self.app.post(request_url,
                                     headers=headers,
                                     data=body,
                                     query_string=build_query_string(params))
        elif 'patch' in requests_method.__name__:
            response = self.app.patch(request_url,
                                      headers=headers,
                                      data=body,
                                      query_string=build_query_string(params))
        elif 'delete' in requests_method.__name__:
            response = self.app.delete(request_url,
                                       headers=headers,
                                       query_string=build_query_string(params))
        else:
            raise NotImplemented()

        if response.status_code != expected_status_code:
            response.content = response.data
            response.json = lambda: json.loads(response.data)
            self._raise_client_error(response, request_url)

        return json.loads(response.data)


@attr(client_min_version=1, client_max_version=LATEST_API_VERSION)
class BaseServerTestCase(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super(BaseServerTestCase, self).__init__(*args, **kwargs)

    def create_client(self, headers=None):
        client = CloudifyClient(host='localhost',
                                headers=headers)
        mock_http_client = MockHTTPClient(self.app,
                                          headers=headers)
        client._client = mock_http_client
        client.blueprints.api = mock_http_client
        client.deployments.api = mock_http_client
        client.deployments.outputs.api = mock_http_client
        client.deployment_modifications.api = mock_http_client
        client.executions.api = mock_http_client
        client.nodes.api = mock_http_client
        client.node_instances.api = mock_http_client
        client.manager.api = mock_http_client
        client.evaluate.api = mock_http_client
        client.tokens.api = mock_http_client
        client.events.api = mock_http_client
        # only exists in v2 and above
        if CLIENT_API_VERSION != 'v1':
            client.plugins.api = mock_http_client
            client.snapshots.api = mock_http_client

        return client

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.rest_service_log = tempfile.mkstemp()[1]
        self.securest_log_file = tempfile.mkstemp()[1]
        self.file_server = FileServer(self.tmpdir)
        self.addCleanup(self.cleanup)
        self.file_server.start()
        storage_manager.storage_manager_module_name = \
            STORAGE_MANAGER_MODULE_NAME

        # workaround for setting the rest service log path, since it's
        # needed when 'server' module is imported.
        # right after the import the log path is set normally like the rest
        # of the variables (used in the reset_state)
        tmp_conf_file = tempfile.mkstemp()[1]
        json.dump({'rest_service_log_path': self.rest_service_log,
                   'rest_service_log_file_size_MB': 1,
                   'rest_service_log_files_backup_count': 1,
                   'rest_service_log_level': 'DEBUG'},
                  open(tmp_conf_file, 'w'))
        os.environ['MANAGER_REST_CONFIG_PATH'] = tmp_conf_file
        try:
            from manager_rest import server
        finally:
            del(os.environ['MANAGER_REST_CONFIG_PATH'])

        server.reset_state(self.create_configuration())
        utils.copy_resources(config.instance().file_server_root)
        server.setup_app()
        server.app.config['Testing'] = True
        self.app = server.app.test_client()
        self.client = self.create_client()
        self.initialize_provider_context()

    def cleanup(self):
        self.quiet_delete(self.rest_service_log)
        self.quiet_delete(self.securest_log_file)
        if self.file_server:
            self.file_server.stop()

    def initialize_provider_context(self, client=None):
        if not client:
            client = self.client
        # creating an empty bootstrap context
        client.manager.create_context(self.id(), {'cloudify': {}})

    def create_configuration(self):
        from manager_rest.config import Config
        test_config = Config()
        test_config.test_mode = True
        test_config.file_server_root = self.tmpdir
        test_config.file_server_base_uri = 'http://localhost:{0}'.format(
            FILE_SERVER_PORT)
        test_config.file_server_blueprints_folder = \
            FILE_SERVER_BLUEPRINTS_FOLDER
        test_config.file_server_uploaded_blueprints_folder = \
            FILE_SERVER_UPLOADED_BLUEPRINTS_FOLDER
        test_config.file_server_resources_uri = FILE_SERVER_RESOURCES_URI
        test_config.rest_service_log_level = 'DEBUG'
        test_config.rest_service_log_path = self.rest_service_log
        test_config.rest_service_log_file_size_MB = 100,
        test_config.rest_service_log_files_backup_count = 20
        test_config.security_audit_log_level = 'DEBUG'
        test_config.security_audit_log_file = self.securest_log_file
        test_config.security_audit_log_file_size_MB = 100
        test_config.security_audit_log_files_backup_count = 20
        return test_config

    def _version_url(self, url):
        # method for versionifying URLs for requests which don't go through
        # the REST client; the version is taken from the REST client regardless
        if CLIENT_API_VERSION not in url:
            url = '/api/{0}{1}'.format(CLIENT_API_VERSION, url)

        return url

    def post(self, resource_path, data, query_params=None):
        url = self._version_url(resource_path)
        result = self.app.post(urllib.quote(url),
                               content_type='application/json',
                               data=json.dumps(data),
                               query_string=build_query_string(query_params))
        result.json = json.loads(result.data)
        return result

    def post_file(self, resource_path, file_path, query_params=None):
        url = self._version_url(resource_path)
        with open(file_path) as f:
            result = self.app.post(urllib.quote(url),
                                   data=f.read(),
                                   query_string=build_query_string(
                                       query_params))
            result.json = json.loads(result.data)
            return result

    def put_file(self, resource_path, file_path, query_params=None):
        url = self._version_url(resource_path)
        with open(file_path) as f:
            result = self.app.put(urllib.quote(url),
                                  data=f.read(),
                                  query_string=build_query_string(
                                      query_params))
            result.json = json.loads(result.data)
            return result

    def put(self, resource_path, data=None, query_params=None):
        url = self._version_url(resource_path)
        result = self.app.put(urllib.quote(url),
                              content_type='application/json',
                              data=json.dumps(data) if data else None,
                              query_string=build_query_string(query_params))
        result.json = json.loads(result.data)
        return result

    def patch(self, resource_path, data):
        url = self._version_url(resource_path)
        result = self.app.patch(urllib.quote(url),
                                content_type='application/json',
                                data=json.dumps(data))
        result.json = json.loads(result.data)
        return result

    def get(self, resource_path, query_params=None, headers=None):
        url = self._version_url(resource_path)
        result = self.app.get(urllib.quote(url),
                              headers=headers,
                              query_string=build_query_string(query_params))
        result.json = json.loads(result.data)
        return result

    def head(self, resource_path):
        url = self._version_url(resource_path)
        result = self.app.head(urllib.quote(url))
        return result

    def delete(self, resource_path, query_params=None):
        url = self._version_url(resource_path)
        result = self.app.delete(urllib.quote(url),
                                 query_string=build_query_string(query_params))
        result.json = json.loads(result.data)
        return result

    def check_if_resource_on_fileserver(self, blueprint_id, resource_path):
        url = 'http://localhost:{0}/{1}/{2}/{3}'.format(
            FILE_SERVER_PORT, FILE_SERVER_BLUEPRINTS_FOLDER,
            blueprint_id, resource_path)
        try:
            urllib2.urlopen(url)
            return True
        except urllib2.HTTPError:
            return False

    def get_blueprint_path(self, blueprint_dir_name):
        return os.path.join(os.path.dirname(
            os.path.abspath(__file__)), blueprint_dir_name)

    def archive_mock_blueprint(self, archive_func=archiving.make_targzfile,
                               blueprint_dir='mock_blueprint'):
        archive_path = tempfile.mkstemp()[1]
        source_dir = os.path.join(os.path.dirname(
            os.path.abspath(__file__)), blueprint_dir)
        archive_func(archive_path, source_dir)
        return archive_path

    def get_mock_blueprint_path(self):
        return os.path.join(os.path.dirname(
            os.path.abspath(__file__)), 'mock_blueprint', 'blueprint.yaml')

    def put_blueprint_args(self, blueprint_file_name=None,
                           blueprint_id='blueprint',
                           archive_func=archiving.make_targzfile,
                           blueprint_dir='mock_blueprint'):

        resource_path = self._version_url(
            '/blueprints/{1}'.format(CLIENT_API_VERSION, blueprint_id))

        result = [
            resource_path,
            self.archive_mock_blueprint(archive_func, blueprint_dir),
        ]

        if blueprint_file_name:
            data = {'application_file_name': blueprint_file_name}
        else:
            data = {}

        result.append(data)
        return result

    def put_deployment(self,
                       deployment_id='deployment',
                       blueprint_file_name=None,
                       blueprint_id='blueprint',
                       inputs=None):
        blueprint_response = self.put_file(
            *self.put_blueprint_args(blueprint_file_name,
                                     blueprint_id)).json

        if 'error_code' in blueprint_response:
            raise RuntimeError(
                '{}: {}'.format(blueprint_response['error_code'],
                                blueprint_response['message']))

        blueprint_id = blueprint_response['id']
        deployment = self.client.deployments.create(blueprint_id,
                                                    deployment_id,
                                                    inputs=inputs)
        return blueprint_id, deployment.id, blueprint_response, deployment

    def upload_plugin(self, package_name, package_version):
        temp_file_path = self.create_wheel(package_name, package_version)
        response = self.post_file('/plugins', temp_file_path)
        os.remove(temp_file_path)
        return response

    def create_wheel(self, package_name, package_version):
        module_src = '{0}=={1}'.format(package_name, package_version)
        wagon_client = Wagon(module_src)
        return wagon_client.create(
            archive_destination_dir=tempfile.gettempdir(), force=True)

    def wait_for_url(self, url, timeout=5):
        end = time.time() + timeout

        while end >= time.time():
            try:
                status = urllib.urlopen(url).getcode()
                if status == 200:
                    return
            except IOError:
                time.sleep(1)

        raise RuntimeError('Url {0} is not available (waited {1} '
                           'seconds)'.format(url, timeout))

    @staticmethod
    def quiet_delete(file_path):
        try:
            os.remove(file_path)
        except:
            pass

    def wait_for_deployment_creation(self, client, deployment_id):
        env_creation_execution = None
        deployment_executions = client.executions.list(deployment_id)
        for execution in deployment_executions:
            if execution.workflow_id == 'create_deployment_environment':
                env_creation_execution = execution
                break
        if env_creation_execution:
            self.wait_for_execution(client, env_creation_execution)

    @staticmethod
    def wait_for_execution(client, execution, timeout=900):
        # Poll for execution status until execution ends
        deadline = time.time() + timeout
        while True:
            if time.time() > deadline:
                raise Exception(
                    'execution of operation {0} for deployment {1} timed out'.
                    format(execution.workflow_id, execution.deployment_id))

            execution = client.executions.get(execution.id)
            if execution.status in Execution.END_STATES:
                break
            time.sleep(3)
