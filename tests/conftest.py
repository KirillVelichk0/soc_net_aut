import pathlib
import sys

import pytest
import grpc

from testsuite.databases.pgsql import discover

USERVER_CONFIG_HOOKS = ['_prepare_service_config']
pytest_plugins = [
    'pytest_userver.plugins.postgresql',
    'pytest_userver.plugins.grpc',
]
#pytest_plugins = [
#    'pytest_userver.plugins',
#    'testsuite.databases.pgsql.pytest_plugin',
#]
###################

@pytest.fixture(scope='session')
def AuthAndRegistService_protos():
    return grpc.protos('AuthServ.proto')


@pytest.fixture(scope='session')
def AuthAndRegist_services():
    return grpc.services('AuthServ.proto')


@pytest.fixture
def grpc_service(pgsql, AuthAndRegistService_services, grpc_channel, service_client):
    return AuthAndRegist_services.AuthAndRegistServiceStub(grpc_channel)


@pytest.fixture(scope='session')
def mock_grpc_hello_session(
        AuthAndRegist_services, grpc_mockserver, create_grpc_mock,
):
    mock = create_grpc_mock(AuthAndRegist_services.HelloServiceServicer)
    AuthAndRegist_services.AuthAndRegistServiceServicer_to_server(
        mock.servicer, grpc_mockserver,
    )
    return mock


@pytest.fixture
def mock_grpc_server(mock_grpc_hello_session):
    with mock_grpc_hello_session.mock() as mock:
        yield mock

#походу надо добавить grpc-клиент
@pytest.fixture(scope='session')
def _prepare_service_config(grpc_mockserver_endpoint):
    def patch_config(config, config_vars):
        components = config['components_manager']['components']
        components['hello-client']['endpoint'] = grpc_mockserver_endpoint

    return patch_config


def pytest_configure(config):
    sys.path.append(str(
        pathlib.Path(__file__).parent.parent / 'proto/'))


###############
@pytest.fixture(scope='session')
def root_dir():
    """Path to root directory service."""
    print("ROOT")
    return pathlib.Path(__file__).parent.parent


@pytest.fixture(scope='session')
def initial_data_path(root_dir):
    """Path for find files with data"""
    return [
        root_dir / 'postgresql/data',
    ]


@pytest.fixture(scope='session')
def pgsql_local(root_dir, pgsql_local_create):
    """Create schemas databases for tests"""
    databases = discover.find_schemas(
        'soc_net_aut',  # service name that goes to the DB connection
        [root_dir.joinpath('postgresql/schemas')],
    )
    return pgsql_local_create(list(databases.values()))


@pytest.fixture
def client_deps(pgsql):
    pass
