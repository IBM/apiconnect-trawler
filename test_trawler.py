import statistics
import trawler
import logging
import pytest
import certs_net
import datapower_net
import manager_net
import analytics_net
import requests_mock
import requests
import prometheus_client
import metrics_graphite
import socket
from kubernetes import client, config
import kubernetes
from click.testing import CliRunner

boaty = trawler.Trawler()
boaty.secret_path = 'test-assets'
boaty.use_kubeconfig = False

statistics_enabled = '{"Statistics":{"mAdminState":"enabled"}}'

fake_pod = kubernetes.client.V1Pod(
    metadata=kubernetes.client.V1ObjectMeta(
        name='testpod',
        namespace='trawler-test',
        annotations={"testAnnotation": "testValue"}
    ),
    status=kubernetes.client.V1PodStatus(
        conditions=[
            kubernetes.client.V1PodCondition(type='Ready', status=True)
        ],
        pod_ip="127.0.0.1"
    )
)

peering_mock = """
    {
        "GatewayPeeringStatus": [
            {
                "Address": "127.0.0.1",
                "Name": "rate-limit",
                "PendingUpdates": 0,
                "ReplicationOffset": 170111082,
                "LinkStatus": "ok",
                "Primary": "yes"
            }
        ]
    }
    """
log_target_mock = """
{
        "_links" : {
        "self" : {"href" : "/mgmt/status/default/LogTargetStatus"},
        "doc" : {"href" : "/mgmt/docs/status/LogTargetStatus"}},
        "LogTargetStatus" : {
        "LogTarget" : {"value": "default-log",
        "href" : "/mgmt/config/default/LogTarget/default-log"},
        "Status" : "active",
        "EventsProcessed" : 210938,
        "EventsDropped" : 0,
        "EventsPending" : 2,
        "ErrorInfo" : "none",
        "RequestedMemory" : 16}}
        """

v6 = '{"APIConnectGatewayService":{"V5CompatibilityMode":"off"}}'


def test_check_nosettings():
    runner = CliRunner()
    result = runner.invoke(trawler.cli, ["--config", "/non/existent"])
    assert result.exit_code == 2


def test_check_config_load_nographite():
    boaty2 = trawler.Trawler('test-assets/no-graphite.yaml')
    assert 'prometheus' in boaty2.config
    assert 'graphite' not in boaty2.config


def test_check_config_load():
    boaty.load_config('test-assets/config.yaml')
    assert 'prometheus' in boaty.config
    assert 'graphite' in boaty.config
    assert boaty.config['graphite']['enabled'] is False


def test_trawl(caplog, mocker):
    caplog.set_level(logging.INFO)
    boaty.config['nets'] = {}
    mocker.patch('time.sleep', side_effect=KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt):
        print(boaty.config)
        boaty.trawl_metrics()
    assert 'prometheus' in boaty.config
    assert 'graphite' in boaty.config
    assert 'INFO' in caplog.text


def test_secret():
    boaty.secrets_path = 'test-assets'
    content = boaty.read_secret('samplesecret')
    assert content == 'not-a-secret'


def test_missing_secret():
    boaty.secrets_path = 'test-assets'
    content = boaty.read_secret('missingsecret')
    assert content is None

def test_trawler_gauge(mocker, caplog):
    caplog.set_level(logging.INFO)
    if 'labels' in boaty.config['prometheus']:
      boaty.config['prometheus'].pop('labels')
    boaty.set_gauge('component', 'target_name', 23, 'pod_name')
    assert 'Creating gauge ' in caplog.text
    # Lookup values from prometheus client
    assert prometheus_client.REGISTRY.get_sample_value('component_target_name', labels={"pod": "pod_name"}) == 23

def test_trawler_gauge_default_labels(mocker, caplog):
    caplog.set_level(logging.INFO)
    boaty.config['prometheus']['labels'] = {'cluster':'goat'}
    boaty.set_gauge('component', 'target_name_default', 23, 'pod_name')
    assert 'Creating gauge ' in caplog.text
    # Lookup values from prometheus client
    assert prometheus_client.REGISTRY.get_sample_value('component_target_name_default', labels={"pod": "pod_name", "cluster":"goat"}) == 23

def test_trawler_gauge_additional_labels(mocker, caplog):
    caplog.set_level(logging.INFO)
    if 'labels' in boaty.config['prometheus']:
      boaty.config['prometheus'].pop('labels')
    boaty.set_gauge('labels', 'add_additional', 1, pod_name='pod_name', labels={"group": "labels"})
    assert 'Creating gauge ' in caplog.text
    # Lookup values from prometheus client
    assert prometheus_client.REGISTRY.get_sample_value('labels_add_additional', labels={"pod": "pod_name", "group": "labels"}) == 1


def test_datapower_fishing(mocker):
    """ test the pod finding """
    mocker.patch('kubernetes.config.load_incluster_config')
    mocker.patch('kubernetes.client.CoreV1Api.list_pod_for_all_namespaces',
                 return_value=kubernetes.client.V1PodList(items=[fake_pod])
                 )
    mocker.patch('datapower_net.DataPowerNet.load_password_from_secret', return_value='password')
    with requests_mock.mock() as m:
        m.get('https://127.0.0.1:5554/mgmt/config/apiconnect/APIConnectGatewayService/default', text=v6)
        m.get('https://127.0.0.1:5554/mgmt/config/apiconnect/Statistics', text=statistics_enabled)

        m.get('https://127.0.0.1:5554/mgmt/status/apiconnect/GatewayPeeringStatus', text=peering_mock)
        m.get('https://127.0.0.1:5554/mgmt/status/apiconnect/AnalyticsEndpointStatus', text="")
        m.get('https://127.0.0.1:5554/mgmt/status/apiconnect/TCPSummary', text="")
        m.get('https://127.0.0.1:5554/mgmt/status/apiconnect/LogTargetStatus', text=log_target_mock)
        m.get('https://127.0.0.1:5554/mgmt/status/apiconnect/ObjectStatus', text="")
        m.get('https://127.0.0.1:5554/mgmt/status/apiconnect/APIDocumentCachingSummary', text="")
        m.get('https://127.0.0.1:5554/mgmt/status/apiconnect/HTTPTransactions2', text="")
        new_net = datapower_net.DataPowerNet({}, boaty)
        new_net.fish()
        assert config.load_incluster_config.called


def test_datapower_fishing_error(mocker, caplog):
    caplog.set_level(logging.INFO)
    mocker.patch('kubernetes.client.CoreV1Api.list_pod_for_all_namespaces',
                 side_effect=kubernetes.client.rest.ApiException('error')
                 )    
    new_net = datapower_net.DataPowerNet({}, boaty)
    assert kubernetes.client.CoreV1Api.list_pod_for_all_namespaces


def test_datapower_instance(mocker, caplog):
    caplog.set_level(logging.INFO)
    with requests_mock.mock() as m:
        m.get('https://127.0.0.1:5554/mgmt/config/apiconnect/Statistics', text=statistics_enabled)
        v5c = '{"APIConnectGatewayService":{"V5CompatibilityMode":"on"}}'
        m.get('https://127.0.0.1:5554/mgmt/config/apiconnect/APIConnectGatewayService/default', text=v5c)
        dp = datapower_net.DataPower('127.0.0.1', '5554', 'myDp', 'namespace', 'admin', 'password', boaty)
        assert dp.name == 'myDp'
        assert dp.ip == '127.0.0.1'
        assert dp.v5c
        # Mock data
        m.get('https://127.0.0.1:5554/mgmt/status/apiconnect/LogTargetStatus', text=log_target_mock)
        m.get('/mgmt/config/apiconnect/Statistics', text=statistics_enabled)

        dp.fetch_data('LogTargetStatus', 'test')
        assert 'Creating gauge ' in caplog.text
        # Lookup values from prometheus client
        assert prometheus_client.REGISTRY.get_sample_value(
            'datapower_test_EventsProcessed', 
            labels={"pod": "myDp", "namespace": "namespace"}) == 210938
        assert prometheus_client.REGISTRY.get_sample_value(
            'datapower_test_EventsDropped', 
            labels={"pod": "myDp", "namespace": "namespace"}) == 0
        assert prometheus_client.REGISTRY.get_sample_value(
            'datapower_test_EventsPending', 
            labels={"pod": "myDp", "namespace": "namespace"}) == 2


def test_datapower_peering(mocker, caplog):
    caplog.set_level(logging.INFO)
    with requests_mock.mock() as m:
        v6 = '{"APIConnectGatewayService":{"V5CompatibilityMode":"off"}}'
        m.get('https://127.0.0.1:5554/mgmt/config/apiconnect/APIConnectGatewayService/default', text=v6)
        m.get('https://127.0.0.1:5554/mgmt/config/apiconnect/Statistics', text=statistics_enabled)

        dp = datapower_net.DataPower('127.0.0.1', '5554', 'myDp', 'namespace', 'admin', 'password', boaty)
        assert dp.name == 'myDp'
        assert dp.ip == '127.0.0.1'
        assert not dp.v5c
        # Mock data
        mock_data = """
        {
            "GatewayPeeringStatus": [
                {
                    "Address": "127.0.0.1",
                    "Name": "rate-limit",
                    "PendingUpdates": 0,
                    "ReplicationOffset": 170111082,
                    "LinkStatus": "ok",
                    "Primary": "yes"
                }
            ]
        }
        """

        m.get('https://127.0.0.1:5554/mgmt/status/apiconnect/GatewayPeeringStatus', text=mock_data)

        dp.gateway_peering_status()

        # Lookup values from prometheus client
        assert prometheus_client.REGISTRY.get_sample_value(
            'datapower_gateway_peering_primary_info', 
            labels={"pod": "myDp", "peer_group": "rate-limit", "namespace": "namespace"}) == 1
        assert prometheus_client.REGISTRY.get_sample_value(
            'datapower_gateway_peering_primary_link', 
            labels={"pod": "myDp", "peer_group": "rate-limit", "namespace": "namespace"}) == 1
        assert prometheus_client.REGISTRY.get_sample_value(
            'datapower_gateway_peering_primary_offset', 
            labels={"pod": "myDp", "peer_group": "rate-limit", "namespace": "namespace"}) == 170111082


def test_datapower_instance_readtimeout(caplog, mocker):
    caplog.set_level(logging.INFO)
    with requests_mock.mock() as m:
        m.put('https://127.0.0.1:5554/mgmt/config/apiconnect',
              exc=requests.exceptions.ReadTimeout())
        m.get('https://127.0.0.1:5554/mgmt/config/apiconnect/Statistics',
              exc=requests.exceptions.ReadTimeout())
        m.get('https://127.0.0.1:5554/mgmt/config/apiconnect/APIConnectGatewayService/default',
              exc=requests.exceptions.ReadTimeout())
        dp = datapower_net.DataPower('127.0.0.1', '5554', 'myDp', 'namespace', 'admin', 'password', boaty)
        assert dp.name == 'myDp'
        assert dp.ip == '127.0.0.1'
        assert 'rest-mgmt' in caplog.text


def test_datapower_instance_connecttimeout(caplog, mocker):
    caplog.set_level(logging.INFO)
    with requests_mock.mock() as m:
        m.put('https://127.0.0.1:5554/mgmt/config/apiconnect',
              exc=requests.exceptions.ReadTimeout())
        m.get('https://127.0.0.1:5554/mgmt/config/apiconnect/Statistics',
              exc=requests.exceptions.ReadTimeout())
        m.get('https://127.0.0.1:5554/mgmt/config/apiconnect/APIConnectGatewayService/default',
              exc=requests.exceptions.ReadTimeout())
        dp = datapower_net.DataPower('127.0.0.1', '5554', 'myDp', 'namespace', 'admin', 'password', boaty)
        assert dp.name == 'myDp'
        assert dp.ip == '127.0.0.1'
        assert 'rest-mgmt' in caplog.text

def test_datapower_instance_api_test(caplog, mocker):
    """ Test per gateway api testing """
    caplog.set_level(logging.INFO)
    api_tests = [
        {"name":"test", "path": "/apitest", "method": "get"}
    ]
    with requests_mock.mock() as m:
        v6 = '{"APIConnectGatewayService":{"V5CompatibilityMode":"off"}}'
        m.get('https://127.0.0.1:5554/mgmt/config/apiconnect/APIConnectGatewayService/default', text=v6)
        m.get('https://127.0.0.1:5554/mgmt/config/apiconnect/Statistics', text=statistics_enabled)
        m.get('https://127.0.0.1:9443/apitest', text='1')
        dp = datapower_net.DataPower('127.0.0.1', '5554', 'myDp', 'namespace', 'admin', 'password', boaty, api_tests)
        assert dp.name == 'myDp'
        assert dp.ip == '127.0.0.1'
        assert dp.api_tests == api_tests
        dp.invoke_api(dp.api_tests[0])
        assert prometheus_client.REGISTRY.get_sample_value(
            'datapower_invoke_api_test_size', 
            labels={"pod": "myDp", "namespace": "namespace"}) == 1
        assert prometheus_client.REGISTRY.get_sample_value(
            'datapower_invoke_api_test_time', 
            labels={"pod": "myDp", "namespace": "namespace"})
        assert prometheus_client.REGISTRY.get_sample_value(
            'datapower_invoke_api_test_status_total', 
            labels={"pod": "myDp", "namespace": "namespace", "code": "200"})


def test_manager_fishing_errors(mocker, caplog):
    caplog.set_level(logging.INFO)
    with requests_mock.mock() as m:
        m.get('https://juhu.local/api/cloud/topology', exc=requests.exceptions.ConnectionError)
    mocker.patch('kubernetes.config.load_incluster_config')
    mocker.patch('kubernetes.client.CoreV1Api.list_namespaced_service', side_effect=kubernetes.client.rest.ApiException)
    new_net = manager_net.ManagerNet({}, boaty)
    new_net.hostname = 'juhu.local'
    new_net.get_topology_info()
    assert new_net.password == 'not-a-password'
    assert config.load_incluster_config.called
    assert client.CoreV1Api.list_namespaced_service.called
    assert 'Error calling kubernetes API' in caplog.text


def test_cert_fishing(mocker):
    mocker.patch('kubernetes.config.load_incluster_config')
    mocker.patch('kubernetes.client.CoreV1Api.list_namespaced_secret')
    new_net = certs_net.CertsNet({"namespace": "certs"}, boaty)
    new_net.fish()
    assert config.load_incluster_config.called
    assert client.CoreV1Api.list_namespaced_secret.called


def test_cert_fishing_all_namespaces(mocker):
    mocker.patch('kubernetes.config.load_incluster_config')
    mocker.patch('kubernetes.client.CoreV1Api.list_secret_for_all_namespaces')
    new_net = certs_net.CertsNet({}, boaty)
    new_net.fish()
    assert config.load_incluster_config.called
    assert client.CoreV1Api.list_secret_for_all_namespaces.called


def test_analytics_fishing(mocker):
    mocker.patch('kubernetes.config.load_incluster_config')
    mocker.patch('kubernetes.client.CoreV1Api.list_namespaced_service')
    mocker.patch('kubernetes.client.CoreV1Api.list_namespaced_secret')
    mocker.patch('kubernetes.client.CustomObjectsApi.list_cluster_custom_object',
                 return_value={
                     'items': [
                         {'status': {
                          'services': {'director':'director-local'},
                          'serviceClientSecret':'none',
                          'versions': {'reconciled':'10.0.4.1'}}}]})

    new_net = analytics_net.AnalyticsNet({}, boaty)
    new_net.fish()
    assert config.load_incluster_config.called
    assert client.CoreV1Api.list_namespaced_service.called
    assert client.CoreV1Api.list_namespaced_secret.called


def test_metrics_graphite_stage():
    metrics = metrics_graphite.instance({"type":"graphite"})
    length = len(metrics.cache) 
    metrics.stage('hello', 1)
    assert len(metrics.cache) is length + 1
    assert "trawler.hello" in metrics.cache[length]


def test_metrics_graphite_prefix():
    import metrics_graphite
    metrics = metrics_graphite.instance({"type":"graphite", "prefix":"random"})
    assert metrics.prefix == "random"
    metrics.stage('hello', 1)
    assert "random." in metrics.cache[-1]
