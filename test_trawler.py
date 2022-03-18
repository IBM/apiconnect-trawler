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
import watch_pods
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



def test_check_nosettings():
    runner = CliRunner()
    result = runner.invoke(trawler.cli, ["--config", "/non/existent"])
    assert result.exit_code == 2


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
    boaty.set_gauge('component', 'target_name', 23, 'pod_name')
    assert 'Creating gauge ' in caplog.text
    # Lookup values from prometheus client
    assert prometheus_client.REGISTRY.get_sample_value('component_target_name', labels={"pod": "pod_name"}) == 23

def test_trawler_gauge_additional_labels(mocker, caplog):
    caplog.set_level(logging.INFO)
    boaty.set_gauge('labels', 'add_additional', 1, pod_name='pod_name', labels={"group": "labels"})
    assert 'Creating gauge ' in caplog.text
    # Lookup values from prometheus client
    assert prometheus_client.REGISTRY.get_sample_value('labels_add_additional', labels={"pod": "pod_name", "group": "labels"}) == 1

def test_datapower_fishing(mocker):
    mocker.patch('kubernetes.config.load_incluster_config')
    mocker.patch('watch_pods.Watcher.getPods')
    new_net = datapower_net.DataPowerNet({}, boaty)
    new_net.fish()
    assert config.load_incluster_config.called
    assert watch_pods.Watcher.getPods.called


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
        dp = datapower_net.DataPower('127.0.0.1', '5554', 'myDp', 'admin', 'password', boaty)
        assert dp.name == 'myDp'
        assert dp.ip == '127.0.0.1'
        assert dp.v5c
        # Mock data
        mock_data = """
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
        m.get('https://127.0.0.1:5554/mgmt/status/apiconnect/LogTargetStatus', text=mock_data)
        m.get('/mgmt/config/apiconnect/Statistics', text=statistics_enabled)

        dp.fetch_data('LogTargetStatus', 'test')
        assert 'Creating gauge ' in caplog.text
        # Lookup values from prometheus client
        assert prometheus_client.REGISTRY.get_sample_value('datapower_test_EventsProcessed', labels={"pod": "myDp"}) == 210938
        assert prometheus_client.REGISTRY.get_sample_value('datapower_test_EventsDropped', labels={"pod": "myDp"}) == 0
        assert prometheus_client.REGISTRY.get_sample_value('datapower_test_EventsPending', labels={"pod": "myDp"}) == 2

def test_datapower_peering(mocker, caplog):
    caplog.set_level(logging.INFO)
    with requests_mock.mock() as m:
        v6 = '{"APIConnectGatewayService":{"V5CompatibilityMode":"off"}}'
        m.get('https://127.0.0.1:5554/mgmt/config/apiconnect/APIConnectGatewayService/default', text=v6)
        m.get('https://127.0.0.1:5554/mgmt/config/apiconnect/Statistics', text=statistics_enabled)

        dp = datapower_net.DataPower('127.0.0.1', '5554', 'myDp', 'admin', 'password', boaty)
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
        assert 'Creating gauge ' in caplog.text
        # Lookup values from prometheus client
        assert prometheus_client.REGISTRY.get_sample_value('datapower_gateway_peering_primary_info', labels={"pod": "myDp", "peer_group": "rate-limit"}) == 1
        assert prometheus_client.REGISTRY.get_sample_value('datapower_gateway_peering_primary_link', labels={"pod": "myDp", "peer_group": "rate-limit"}) == 1
        assert prometheus_client.REGISTRY.get_sample_value('datapower_gateway_peering_primary_offset', labels={"pod": "myDp", "peer_group": "rate-limit"}) == 170111082


def test_datapower_instance_readtimeout(caplog, mocker):
    caplog.set_level(logging.INFO)
    with requests_mock.mock() as m:
        m.put('https://127.0.0.1:5554/mgmt/config/apiconnect',
              exc=requests.exceptions.ReadTimeout())
        m.get('https://127.0.0.1:5554/mgmt/config/apiconnect/Statistics',
              exc=requests.exceptions.ReadTimeout())
        m.get('https://127.0.0.1:5554/mgmt/config/apiconnect/APIConnectGatewayService/default',
              exc=requests.exceptions.ReadTimeout())
        dp = datapower_net.DataPower('127.0.0.1', '5554', 'myDp', 'admin', 'password', trawler=boaty)
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
        dp = datapower_net.DataPower('127.0.0.1', '5554', 'myDp', 'admin', 'password', trawler=boaty)
        assert dp.name == 'myDp'
        assert dp.ip == '127.0.0.1'
        assert 'rest-mgmt' in caplog.text


def test_manager_fishing_error(mocker, caplog):
    caplog.set_level(logging.INFO)
    mocker.patch('kubernetes.config.load_incluster_config')
    mocker.patch('kubernetes.client.CoreV1Api.list_namespaced_service', side_effect=kubernetes.client.rest.ApiException)
    new_net = manager_net.ManagerNet({}, boaty)
    assert new_net.password == 'not-a-password'
    assert config.load_incluster_config.called
    assert client.CoreV1Api.list_namespaced_service.called
    assert 'Error calling kubernetes API' in caplog.text

def test_cert_fishing(mocker):
    mocker.patch('kubernetes.config.load_incluster_config')
    mocker.patch('kubernetes.client.CoreV1Api.list_namespaced_secret')
    new_net = certs_net.CertsNet({"namespace":"certs"}, boaty)
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
