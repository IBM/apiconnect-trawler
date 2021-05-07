import trawler
import logging
import pytest
import certs_net
import datapower_net
import manager_net
import analytics_net
import requests_mock
import requests
import socket
from prometheus_client import REGISTRY
from kubernetes import client, config
import kubernetes
from click.testing import CliRunner

boaty = trawler.Trawler()
boaty.secret_path = 'test-assets'
boaty.use_kubeconfig = False




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


def test_datapower_fishing(mocker):
    mocker.patch('kubernetes.config.load_incluster_config')
    mocker.patch('kubernetes.client.CoreV1Api.list_namespaced_pod')
    new_net = datapower_net.DataPowerNet({}, boaty)
    new_net.fish()
    assert config.load_incluster_config.called
    assert client.CoreV1Api.list_namespaced_pod.called


def test_datapower_fishing_error(mocker, caplog):
    caplog.set_level(logging.INFO)
    mocker.patch('kubernetes.config.load_incluster_config')
    mocker.patch('kubernetes.client.CoreV1Api.list_namespaced_pod', side_effect=kubernetes.client.rest.ApiException)
    new_net = datapower_net.DataPowerNet({}, boaty)
    new_net.fish()
    assert config.load_incluster_config.called
    assert client.CoreV1Api.list_namespaced_pod.called
    assert 'Error calling kubernetes API' in caplog.text


def test_datapower_instance(mocker, caplog):
    caplog.set_level(logging.INFO)
    with requests_mock.mock() as m:
        m.put('https://127.0.0.1:5554/mgmt/config/apiconnect/Statistics/default', text="")
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
        m.put('/mgmt/config/apiconnect/Statistics/default', text='')

        dp.fetch_data('LogTargetStatus', 'test')
        assert 'Creating gauge ' in caplog.text
        # Lookup values from prometheus client
        assert REGISTRY.get_sample_value('datapower_test_EventsProcessed', labels={"pod": "myDp"}) == 210938
        assert REGISTRY.get_sample_value('datapower_test_EventsDropped', labels={"pod": "myDp"}) == 0
        assert REGISTRY.get_sample_value('datapower_test_EventsPending', labels={"pod": "myDp"}) == 2


def test_datapower_instance_readtimeout(caplog, mocker):
    caplog.set_level(logging.INFO)
    with requests_mock.mock() as m:
        m.put('https://127.0.0.1:5554/mgmt/config/apiconnect',
              exc=requests.exceptions.ReadTimeout())
        m.put('https://127.0.0.1:5554/mgmt/config/apiconnect/Statistics/default',
              exc=requests.exceptions.ReadTimeout())
        m.get('https://127.0.0.1:5554/mgmt/config/apiconnect/APIConnectGatewayService/default',
              exc=requests.exceptions.ReadTimeout())
        dp = datapower_net.DataPower('127.0.0.1', '5554', 'myDp', 'admin', 'password', boaty)
        assert dp.name == 'myDp'
        assert dp.ip == '127.0.0.1'
        assert 'rest-mgmt' in caplog.text


def test_datapower_instance_connecttimeout(caplog, mocker):
    caplog.set_level(logging.INFO)
    with requests_mock.mock() as m:
        m.put('https://127.0.0.1:5554/mgmt/config/apiconnect',
              exc=requests.exceptions.ReadTimeout())
        m.put('https://127.0.0.1:5554/mgmt/config/apiconnect/Statistics/default',
              exc=requests.exceptions.ReadTimeout())
        m.get('https://127.0.0.1:5554/mgmt/config/apiconnect/APIConnectGatewayService/default',
              exc=requests.exceptions.ReadTimeout())
        dp = datapower_net.DataPower('127.0.0.1', '5554', 'myDp', 'admin', 'password', boaty)
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
    new_net = certs_net.CertsNet({}, boaty)
    new_net.fish()
    assert config.load_incluster_config.called
    assert client.CoreV1Api.list_namespaced_secret.called

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
    import metrics_graphite
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
