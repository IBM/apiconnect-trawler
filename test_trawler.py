import trawler
import pytest
import datapower_net
import productstats_net
import requests_mock
from kubernetes import client, config
from click.testing import CliRunner

boaty = trawler.Trawler()


def test_check_nosettings():
    runner = CliRunner()
    result = runner.invoke(trawler.cli, ["--config", "/non/existent"])
    assert result.exit_code == 2


def test_check_config_load():
    boaty.load_config('test-assets/config.yaml')
    assert 'prometheus' in boaty.config
    assert 'graphite' in boaty.config
    assert boaty.config['graphite']['enabled'] is False


def test_do_stuff(caplog, mocker):
    mocker.patch('datapower_net.DataPowerNet.fish')
    mocker.patch('productstats_net.ProductStatsNet.fish')
    mocker.patch('time.sleep', side_effect=KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt):
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


def test_product_fishing(mocker):
    mocker.patch('kubernetes.config.load_incluster_config')
    mocker.patch('kubernetes.client.CoreV1Api.list_namespaced_service')
    with requests_mock.mock() as m:
        m.get(text='{"counts":{"blah":189}}')
    new_net = productstats_net.ProductStatsNet({}, boaty)
    assert new_net.password == 'not-a-password'
    assert config.load_incluster_config.called
    assert client.CoreV1Api.list_namespaced_service.called
