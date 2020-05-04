import trawler
import datapower_net
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
    boaty.do_stuff()
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
