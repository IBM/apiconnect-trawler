import trawler
from click.testing import CliRunner


def test_check_nosettings():
    runner = CliRunner()
    result = runner.invoke(trawler.cli, [])
    assert result.exit_code == 2
