from nose.tools import assert_equal

from service.connectors.snow import SNOWHelper
from settings import UnitTestAppConfig


class TestSnowHelper:

    @classmethod
    def setup(cls):
        cls._helper = SNOWHelper(UnitTestAppConfig())

    def test_param_no_dates(self):
        start = None
        end = None
        expected = ''
        actual = self._helper.create_param_query(start, end)
        assert_equal(expected, actual)

    def test_param_start_only(self):
        start = '2018-12-25'
        end = None
        expected = '&sysparm_query=sys_created_on>=javascript:gs.dateGenerate(%272018-12-25%27,%2700:00:00%27)^ORDERBYDESCu_number'
        actual = self._helper.create_param_query(start, end)
        assert_equal(expected, actual)

    def test_param_end_only(self):
        start = None
        end = '2019-01-01'
        expected = '&sysparm_query=sys_created_on<=javascript:gs.dateGenerate(%272019-01-01%27,%2723:59:59%27)^ORDERBYDESCu_number'
        actual = self._helper.create_param_query(start, end)
        assert_equal(expected, actual)

    def test_param_start_end(self):
        start = '2018-12-25'
        end = '2019-01-01'
        expected = '&sysparm_query=sys_created_onBETWEENjavascript:gs.dateGenerate(%272018-12-25%27,%2700:00:00%27)@javascript:gs.dateGenerate(%272019-01-01%27,%2723:59:59%27)^ORDERBYDESCu_number'
        actual = self._helper.create_param_query(start, end)
        assert_equal(expected, actual)
