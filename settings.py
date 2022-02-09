import os
from distutils.util import strtobool

from dcustructuredlogginggrpc import get_logging
from pymongo import MongoClient, uri_parser

logger = get_logging()


class AppConfig(object):
    SNOW_URL = None
    SNOW_USER = 'dcuapi'
    BLOCKLIST_COLLECTION = 'blacklist'
    COLLECTION = 'incidents'
    EMAIL_COLLECTION = 'acknowledge_email'
    DBURL = os.getenv('MONGO_URL', '')

    def __init__(self):
        self.SNOW_PASS = os.getenv('SNOW_PASS', 'snow_pass')
        parsed_uri = uri_parser.parse_uri(self.DBURL)
        self.DB = parsed_uri['database']
        self.DB_PASS = parsed_uri['password']
        self.DB_USER = parsed_uri['username']
        self.DB_HOST = parsed_uri['nodelist'][0][0]
        self.DATABASE_IMPACTED = strtobool(os.getenv('DATABASE_IMPACTED', 'False'))

        self._blacklist_client = MongoClient(self.DBURL, connect=False)
        self._blacklist_db = self._blacklist_client[self.DB]
        self._blacklist_collection = self._blacklist_db[self.BLOCKLIST_COLLECTION]
        self._user_gen_domains = []

    @property
    def user_gen_domains(self):
        if not self._user_gen_domains:
            try:
                blacklist_record = self._blacklist_collection.find({'category': 'user_gen'})
                self._user_gen_domains = [x.get('entity') for x in blacklist_record]
            except Exception as e:
                logger.error('Unable to get user gen list from Mongo: {}'.format(e))
        return self._user_gen_domains


class ProductionAppConfig(AppConfig):
    SNOW_URL = 'https://godaddy.service-now.com/api/now/table'
    MIDDLEWARE_QUEUE = 'dcumiddleware'
    GDBS_QUEUE = 'gdbrandservice'
    EXEMPT_REPORTERS = {'Sucuri': '395146638', 'DBP': '290638894', 'PhishLabs': '129092584'}
    TRUSTED_REPORTERS = {'375006196'}  # Threat Hunting
    SNOW_USER = 'dcuapiv2'

    def __init__(self):
        super(ProductionAppConfig, self).__init__()


class OTEAppConfig(AppConfig):
    SNOW_URL = 'https://godaddytest.service-now.com/api/now/table'
    MIDDLEWARE_QUEUE = 'otedcumiddleware'
    GDBS_QUEUE = 'otegdbrandservice'
    EXEMPT_REPORTERS = {'Sucuri': '1500631816', 'DBP': '1500495186', 'PhishLabs': '908557'}
    TRUSTED_REPORTERS = {'1500602948'}  # Threat Hunting

    def __init__(self):
        super(OTEAppConfig, self).__init__()


class TestAppConfig(AppConfig):
    SNOW_URL = 'https://godaddydev.service-now.com/api/now/table'
    MIDDLEWARE_QUEUE = 'testdcumiddleware'
    GDBS_QUEUE = 'testgdbrandservice'
    EXEMPT_REPORTERS = {}
    TRUSTED_REPORTERS = {}

    def __init__(self):
        super(TestAppConfig, self).__init__()


class DevelopmentAppConfig(AppConfig):
    SNOW_URL = 'https://godaddydev.service-now.com/api/now/table'
    MIDDLEWARE_QUEUE = 'devdcumiddleware'
    GDBS_QUEUE = 'devgdbrandservice'
    EXEMPT_REPORTERS = {'dcuapi_test_dev': '1054985'}
    TRUSTED_REPORTERS = {'4134470'}  # Threat Hunting

    def __init__(self):
        super(DevelopmentAppConfig, self).__init__()


class UnitTestAppConfig(AppConfig):
    SNOW_URL = 'https://godaddydev.service-now.com/api/now/table'
    EXEMPT_REPORTERS = {'Sucuri': '0', 'DBP': '0', 'PhishLabs': '0'}
    TRUSTED_REPORTERS = {'threat-hunting-reporter-id'}

    def __init__(self):
        self.DBURL = 'mongodb://guest:guest@localhost/test'
        super(UnitTestAppConfig, self).__init__()


config_by_name = {'dev': DevelopmentAppConfig,
                  'ote': OTEAppConfig,
                  'prod': ProductionAppConfig,
                  'test': TestAppConfig,
                  'unit-test': UnitTestAppConfig}
