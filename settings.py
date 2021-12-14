import os
from distutils.util import strtobool

from pymongo import uri_parser


class AppConfig(object):
    SNOW_URL = None
    SNOW_USER = 'dcuapi'
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


class DevelopmentAppConfig(AppConfig):
    SNOW_URL = 'https://godaddydev.service-now.com/api/now/table'
    MIDDLEWARE_QUEUE = 'devdcumiddleware'
    GDBS_QUEUE = 'devgdbrandservice'
    EXEMPT_REPORTERS = {'dcuapi_test_dev': '1054985'}
    TRUSTED_REPORTERS = {'4134470'}  # Threat Hunting

    def __init__(self):
        super(DevelopmentAppConfig, self).__init__()


class TestAppConfig(AppConfig):
    SNOW_URL = 'https://godaddydev.service-now.com/api/now/table'
    EXEMPT_REPORTERS = {'Sucuri': '0', 'DBP': '0', 'PhishLabs': '0'}
    TRUSTED_REPORTERS = {'threat-hunting-reporter-id'}

    def __init__(self):
        self.DBURL = 'mongodb://guest:guest@localhost/test'
        super(TestAppConfig, self).__init__()


config_by_name = {'dev': DevelopmentAppConfig,
                  'ote': OTEAppConfig,
                  'prod': ProductionAppConfig,
                  'test': TestAppConfig}
