import os
import urllib
from distutils.util import strtobool


class AppConfig(object):
    SNOW_URL = None
    SNOW_USER = 'dcuapi'

    DBURL = 'localhost'
    DB = 'test'
    DB_USER = 'user'
    DB_HOST = 'localhost'
    COLLECTION = 'incidents'
    EMAIL_COLLECTION = 'acknowledge_email'

    def __init__(self):
        self.SNOW_PASS = os.getenv('SNOW_PASS', 'snow_pass')
        self.DB_PASS = urllib.quote(os.getenv('DB_PASS', 'password'))
        self.DBURL = 'mongodb://{}:{}@{}/{}'.format(self.DB_USER, self.DB_PASS, self.DB_HOST, self.DB)
        self.DATABASE_IMPACTED = strtobool(os.getenv('DATABASE_IMPACTED', 'False'))


class ProductionAppConfig(AppConfig):
    SNOW_URL = 'https://godaddy.service-now.com/api/now/table'
    MIDDLEWARE_QUEUE = 'dcumiddleware'
    EXEMPT_REPORTERS = {'Sucuri': '198103515', 'DBP': '290638894', 'PhishLabs': '129092584'}

    DB = 'phishstory'
    DB_HOST = '10.22.9.209'
    DB_USER = 'sau_p_phish'

    def __init__(self):
        super(ProductionAppConfig, self).__init__()


class OTEAppConfig(AppConfig):
    SNOW_URL = 'https://godaddytest.service-now.com/api/now/table'
    MIDDLEWARE_QUEUE = 'otedcumiddleware'
    EXEMPT_REPORTERS = {'Sucuri': '1500070951', 'DBP': '1500495186', 'PhishLabs': '908557'}

    DB = 'otephishstory'
    DB_HOST = '10.22.9.209'
    DB_USER = 'sau_o_phish'

    def __init__(self):
        super(OTEAppConfig, self).__init__()


class DevelopmentAppConfig(AppConfig):
    SNOW_URL = 'https://godaddydev.service-now.com/api/now/table'
    MIDDLEWARE_QUEUE = 'devdcumiddleware'
    EXEMPT_REPORTERS = {'dcuapi_test_dev': '1054985'}

    DB = 'devphishstory'
    DB_HOST = '10.36.156.188'
    DB_USER = 'devuser'

    def __init__(self):
        super(DevelopmentAppConfig, self).__init__()


class TestAppConfig(AppConfig):
    SNOW_URL = 'https://godaddydev.service-now.com/api/now/table'
    EXEMPT_REPORTERS = {'Sucuri': '0', 'DBP': '0', 'PhishLabs': '0'}

    DBURL = 'localhost'
    DB = 'devphishstory'


config_by_name = {'dev': DevelopmentAppConfig,
                  'ote': OTEAppConfig,
                  'prod': ProductionAppConfig,
                  'test': TestAppConfig}
