import os
import urllib

from encryption_helper import PasswordDecrypter


class AppConfig:
    SNOW_URL = None

    SNOW_USER = 'dcuapi'

    DBURL = 'localhost'
    DB = 'test'
    DB_USER = 'user'
    DB_HOST = 'localhost'
    COLLECTION = 'incidents'

    def __init__(self):
        self.SNOW_PASS = PasswordDecrypter.decrypt(os.getenv('SNOW_PASS') or 'password')
        self.DB_PASS = os.getenv('DB_PASS') or 'password'
        self.DB_PASS = urllib.quote(PasswordDecrypter.decrypt(self.DB_PASS))
        self.DBURL = 'mongodb://{}:{}@{}/{}'.format(self.DB_USER, self.DB_PASS, self.DB_HOST, self.DB)


class ProductionAppConfig(AppConfig):
    SNOW_URL = 'https://godaddy.service-now.com/api/now/table'
    MIDDLEWARE_QUEUE = 'dcumiddleware'

    DB = 'phishstory'
    DB_HOST = '10.22.9.209'
    DB_USER = 'sau_p_phish'


class OTEAppConfig(AppConfig):
    SNOW_URL = 'https://godaddytest.service-now.com/api/now/table'
    MIDDLEWARE_QUEUE = 'otedcumiddleware'

    DB = 'otephishstory'
    DB_HOST = '10.22.9.209'
    DB_USER = 'sau_o_phish'


class DevelopmentAppConfig(AppConfig):
    SNOW_URL = 'https://godaddydev.service-now.com/api/now/table'
    MIDDLEWARE_QUEUE = 'devdcumiddleware'

    DB = 'devphishstory'
    DB_HOST = '10.22.188.208'
    DB_USER = 'devuser'


class TestAppConfig(AppConfig):
    SNOW_URL = 'https://godaddydev.service-now.com/api/now/table'

    DBURL = 'mongodb://devuser:phishstory@10.22.188.208/devphishstory'
    DB = 'devphishstory'

config_by_name = {'dev': DevelopmentAppConfig,
                  'ote': OTEAppConfig,
                  'prod': ProductionAppConfig,
                  'test': TestAppConfig}
