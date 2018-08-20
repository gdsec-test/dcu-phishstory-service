import os
import urllib

from settings import config_by_name

app_settings = config_by_name[os.getenv('sysenv', 'dev')]


class CeleryConfig:
    BROKER_TRANSPORT = 'pyamqp'
    BROKER_USE_SSL = True
    CELERY_TASK_SERIALIZER = 'pickle'
    CELERY_RESULT_SERIALIZER = 'json'
    CELERY_ACCEPT_CONTENT = ['json']
    CELERY_IMPORTS = 'run'
    CELERY_SEND_EVENTS = False
    CELERYD_HIJACK_ROOT_LOGGER = False

    CELERY_ROUTES = {
        'run.process': {'queue': app_settings.MIDDLEWARE_QUEUE}
    }

    def __init__(self):
        self.BROKER_PASS = urllib.quote(os.getenv('BROKER_PASS', 'password'))
        self.BROKER_URL = 'amqp://02d1081iywc7A:' + self.BROKER_PASS + '@rmq-dcu.int.godaddy.com:5672/grandma'
