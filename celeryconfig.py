import os
import urllib

from kombu import Exchange, Queue
from encryption_helper import PasswordDecrypter


class CeleryConfig:
    BROKER_TRANSPORT = 'pyamqp'
    BROKER_USE_SSL = True
    CELERY_TASK_SERIALIZER = 'pickle'
    CELERY_RESULT_SERIALIZER = 'json'
    CELERY_ACCEPT_CONTENT = ['json']
    CELERY_IMPORTS = 'run'
    CELERYD_HIJACK_ROOT_LOGGER = False

    def __init__(self, task, queue):
        self.CELERY_QUEUES = (
            Queue(queue, Exchange(queue), routing_key=queue),
        )
        self.CELERY_ROUTES = {task: {'queue': queue}}
        self.BROKER_PASS = os.getenv('BROKER_PASS') or 'password'
        self.BROKER_PASS = urllib.quote(PasswordDecrypter.decrypt(self.BROKER_PASS))
        self.BROKER_URL = 'amqp://02d1081iywc7A:' + self.BROKER_PASS + '@rmq-dcu.int.godaddy.com:5672/grandma'
