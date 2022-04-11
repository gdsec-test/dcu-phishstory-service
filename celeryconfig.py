import os

from celery import Celery
from kombu import Exchange, Queue

from settings import config_by_name

app_settings = config_by_name[os.getenv('sysenv', 'dev')]


class CeleryConfig:
    broker_transport = 'pyamqp'
    broker_use_ssl = True
    task_serializer = 'pickle'
    result_serializer = 'json'
    accept_content = ['json']
    imports = 'run'
    worker_send_task_events = False
    worker_hijack_root_logger = False
    WORKER_ENABLE_REMOTE_CONTROL = False

    # TODO CMAPT-5032: remove everything after and including if app_settings.QUORUM_QUEUE for routes and broker_url
    task_routes = {
        'run.process': {
            'queue': Queue(app_settings.GDBS_QUEUE, Exchange(app_settings.GDBS_QUEUE),
                           routing_key=app_settings.GDBS_QUEUE, queue_arguments={'x-queue-type': 'quorum'})}
            if app_settings.QUORUM_QUEUE else {'queue': app_settings.MIDDLEWARE_QUEUE},
        'run.hubstream_sync': {
            'queue': Queue(app_settings.GDBS_QUEUE, Exchange(app_settings.GDBS_QUEUE),
                           routing_key=app_settings.GDBS_QUEUE, queue_arguments={'x-queue-type': 'quorum'})}
            if app_settings.QUORUM_QUEUE else {'queue': app_settings.GDBS_QUEUE}
    }
    broker_url = os.getenv('MULTIPLE_BROKERS') if app_settings.QUORUM_QUEUE else os.getenv('BROKER_URL')


def get_celery() -> Celery:
    capp = Celery()
    capp.config_from_object(CeleryConfig)
    return capp
