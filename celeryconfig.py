import os

from celery import Celery

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

    task_routes = {
        'run.process': {'queue': app_settings.MIDDLEWARE_QUEUE},
        'run.hubstream_sync': {'queue': app_settings.GDBS_QUEUE}
    }
    broker_url = os.getenv('BROKER_URL')


def get_celery() -> Celery:
    capp = Celery()
    capp.config_from_object(CeleryConfig)
    return capp
