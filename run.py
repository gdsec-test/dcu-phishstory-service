import logging.config
import os
import time

import grpc
import yaml
from celery import Celery
from concurrent import futures

import service.grpc_stub.phishstory_pb2
import service.grpc_stub.phishstory_pb2_grpc
from celeryconfig import CeleryConfig
from service.api.servicenow_impl import SNOW
from service.grpc_stub.phishstory_pb2 import CreateTicketResponse, \
    UpdateTicketResponse, \
    GetTicketsResponse, \
    GetTicketResponse
from service.grpc_stub.phishstory_pb2_grpc import PhishstoryServicer
from settings import config_by_name

app_settings = config_by_name[os.getenv('sysenv') or 'dev']()

capp = Celery()
capp.config_from_object(CeleryConfig())

_ONE_DAY_IN_SECONDS = 86400

path = os.path.dirname(os.path.abspath(__file__)) + '/' + 'logging.yml'
value = os.getenv('LOG_CFG', None)
if value:
    path = value
if os.path.exists(path):
    with open(path, 'rt') as f:
        lconfig = yaml.safe_load(f.read())
    logging.config.dictConfig(lconfig)
else:
    logging.basicConfig(level=logging.INFO)
logging.raiseExceptions = True
logger = logging.getLogger(__name__)



class API(PhishstoryServicer):
    def __init__(self):
        self._api = SNOW(app_settings, capp)

    def CreateTicket(self, request, context):
        logger.info("Received CreateTicket Request: {}".format(request))

        # TO-DO this may need to change
        data = {'type': request.type, 'source': request.source, 'target': request.target,
                'proxy': request.proxy, 'intentional': request.intentional,
                'reporter': request.reporter, 'info': request.info, 'infoUrl': request.infoUrl}

        res = self._api.create_ticket(data)
        return CreateTicketResponse(res.get('ticketId'))

    def GetTicket(self, request, context):
        logger.info("Received GetTicket Request: {}".format(request))

        # TO-DO this may need to change
        res = self._api.get_ticket_info({'ticketId': request.ticketId})
        return GetTicketResponse(res)

    def GetTickets(self, request, context):
        logger.info("Received GetTickets Request: {}".format(request))

        # TO-DO this may need to change
        data = {'type': request.type, 'source': request.source, 'sourceDomainOrIp': request.sourceDomainOrIp,
                'target': request.target, 'isTicketClosed': request.isTicketClosed, 'created': request.created,
                'closed': request.closed, 'proxy': request.proxy, 'intentional': request.intentional,
                'reporter': request.reporter, 'info': request.info, 'infoUrl': request.infoUrl}

        res = self._api.get_tickets(data)
        return GetTicketsResponse(res)

    def UpdateTicket(self, request, context):
        logger.info("Received UpdateTicket Request: {}".format(request))

        # TO-DO this may need to change
        data = {'ticketId': request.ticketId, 'type': request.type, 'isTicketClosed': request.isTicketClosed,
                'target': request.target}

        res = self._api.update_ticket(data)
        return UpdateTicketResponse(res)


def serve():
    # Configure and start service
    server = grpc.server(thread_pool=futures.ThreadPoolExecutor(max_workers=10))
    service.grpc_stub.phishstory_pb2_grpc.add_PhishstoryServicer_to_server(
        API(), server)
    logger.info("Listening on port 5000...")
    server.add_insecure_port('[::]:5000')
    server.start()
    try:
        while True:
            time.sleep(_ONE_DAY_IN_SECONDS)
    except KeyboardInterrupt:
        logger.info("Stopping server")
        server.stop(0)


if __name__ == '__main__':
    serve()
