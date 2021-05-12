import logging.config
import os
import time
from concurrent import futures

import grpc
import yaml
from celery import Celery

import pb.phishstory_service_pb2_grpc
from celeryconfig import CeleryConfig
from pb.convertor import dict_to_protobuf, protobuf_to_dict
from pb.phishstory_service_pb2 import (CheckDuplicateResponse,
                                       CreateTicketResponse, GetTicketResponse,
                                       GetTicketsResponse,
                                       UpdateTicketResponse)
from pb.phishstory_service_pb2_grpc import PhishstoryServicer
from service.api.snow_api import SNOWAPI
from settings import config_by_name

app_settings = config_by_name[os.getenv('sysenv', 'dev')]()

capp = Celery()
capp.config_from_object(CeleryConfig())

_ONE_DAY_IN_SECONDS = 86400

path = os.path.dirname(os.path.abspath(__file__)) + '/' + 'logging.yaml'
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
        self._api = SNOWAPI(app_settings, capp)

    def CreateTicket(self, request, context):
        logger.info("Received CreateTicket Request")
        ticket_id = ''

        try:
            data = protobuf_to_dict(request, including_default_value_fields=True)
            logger.info("Fields received in the request : {}".format({'type': data.get('type'),
                                                                      'source': data.get('source'),
                                                                      'reporter': data.get('reporter')}))
            ticket_id = self._api.create_ticket(data)
        except Exception as e:
            context.set_details(str(e))
            context.set_code(grpc.StatusCode.INTERNAL)

        return CreateTicketResponse(ticketId=ticket_id) if ticket_id else CreateTicketResponse()

    def GetTicket(self, request, context):
        logger.info("Received GetTicket Request {}".format(request))
        ticket_info = {}

        try:
            data = protobuf_to_dict(request)
            ticket_info = self._api.get_ticket(data)
        except Exception as e:
            context.set_details(str(e))
            context.set_code(grpc.StatusCode.INTERNAL)

        return dict_to_protobuf(GetTicketResponse, ticket_info, strict=False) if ticket_info else GetTicketResponse()

    def GetTickets(self, request, context):
        logger.info("Received GetTickets Request {}".format(request))
        ticket_ids = {}

        try:
            data = protobuf_to_dict(request)

            '''
            Protobuf3 does not delineate between default values and values that are set but equal to default values.
            In this case any booleans such as 'closed' or 'intentional' will always be False unless set to True.
            Since the behavior provided by always included these booleans in queries is relatively benign, we include them
            regardless whether or not their values are True or False.
            See https://developers.google.com/protocol-buffers/docs/proto3 for more information regarding Protobuf defaults
            '''

            data['closed'] = request.closed
            data['limit'] = request.limit or 100
            data['offset'] = request.offset or 0

            ticket_ids = self._api.get_tickets(data)
        except Exception as e:
            context.set_details(str(e))
            context.set_code(grpc.StatusCode.INTERNAL)

        return dict_to_protobuf(GetTicketsResponse, ticket_ids) if ticket_ids else GetTicketsResponse()

    def UpdateTicket(self, request, context):
        logger.info("Received UpdateTicket Request {}".format(request))

        try:
            data = protobuf_to_dict(request)
            self._api.update_ticket(data)
        except Exception as e:
            context.set_details(str(e))
            context.set_code(grpc.StatusCode.INTERNAL)

        return UpdateTicketResponse()

    def CheckDuplicate(self, request, context):
        logger.info("Received UpdateTicket Request {}".format(request))
        duplicate = None

        try:
            duplicate, _ = self._api.check_duplicate(request.source)
        except Exception as e:
            context.set_details(str(e))
            context.set_code(grpc.StatusCode.INTERNAL)

        return CheckDuplicateResponse(duplicate=duplicate) if duplicate else CheckDuplicateResponse()


def serve():
    # Configure and start service
    server = grpc.server(thread_pool=futures.ThreadPoolExecutor(max_workers=10))
    pb.phishstory_service_pb2_grpc.add_PhishstoryServicer_to_server(
        API(), server)
    logger.info("Listening on port 50051...")
    server.add_insecure_port('[::]:50051')
    server.start()

    try:
        while True:
            time.sleep(_ONE_DAY_IN_SECONDS)
    except KeyboardInterrupt:
        logger.info("Stopping server")
        server.stop(0)


if __name__ == '__main__':
    serve()
