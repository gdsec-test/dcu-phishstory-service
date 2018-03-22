import logging.config
import os
import time

import grpc
import yaml
import pb.phishstory_pb2_grpc
from celery import Celery
from concurrent import futures
from pb.convertor import protobuf_to_dict, dict_to_protobuf
from pb.phishstory_pb2_grpc import PhishstoryServicer

from celeryconfig import CeleryConfig
from pb.phishstory_pb2 import CreateTicketResponse, \
    UpdateTicketResponse, \
    GetTicketsResponse, \
    GetTicketResponse
from service.api.snow_api import SNOWAPI
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
        self._api = SNOWAPI(app_settings, capp)

    def CreateTicket(self, request, context):
        logger.info("Received CreateTicket Request {}".format(request))

        try:
            data = protobuf_to_dict(request, including_default_value_fields=True)
            ticket_id = self._api.create_ticket(data)
        except Exception as e:
            context.set_details(e.message)
            context.set_code(grpc.StatusCode.INTERNAL)
            return CreateTicketResponse()

        return CreateTicketResponse(ticketId=ticket_id)

    def GetTicket(self, request, context):
        logger.info("Received GetTicket Request {}".format(request))

        try:
            ticket_info = self._api.get_ticket(request.ticketId)
        except Exception as e:
            context.set_details(e.message)
            context.set_code(grpc.StatusCode.INTERNAL)
            return GetTicketResponse()

        return dict_to_protobuf(GetTicketResponse, ticket_info, strict=False)

    def GetTickets(self, request, context):
        logger.info("Received GetTickets Request {}".format(request))

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
            context.set_details(e.message)
            context.set_code(grpc.StatusCode.INTERNAL)
            return GetTicketsResponse()

        return dict_to_protobuf(GetTicketsResponse, ticket_ids)

    def UpdateTicket(self, request, context):
        logger.info("Received UpdateTicket Request {}".format(request))

        try:
            data = protobuf_to_dict(request)
            self._api.update_ticket(data)
        except Exception as e:
            context.set_details(e.message)
            context.set_code(grpc.StatusCode.INTERNAL)
            return UpdateTicketResponse()

        return UpdateTicketResponse()


def serve():
    # Configure and start service
    server = grpc.server(thread_pool=futures.ThreadPoolExecutor(max_workers=10))
    pb.phishstory_pb2_grpc.add_PhishstoryServicer_to_server(
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
