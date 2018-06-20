# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
import grpc

import phishstory_service_pb2 as phishstory__service__pb2


class PhishstoryStub(object):
  # missing associated documentation comment in .proto file
  pass

  def __init__(self, channel):
    """Constructor.

    Args:
      channel: A grpc.Channel.
    """
    self.CreateTicket = channel.unary_unary(
        '/phishstoryservice.Phishstory/CreateTicket',
        request_serializer=phishstory__service__pb2.CreateTicketRequest.SerializeToString,
        response_deserializer=phishstory__service__pb2.CreateTicketResponse.FromString,
        )
    self.UpdateTicket = channel.unary_unary(
        '/phishstoryservice.Phishstory/UpdateTicket',
        request_serializer=phishstory__service__pb2.UpdateTicketRequest.SerializeToString,
        response_deserializer=phishstory__service__pb2.UpdateTicketResponse.FromString,
        )
    self.GetTicket = channel.unary_unary(
        '/phishstoryservice.Phishstory/GetTicket',
        request_serializer=phishstory__service__pb2.GetTicketRequest.SerializeToString,
        response_deserializer=phishstory__service__pb2.GetTicketResponse.FromString,
        )
    self.GetTickets = channel.unary_unary(
        '/phishstoryservice.Phishstory/GetTickets',
        request_serializer=phishstory__service__pb2.GetTicketsRequest.SerializeToString,
        response_deserializer=phishstory__service__pb2.GetTicketsResponse.FromString,
        )
    self.CheckDuplicate = channel.unary_unary(
        '/phishstoryservice.Phishstory/CheckDuplicate',
        request_serializer=phishstory__service__pb2.CheckDuplicateRequest.SerializeToString,
        response_deserializer=phishstory__service__pb2.CheckDuplicateResponse.FromString,
        )


class PhishstoryServicer(object):
  # missing associated documentation comment in .proto file
  pass

  def CreateTicket(self, request, context):
    # missing associated documentation comment in .proto file
    pass
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def UpdateTicket(self, request, context):
    # missing associated documentation comment in .proto file
    pass
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def GetTicket(self, request, context):
    # missing associated documentation comment in .proto file
    pass
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def GetTickets(self, request, context):
    # missing associated documentation comment in .proto file
    pass
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def CheckDuplicate(self, request, context):
    # missing associated documentation comment in .proto file
    pass
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')


def add_PhishstoryServicer_to_server(servicer, server):
  rpc_method_handlers = {
      'CreateTicket': grpc.unary_unary_rpc_method_handler(
          servicer.CreateTicket,
          request_deserializer=phishstory__service__pb2.CreateTicketRequest.FromString,
          response_serializer=phishstory__service__pb2.CreateTicketResponse.SerializeToString,
      ),
      'UpdateTicket': grpc.unary_unary_rpc_method_handler(
          servicer.UpdateTicket,
          request_deserializer=phishstory__service__pb2.UpdateTicketRequest.FromString,
          response_serializer=phishstory__service__pb2.UpdateTicketResponse.SerializeToString,
      ),
      'GetTicket': grpc.unary_unary_rpc_method_handler(
          servicer.GetTicket,
          request_deserializer=phishstory__service__pb2.GetTicketRequest.FromString,
          response_serializer=phishstory__service__pb2.GetTicketResponse.SerializeToString,
      ),
      'GetTickets': grpc.unary_unary_rpc_method_handler(
          servicer.GetTickets,
          request_deserializer=phishstory__service__pb2.GetTicketsRequest.FromString,
          response_serializer=phishstory__service__pb2.GetTicketsResponse.SerializeToString,
      ),
      'CheckDuplicate': grpc.unary_unary_rpc_method_handler(
          servicer.CheckDuplicate,
          request_deserializer=phishstory__service__pb2.CheckDuplicateRequest.FromString,
          response_serializer=phishstory__service__pb2.CheckDuplicateResponse.SerializeToString,
      ),
  }
  generic_handler = grpc.method_handlers_generic_handler(
      'phishstoryservice.Phishstory', rpc_method_handlers)
  server.add_generic_rpc_handlers((generic_handler,))