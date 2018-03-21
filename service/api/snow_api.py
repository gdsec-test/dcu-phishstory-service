import json
import logging
import urllib

from dcdatabase.phishstorymongo import PhishstoryMongo

from service.api.interface import DataStore
from service.connectors.snow import SNOWHelper

from requests import codes


class SNOWAPI(DataStore):

    EXTERNAL_DATA = {
        'u_number': 'ticketId',
        'u_reporter': 'reporter',
        'u_source': 'source',
        'u_source_domain_or_ip': 'sourceDomainOrIp',
        'u_closed': 'closed',
        'sys_created_on': 'createdAt',
        'u_closed_date': 'closedAt',
        'u_type': 'type',
        'u_target': 'target',
        'u_proxy_ip': 'proxy'
    }

    MIDDLEWARE_KEYS = ['ticketId',
                       'type',
                       'source',
                       'sourceDomainOrIp',
                       'sourceSubDomain',
                       'target',
                       'proxy',
                       'reporter']

    SUPPORTED_TYPES = ['PHISHING', 'MALWARE', 'SPAM', 'NETWORK_ABUSE']

    TICKET_TABLE_NAME = 'u_dcu_ticket'

    def __init__(self, app_settings, celery):
        self._logger = logging.getLogger(__name__)

        self._datastore = SNOWHelper(app_settings)
        self._db = PhishstoryMongo(app_settings)
        self._celery = celery

    def create_ticket(self, args):
        """
        Creates a ticket for the provided abuse report in SNOW and MongoDB. Passes along filtered arguments to
        the middleware queue for further processing and enrichment.
        :param args:
        :return:
        """
        source = args.get('source')

        # Check to see if the abuse report has been previously submitted for this source
        is_duplicate = self._check_duplicate(source)
        if is_duplicate is None:
            raise Exception("Unable to complete your request at this time")

        if is_duplicate:
            raise Exception("Unable to create new ticket for {}. There is an existing open ticket".format(source))

        try:
            payload = self._datastore.create_post_payload(args)
            response = self._datastore.post_request('/{}'.format(self.TICKET_TABLE_NAME), payload)

            snow_data = json.loads(response.content)
        except Exception as e:
            self._logger.error("Error creating ticket {} {}".format(source, e.message))
            raise Exception("Unable to create ticket for {}".format(source))

        # SNOW ticket created successfully
        if response.status_code == codes.created and args.get('type') in self.SUPPORTED_TYPES:
            args['ticketId'] = snow_data['result']['u_number']
            json_for_middleware = {key: args[key] for key in self.MIDDLEWARE_KEYS}

            if args.get('metadata'):
                json_for_middleware['metadata'] = args['metadata']

            ticket_id = json_for_middleware.get('ticketId')
            self._db.add_new_incident(ticket_id, json_for_middleware)
            self._send_to_middleware(json_for_middleware)

            return ticket_id

    def update_ticket(self, args):
        """
        Update the SNOW ticket with provided args, and close the ticket if closed and close_reason is provided.
        :param args:
        :return:
        """
        if args.get('closed') and not args.get('close_reason'):
            raise Exception("Unable to close ticket {}. close_reason not provided".format(args.get('ticketId')))

        sys_id = self._get_sys_id(args.get('ticketId'))
        if not sys_id:
            raise Exception("Unable to update ticket {} at this time".format(args.get('ticketId')))

        try:
            payload = self._datastore.create_post_payload(args)
            query = '/{}/{}'.format(self.TICKET_TABLE_NAME, sys_id)
            response = self._datastore.patch_request(query, payload)
        except Exception as e:
            self._logger.error("Unable to update incident {} {}".format(args.get('ticketId'), e.message))
            raise Exception("Unable to update ticket {} at this time".format(args.get('ticketId')))

        if response.status_code == codes.ok and args.get('closed'):
            self._logger.info("Closing ticket {} with close_reason {}".format(args['ticketId'], args['close_reason']))
            self._db.close_incident(args['ticketId'], dict(close_reason=args.get('close_reason')))

    def get_tickets(self, args):
        """
        Finds all tickets that match Q parameters provided in args and returns the resulting ticketIds
        :param args:
        :return:
        """
        args['sysparm_fields'] = 'u_number'

        try:
            url_args = self._datastore.create_url_parameters(args) + '&sysparm_query=active=true^ORDERBYDESCu_number'
            query = '/{}{}'.format(self.TICKET_TABLE_NAME, url_args)
            response = self._datastore.get_request(query)

            snow_data = json.loads(response.content)
        except Exception as e:
            self._logger.error("Unable to retrieve tickets matching {} {}".format(args, e.message))
            raise Exception("Unable to retrieve tickets matching {}".format(args))

        ticket_dict = {}

        if response.status_code == codes.ok:
            store = response.headers._store
            if 'x-total-count' in store and len(store['x-total-count']) > 1:
                total_records = int(store['x-total-count'][1])
                ticket_dict['pagination'] = SNOWHelper.create_pagination_links(args['offset'], args['limit'],
                                                                               total_records)

        ticket_dict['ticketIds'] = [ticket.get('u_number') for ticket in snow_data.get('result', [])]
        return ticket_dict

    def get_ticket(self, ticket_id):
        """
        Retrieves all SNOW information for a provided ticketId
        :param ticket_id:
        :return:
        """

        try:
            query = '/{}?sysparam_limit=1&u_number={}'.format(self.TICKET_TABLE_NAME, ticket_id)
            response = self._datastore.get_request(query)

            snow_data = json.loads(response.content)
        except Exception as e:
            self._logger.error("Unable to retrieve ticket information for {} {}".format(ticket_id, e.message))
            raise Exception("Unable to retrieve ticket information for {}".format(ticket_id))

        if response.status_code != codes.ok:
            self._logger.error("Expected status code {} got {}".format(codes.ok, response.status_code))
            raise Exception("Unable to retrieve ticket information for {}".format(ticket_id))

        self._logger.info("Retrieved info for ticket {}: {}".format(ticket_id, snow_data))
        if snow_data.get('result'):
            ticket_data = snow_data['result'][0]

            # Necessary evil for converting unicode to bool
            ticket_data['u_closed'] = True if 'true' in ticket_data['u_closed'].lower() else False
            return {v: ticket_data[k] for k, v in self.EXTERNAL_DATA.iteritems()}

    def _check_duplicate(self, source):
        """
        Determines whether or not a ticket is currently "Open" matching the provided source
        :param source:
        :return:
        """
        if not source:
            self._logger.error("Invalid source provided. Failed to check for duplicate ticket")
            return

        try:
            url_args = self._datastore.create_url_parameters({'closed': 'false', 'source': urllib.quote_plus(source)})
            query = '/{}{}'.format(self.TICKET_TABLE_NAME, url_args)
            response = self._datastore.get_request(query)

            snow_data = json.loads(response.content)
        except Exception as e:
            self._logger.error("Unable to determine if {} is a duplicate {}".format(source, e.message))
            return

        return bool(snow_data.get('result'))

    def _get_sys_id(self, ticket_id):
        """
        Given a ticketId, attempt to retrieve the associated sys_id to retrieve all related information.
        :param ticket_id:
        :return:
        """
        try:
            query = '/{}?u_number={}'.format(self.TICKET_TABLE_NAME, ticket_id)
            response = self._datastore.get_request(query)

            snow_data = json.loads(response.content)
        except Exception as e:
            self._logger.error("Unable to retrieve SysId for ticket {} {}".format(ticket_id, e.message))
            return

        if response.status_code != codes.ok:
            self._logger.error("Expected status code {} got {}".format(codes.ok, response.status_code))
            return

        if 'result' not in snow_data:
            self._logger.error("'result' does not exist in snow_data {}".format(snow_data))
            return

        if not snow_data.get('result'):
            self._logger.error("No records found for {}".format(ticket_id))
            return

        return snow_data['result'][0]['sys_id']

    def _send_to_middleware(self, payload):
        try:
            self._logger.info("Sending payload to Middleware {}".format(payload))
            self._celery.send_task('run.process', (payload,))
        except Exception as e:
            self._logger.error("Unable to send payload to Middleware {} {}".format(payload, e.message))
