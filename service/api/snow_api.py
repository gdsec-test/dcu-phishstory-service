import json
import logging
import urllib

from dcdatabase.phishstorymongo import PhishstoryMongo

from service.api.interface import DataStore
from service.connectors.snow import SNOWHelper

from requests import codes


class SNOWAPI(DataStore):

    HTML2SNOW = {
        'limit': 'sysparm_limit',
        'offset': 'sysparm_offset',
        'sourceDomainOrIp': 'u_source_domain_or_ip',
        'source': 'u_source',
        'createdStart': 'sys_created_on',
        'createdEnd': 'u_closed_date',
        'type': 'u_type',
        'intentional': 'u_intentional',
        'target': 'u_target',
        'reporter': 'u_reporter',
        'closed': 'u_closed',
        'proxy': 'u_proxy_ip',
        'info': 'u_info',
        'infoUrl': 'u_url_more_info',
        'ticketId': 'u_number'
    }

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

        # Check to see if the abuse report has been previously submitted for this source
        is_duplicate = self._check_duplicate(args.get('source'))
        if is_duplicate is None:
            raise Exception("Unable to complete your request at this time")

        if is_duplicate:
            raise Exception("Unable to create new ticket for {}. There is an existing open ticket".format(args.get('source')))

        try:
            payload = self._create_http_payload(args)
            response = self._datastore.post_request('/{}'.format(self.TICKET_TABLE_NAME), payload)

            snow_data = json.loads(response.content)
        except Exception as e:
            self._logger.error("Error creating ticket {} {}".format(args.get('source'), e.message))
            raise Exception("Unable to create ticket for {}".format(args.get('source')))

        # SNOW ticket created successfully
        if response.status_code == codes.created:
            if args.get('type') in self.SUPPORTED_TYPES:

                args['ticketId'] = snow_data['result']['u_number']
                json_for_middleware = {key: args[key] for key in self.MIDDLEWARE_KEYS}

                if args.get('metadata'):
                    json_for_middleware['metadata'] = args['metadata']

                self._db.add_new_incident(json_for_middleware.get('ticketId'), json_for_middleware)
                self._send_to_middleware(json_for_middleware)

                return json_for_middleware.get('ticketId')

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
            payload = self._create_http_payload(args)
            query = '/{}/{}'.format(self.TICKET_TABLE_NAME, sys_id)
            response = self._datastore.patch_request(query, payload)
        except Exception as e:
            self._logger.error("Unable to update incident {} {}".format(args.get('ticketId'), e.message))
            raise Exception("Unable to update ticket {} at this time".format(args.get('ticketId')))

        if response.status_code == codes.ok:
            if args.get('closed'):
                self._logger.info("Closing ticket {} with close_reason {}".format(args['ticketId'], args['close_reason']))
                self._db.close_incident(args['ticketId'], dict(close_reason=args.get('close_reason')))

    def get_tickets(self, args):
        """
        Finds all tickets that match Q parameters provided in args and returns the resulting ticketIds
        :param args:
        :return:
        """

        # Add entries to args dictionary for pagination
        args['sysparm_fields'] = 'u_number'

        try:
            url_args = self._create_url_params_for_get(args) + '&sysparm_query=active=true^ORDERBYDESCu_number'
            query = '/{}{}'.format(self.TICKET_TABLE_NAME, url_args)
            response = self._datastore.get_request(query)

            snow_data = json.loads(response.content)
        except Exception as e:
            self._logger.error("Unable to retrieve tickets matching {} {}".format(args, e.message))
            raise Exception("Unable to retrieve tickets matching {}".format(args))

        return [ticket.get('u_number') for ticket in snow_data.get('result', [])]

    def get_ticket_info(self, args):
        """
        Retrieves all SNOW information for a provided ticketId
        :param args:
        :return:
        """
        try:
            query = '/{}?sysparam_limit=1&u_number={}'.format(self.TICKET_TABLE_NAME, args.get('ticketId'))
            response = self._datastore.get_request(query)

            snow_data = json.loads(response.content)
        except Exception as e:
            self._logger.error("Unable to retrieve ticket information for {} {}".format(args.get('ticketId'), e.message))
            raise Exception("Unable to retrieve ticket information for {}".format(args.get('ticketId')))

        if response.status_code != codes.ok:
            self._logger.error("Expected status code {} got {}".format(codes.ok, response.status_code))
            raise Exception("Unable to retrieve ticket information for {}".format(args.get('ticketId')))

        self._logger.info("Retrieved info for ticket {}: {}".format(args.get('ticketId'), snow_data))
        if snow_data.get('result'):
            ticket_data = snow_data['result'][0]

            # Necessary evil for converting unicode to bool for gRPC response
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
            url_args = self._create_url_params_for_get({'closed': 'false', 'source': urllib.quote_plus(source)})
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

    def _send_to_middleware(self, data):
        try:
            self._logger.info("Sending payload to Middleware {}".format(data))
            self._celery.send_task('run.process', (data,))
        except Exception as e:
            self._logger.error("Unable to send payload to Middleware {} {}".format(data, e.message))

    def _create_url_params_for_get(self, params):
        """
        Used to create a GET style URL parameter string for SNOW API calls.
        Need a special case for GET TICKETS createdStart and createdEnd, so that
        they employ >= or <= instead of just =

        :param params: A dictionary containing values to convert into URL params
        :return: A URL parameters string
        """
        if not params:
            return ''

        query = []

        created_start = '>='
        created_end = '<='
        all_other = '='

        for key, val in params.iteritems():
            operator = all_other
            if key == 'createdStart':
                operator = created_start
            elif key == 'createdEnd':
                operator = created_end

            k = self.HTML2SNOW[key] if key in self.HTML2SNOW else str(key)
            query.append(k + operator + str(val))
        return '?' + '&'.join(query)

    def _create_http_payload(self, data):
        """
        Used to create a POST style JSON payload string for SNOW API calls
        :return: A JSON string
        """
        params_list = {}

        for key, val in data.iteritems():
            k = self.HTML2SNOW[key] if key in self.HTML2SNOW else key
            params_list[k] = val
        return json.dumps(params_list)
