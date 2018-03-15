import json
import logging
import urllib

from dcdatabase.phishstorymongo import PhishstoryMongo

from service.api.interface import DataStore
from service.connectors.snow import SNOWHelper


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

    TICKET_TABLE_NAME = 'u_dcu_ticket'

    def __init__(self, app_settings, celery):
        self._logger = logging.getLogger(__name__)

        self._datastore = SNOWHelper(app_settings)
        self._db = PhishstoryMongo(app_settings)
        self._celery = celery

    def check_duplicate(self, source):
        """
        Determines whether or not a ticket is currently "Open" matching the provided source
        :param source:
        :return:
        """
        if not source:
            self._logger.error("Invalid source URL provided. Failed to check for duplicate ticket")
            return None

        try:
            url_args = self._create_url_params_string({'closed': 'false', 'source': urllib.quote_plus(source)})
            query = '/{table_name}{url_args}'.format(table_name=self.TICKET_TABLE_NAME, url_args=url_args)

            response = self._datastore.get_request(query)
            snow_data = json.loads(response.content)
        except Exception as e:
            self._logger.error("Unable to retrieve result from datastore for {} {}".format(source, e.message))
            return None

        return bool(snow_data.get('result'))

    def create_ticket(self, args):
        """
        Creates a ticket for the provided abuse report in SNOW and MongoDB. Passes along filtered arguments to
        the middleware queue for further processing and enrichment.
        :param args:
        :return:
        """

        # Check to see if the abuse report has been previously submitted for this source
        is_duplicate = self.check_duplicate(args.get('source'))
        if is_duplicate or is_duplicate is None:
            return None

        try:
            response = self._datastore.post_request('/{}'.format(self.TICKET_TABLE_NAME), self._create_json_string(args))
            snow_data = json.loads(response.content)
        except Exception as e:
            self._logger.error("Error while creating ticket for source {} {}".format(args.get('source'), e.message))
            return None

        # SNOW ticket created successfully
        if response.status_code == 201:

            if args.get('type') in ['PHISHING', 'MALWARE', 'SPAM', 'NETWORK_ABUSE']:
                args['ticketId'] = snow_data['result']['u_number']
                json_for_middleware = {key: args[key] for key in self.MIDDLEWARE_KEYS}

                if args.get('metadata'):
                    json_for_middleware['metadata'] = args.get('metadata')

                self._db.add_new_incident(json_for_middleware.get('ticketId'), json_for_middleware)
                self.send_to_middleware(json_for_middleware)

                return json_for_middleware.get('ticketId')
        return None

    def send_to_middleware(self, data):
        try:
            self._logger.info("Attempting to send payload to Middleware: {}".format(data))
            self._celery.send_task('run.process', (data,))
        except Exception as e:
            self._logger.error("Error sending payload to Middleware {} {}".format(data, e.message))


    def update_ticket(self, args):
        """
        Update the SNOW ticket with provided args, and close the ticket if closed and close_reason is provided.
        :param args:
        :return:
        """
        if args.get('closed') and not args.get('close_reason'):
            self._logger.error("Unable to close ticket, close_reason not provided {}".format(args.get('ticketId')))
            return None

        sys_id = self._get_sys_id(args.get('ticketId'))
        if not sys_id:
            return None

        self._logger.info("Attempting to update ticket: {}".format(args.get('ticketId')))

        try:
            query = '/{}/{}'.format(self.TICKET_TABLE_NAME, sys_id)
            response = self._datastore.patch_request(query, self._create_json_string(args))

            snow_data = json.loads(response.content)
            self._logger.info("RESPONSE CONTENT: {}".format(snow_data))
        except Exception as e:
            self._logger.error("Error while updating incident {} {}".format(args.get('ticketId'), e.message))
            return None

        if response.status_code == 200:
            if args.get('closed'):
                self._db.close_incident(args['ticketId'], dict(close_reason=args.get('close_reason')))

        return snow_data


    def get_tickets(self, args):
        """
        Finds all tickets that match Q parameters provided in args and returns the resulting ticketIds
        :param args:
        :return:
        """

        # Add entries to args dictionary for pagination
        args['sysparm_fields'] = 'u_number'

        try:
            url_args = self._create_url_params_string(args) + '&sysparm_query=active=true^ORDERBYDESCu_number'
            query = '/{table_name}{url_args}'.format(table_name=self.TICKET_TABLE_NAME, url_args=url_args)

            response = self._datastore.get_request(query)
            snow_data = json.loads(response.content)
        except Exception as e:
            self._logger.error("Error while getting tickets {} {}".format(args, e.message))
            return None

        ticket_ids = []

        if response.status_code == 200:
            for ticket in snow_data.get('result', []):
                ticket_ids.append(ticket.get('u_number'))
        return ticket_ids


    def get_ticket_info(self, args):
        """
        Retrieves all SNOW information for a provided ticketId
        :param args:
        :return:
        """
        try:
            query = '/{table_name}?sysparam_limit=1&u_number={ticketId}'.format(
                table_name=self.TICKET_TABLE_NAME,
                ticketId=args.get('ticketId'))
            response = self._datastore.get_request(query)

            snow_data = json.loads(response.content)
        except Exception as e:
            self._logger.error("Error retrieving ticket info for {} {}".format(args.get('ticketId'), e.message))
            return None

        ticket_data = {}

        if response.status_code == 200:
            self._logger.info("Retrieved info for ticket {}: {}".format(args.get('ticketId'), snow_data))
            if snow_data.get('result'):
                ticket_data = snow_data['result'][0]

        # To-Do Find a simpler way of converting 'u_closed' to the proper boolean value
        converted = {}
        for k, v in ticket_data.iteritems():
            if k in self.EXTERNAL_DATA:
                if k == 'u_closed':
                    v = bool(v)
                converted[self.EXTERNAL_DATA[k]] = v
        return converted


    def _create_url_params_string(self, params):
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

            if key not in self.HTML2SNOW:
                query.append(str(key) + operator + str(val))
            else:
                query.append(self.HTML2SNOW[key] + operator + str(val))
        return '?' + '&'.join(query)

    def _create_json_string(self, data):
        """
        Used to create a POST style JSON payload string for SNOW API calls
        :return: A JSON string
        """
        params_list = {}

        for key, val in data.iteritems():
            if key in self.HTML2SNOW:
                params_list[self.HTML2SNOW[key]] = val
            else:
                params_list[key] = val
        return json.dumps(params_list)

    def _convert_snow_to_mongo(self, data):
        """
        Converts data returned in SNOW format to one digestible by MongoDB
        :param data:
        :return:
        """
        ext_data = {}
        for key, swagKey in self.EXTERNAL_DATA.iteritems():
            ext_data[swagKey] = data[key] if key in data else None
        return ext_data

    def _get_sys_id(self, ticketId):
        """
        Given a ticketId, attempt to retrieve the associated sys_id to retrieve all related information.
        :param ticketId:
        :return:
        """
        self._logger.info("Attempting to retrieve SysId for {}".format(ticketId))

        try:
            query = '/{table}?u_number={ticket}'.format(table=self.TICKET_TABLE_NAME, ticket=ticketId)
            response = self._datastore.get_request(query)

            snow_data = json.loads(response.content)
        except Exception as e:
            self._logger.error("Error while retrieving SysID for Ticket {} {}".format(ticketId, e.message))
            return None

        if response.status_code != 200:
            self._logger.error("Expected status code 200 got {}".format(response.status_code))
            return None

        if 'result' not in snow_data:
            self._logger.error("Unable to complete your request at this time")
            return None

        if not snow_data.get('result'):
            self._logger.error("No records found for {}".format(ticketId))
            return None

        return snow_data['result'][0]['sys_id']
