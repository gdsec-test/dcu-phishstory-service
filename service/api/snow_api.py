import json
import logging
import urllib

from dcdatabase.emailmongo import EmailMongo
from dcdatabase.phishstorymongo import PhishstoryMongo
from requests import codes

from service.api.interface import DataStore
from service.connectors.snow import SNOWHelper
from service.models.ticket_model import (MIDDLEWARE_MODEL, REPORTER_MODEL,
                                         SUPPORTED_CLOSURES, SUPPORTED_TYPES)


class SNOWAPI(DataStore):
    TICKET_TABLE_NAME = 'u_dcu_ticket'  # SNOW table for Phishstory abuse reports
    EMAIL_KEY = 'email'
    SOURCE_KEY = 'source'

    def __init__(self, app_settings, celery):
        self._logger = logging.getLogger(__name__)

        self._datastore = SNOWHelper(app_settings)
        self._db = PhishstoryMongo(app_settings)
        self._emaildb = EmailMongo(app_settings)
        self._celery = celery

    def create_ticket(self, args):
        """
        Creates a ticket for the provided abuse report in SNOW and MongoDB. Passes filtered arguments to the
        Middleware for further processing and enrichment.
        :param args:
        :return:
        """
        source = args.get(self.SOURCE_KEY)
        generic_error = "Unable to create new ticket for {}.".format(source)

        if args.get('type') not in SUPPORTED_TYPES:
            raise Exception(generic_error + " Unsupported type {}.".format(args.get('type')))

        # reporterEmail should NOT be propagated to SNOW, so we delete the field from args
        reporter_email = args.pop('reporterEmail', None)

        # Check to see if the abuse report has been previously submitted for this source
        if self.check_duplicate(source):
            # Adds acknowledgement email data into acknowledge_email collection in the DB.
            # email data = {source, email, created}
            if reporter_email:
                self._emaildb.add_new_email({self.SOURCE_KEY: source, self.EMAIL_KEY: reporter_email})

            raise Exception(generic_error + " There is an existing open ticket.")

        try:
            payload = self._datastore.create_post_payload(args)
            response = self._datastore.post_request('/{}'.format(self.TICKET_TABLE_NAME), payload)

            snow_data = json.loads(response.content)
        except Exception as e:
            self._logger.error("Error creating ticket {} {}.".format(source, e.message))
            raise Exception(generic_error)

        if response.status_code != codes.created:
            self._logger.error("Expected status code {} got status {}.".format(codes.ok, response.status_code))
            raise Exception(generic_error)

        # SNOW ticket created successfully
        args['ticketId'] = snow_data['result']['u_number']
        json_for_middleware = {key: args[key] for key in MIDDLEWARE_MODEL}

        if args.get('metadata'):
            json_for_middleware['metadata'] = args['metadata']

        # Checking for info field for evidence tracking purposes
        if args.get('info'):
            json_for_middleware['evidence'] = {
                'iris': args['info'] == 'IRIS',
                'snow': args['info'] != 'IRIS'
            }

        ticket_id = json_for_middleware.get('ticketId')
        self._db.add_new_incident(ticket_id, json_for_middleware)

        # Adds acknowledgement email data into acknowledge_email collection in the DB.
        # email data = {source, email, created}
        if reporter_email:
            self._emaildb.add_new_email({self.SOURCE_KEY: source, self.EMAIL_KEY: reporter_email})

        self._send_to_middleware(json_for_middleware)

        return ticket_id

    def update_ticket(self, args):
        """
        Update the SNOW ticket with provided args, and close the ticket if closed and close_reason is provided.
        :param args:
        :return:
        """
        ticket_id = args.get('ticketId')
        generic_error = "Unable to update ticket {}.".format(ticket_id)

        if args.get('closed') and not args.get('close_reason'):
            raise Exception(generic_error + " close_reason not provided.".format(ticket_id))

        if args.get('closed') and args.get('close_reason') not in SUPPORTED_CLOSURES:
            raise Exception(generic_error + " Invalid close reason provided {}.".format(args.get('close_reason')))

        sys_id = self._get_sys_id(ticket_id)
        if not sys_id:
            raise Exception(generic_error.format)

        try:
            payload = self._datastore.create_post_payload(args)
            query = '/{}/{}'.format(self.TICKET_TABLE_NAME, sys_id)
            response = self._datastore.patch_request(query, payload)
        except Exception as e:
            self._logger.error(generic_error + " {}".format(e.message))
            raise Exception(generic_error.format(args.get('ticketId')))

        if response.status_code != codes.ok:
            self._logger.error("Expected status code {} got status {}.".format(codes.ok, response.status_code))
            raise Exception(generic_error.format)

        if args.get('closed'):
            self._logger.info("Closing ticket {} with close_reason {}.".format(args['ticketId'], args['close_reason']))
            self._db.close_incident(args['ticketId'], dict(close_reason=args.get('close_reason')))

    def get_tickets(self, args):
        """
        Finds all tickets that match Q parameters provided in args and returns the resulting ticketIds and pagination.
        :param args:
        :return:
        """
        generic_error = "Unable to retrieve tickets matching {}.".format(args)
        args['sysparm_fields'] = 'u_number'

        try:
            created_start = args.pop('createdStart', None)
            created_end = args.pop('createdEnd', None)
            param_query = self._datastore.create_param_query(created_start, created_end)
            url_args = self._datastore.create_url_parameters(args) + param_query
            query = '/{}{}'.format(self.TICKET_TABLE_NAME, url_args)
            response = self._datastore.get_request(query)

            snow_data = json.loads(response.content)
        except Exception as e:
            self._logger.error(generic_error + " {}.".format(e.message))
            raise Exception(generic_error)

        if response.status_code != codes.ok:
            self._logger.info("Expected status code {} got status {}.".format(codes.ok, response.status_code))
            raise Exception(generic_error)

        if not snow_data.get('result'):
            raise Exception(generic_error)

        ticket_dict = {}

        store = response.headers._store
        if 'x-total-count' in store and len(store['x-total-count']) > 1:
            total_records = int(store['x-total-count'][1])
            ticket_dict['pagination'] = SNOWHelper.create_pagination_links(args['offset'], args['limit'],
                                                                           total_records)

        ticket_dict['ticketIds'] = [ticket.get('u_number') for ticket in snow_data.get('result', [])]
        return ticket_dict

    def get_ticket(self, args):
        """
        Retrieves all SNOW information for a provided ticket_id
        :param args:
        :return:
        """
        ticket_id = args.get('ticketId')
        generic_error = "Unable to retrieve ticket information for {}.".format(ticket_id)

        ext_user_clause = '&u_reporter=' + args.get('reporter') if args.get('reporter') else ''
        try:
            query = '/{}?sysparam_limit=1&u_number={}{}'.format(self.TICKET_TABLE_NAME, ticket_id, ext_user_clause)
            response = self._datastore.get_request(query)

            snow_data = json.loads(response.content)
        except Exception as e:
            self._logger.error(generic_error + " {}".format(e.message))
            raise Exception(generic_error)

        if response.status_code != codes.ok:
            self._logger.error("Expected status code {} got {}.".format(codes.ok, response.status_code))
            raise Exception(generic_error)

        if not snow_data.get('result'):
            raise Exception(generic_error)

        ticket_data = snow_data['result'][0]

        # Necessary evil for converting unicode to bool
        ticket_data['u_closed'] = True if 'true' in ticket_data['u_closed'].lower() else False
        return {v: ticket_data[k] for k, v in REPORTER_MODEL.iteritems()}

    def check_duplicate(self, source):
        """
        Determines whether or not there is an open ticket with an identical source to the one provided.
        :param source:
        :return:
        """
        if not source:
            raise Exception("Invalid source provided. Failed to check for duplicate ticket.")

        try:
            url_args = self._datastore.create_url_parameters({'closed': 'false',
                                                              self.SOURCE_KEY: urllib.quote_plus(source)})
            query = '/{}{}'.format(self.TICKET_TABLE_NAME, url_args)
            response = self._datastore.get_request(query)

            snow_data = json.loads(response.content)
        except Exception as e:
            self._logger.error("Unable to determine if {} is a duplicate {}.".format(source, e.message))
            raise Exception("Unable to complete your request at this time.")

        return bool(snow_data.get('result'))

    def _get_sys_id(self, ticket_id):
        """
        Given a ticket_id, attempt to retrieve the associated sys_id which is SNOW's unique identifier
        :param ticket_id:
        :return:
        """
        try:
            query = '/{}?u_number={}'.format(self.TICKET_TABLE_NAME, ticket_id)
            response = self._datastore.get_request(query)

            snow_data = json.loads(response.content)
        except Exception as e:
            self._logger.error("Unable to retrieve SysId for ticket {} {}.".format(ticket_id, e.message))
            return

        if response.status_code != codes.ok:
            self._logger.error("Expected status code {} got {}.".format(codes.ok, response.status_code))
            return

        if 'result' not in snow_data:
            self._logger.error("'result' does not exist in snow_data {}.".format(snow_data))
            return

        if not snow_data.get('result'):
            self._logger.error("No records found for {}.".format(ticket_id))
            return

        return snow_data['result'][0]['sys_id']

    def _send_to_middleware(self, payload):
        """
        A helper function to send Celery tasks to the Middleware Queue with the provided payload
        :param payload:
        :return:
        """
        try:
            self._logger.info("Sending payload to Middleware {}.".format(payload))
            self._celery.send_task('run.process', (payload,))
        except Exception as e:
            self._logger.error("Unable to send payload to Middleware {} {}.".format(payload, e.message))
