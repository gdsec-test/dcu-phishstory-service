import json
from urllib.parse import quote_plus

from dcdatabase.emailmongo import EmailMongo
from dcdatabase.phishstorymongo import PhishstoryMongo
from dcustructuredlogginggrpc import get_logging
from requests import codes

from celeryconfig import get_celery
from service.api.interface import DataStore
from service.connectors.snow import SNOWHelper
from service.models.ticket_model import (MIDDLEWARE_MODEL, REPORTER_MODEL,
                                         SUPPORTED_CLOSURES, SUPPORTED_TYPES)


class SNOWAPI(DataStore):
    TICKET_TABLE_NAME = 'u_dcu_ticket'  # SNOW table for Phishstory abuse reports
    KEY_ABUSE_VERIFIED = 'abuseVerified'
    KEY_CLOSED = 'closed'
    KEY_CLOSE_REASON = 'close_reason'
    KEY_EMAIL = 'email'
    KEY_INFO = 'info'
    KEY_METADATA = 'metadata'
    KEY_REPORTER = 'reporter'
    KEY_RESULT = 'result'
    KEY_SOURCE = 'source'
    KEY_SOURCE_SUBDOMAIN = 'sourceSubDomain'
    KEY_TICKET_ID = 'ticketId'
    KEY_TYPE = 'type'
    KEY_U_NUMBER = 'u_number'
    USER_GENERATED_DOMAINS = {'joomla.com', 'wix.com', 'wixsite.com', 'htmlcomponentservice.com', 'sendgrid.net',
                              'mediafire.com', '16mb.com', 'gridserver.com', '000webhost.com', 'filesusr.com',
                              'usrfiles.com', 'site123.me', 'onelink.me', 'i-m.mx', 'tonohost.com', 'backblaze.com',
                              'im-creator.com', 'quizzory.com', 'builderall.com', 'formtools.com', 'bitly.com',
                              'multiscreensite.com', 'sunnylandingpages.com', 'surveyheart.com', 'editorx.io',
                              'forms.app', 'joomag.com', 'company.site'}

    def __init__(self, app_settings):
        self._logger = get_logging()

        self._datastore = SNOWHelper(app_settings)
        self._db = PhishstoryMongo(app_settings)
        self._emaildb = EmailMongo(app_settings)
        self._exempt_reporter_ids = set(app_settings.EXEMPT_REPORTERS.values())
        self._db_impacted = app_settings.DATABASE_IMPACTED
        self._trusted_reporters = app_settings.TRUSTED_REPORTERS

    # Logic defined in https://confluence.godaddy.com/display/ITSecurity/API+Redesign+Proposal
    def _domain_cap_reached(self, abuse_type, reporter_id, subdomain, domain):
        # Don't cap tickets in case of content complaints, usergen domains, and exempted reporters
        if abuse_type == 'CONTENT' or \
                domain in self.USER_GENERATED_DOMAINS or \
                reporter_id in self._exempt_reporter_ids:
            return False

        if not (subdomain or domain):
            return False

        query = {'phishstory_status': {'$ne': 'CLOSED'}, self.KEY_TYPE: abuse_type}

        # Prioritize subdomains as we need to cap per subdomain.
        if subdomain:
            # Treating subdomains that start with www the same compared to the ones that don't start with www.
            # For instance www.abc.com and abc.com are the same.
            if subdomain.startswith('www.') and len(subdomain) > 4:
                query['$or'] = [{self.KEY_SOURCE_SUBDOMAIN: subdomain},
                                {self.KEY_SOURCE_SUBDOMAIN: subdomain[4:]}]
            else:
                query[self.KEY_SOURCE_SUBDOMAIN] = subdomain

        else:
            query['sourceDomainOrIp'] = domain

        incidents = self._db.find_incidents(query=query, limit=5)
        return len(incidents) == 5

    def create_ticket(self, args: dict) -> str:
        """
        Creates a ticket for the provided abuse report in SNOW and MongoDB. Passes filtered arguments to the
        Middleware for further processing and enrichment.
        :param args:
        :return:
        """
        source = args.get(self.KEY_SOURCE)
        generic_error = f'Unable to create new ticket for {source}.'
        _is_trusted_reporter = args.get(self.KEY_REPORTER) in self._trusted_reporters

        if args.get(self.KEY_TYPE) not in SUPPORTED_TYPES:
            raise Exception(f'{generic_error} Unsupported type {args.get(self.KEY_TYPE)}.')

        # reporterEmail should NOT be propagated to SNOW, so we delete the field from args
        reporter_email = args.pop('reporterEmail', None)

        # Need metadata from request.
        reclassified_from = args.get('metadata', {}).get('reclassified_from', None)

        # Check to see if the abuse report has been previously submitted for this source
        _is_duplicate_ticket, _duplicate_ticket_ids = self.check_duplicate(source, reclassified_from)
        if _is_duplicate_ticket:
            # Adds acknowledgement email data into acknowledge_email collection in the DB if DB is available
            # email data = {source, email, created}
            if not self._db_impacted:
                # When _db_impacted is True MongoDB is unavailable and normal DB operations cannot be performed
                if reporter_email:
                    self._emaildb.add_new_email({self.KEY_SOURCE: source, self.KEY_EMAIL: reporter_email})
                # If the original ticket came from a trusted reporter, set an abuseVerified field
                elif _is_trusted_reporter and _duplicate_ticket_ids:
                    for _ticket_id in _duplicate_ticket_ids:
                        self._db.update_incident(_ticket_id, {self.KEY_ABUSE_VERIFIED: True})

            raise Exception(f'{generic_error} There is an existing open ticket.')

        if not self._db_impacted:
            # Bypass domain cap for trusted reporters
            if not _is_trusted_reporter:
                # Check if domain cap has been reached for the particular domain when DB is operational
                if self._domain_cap_reached(args.get(self.KEY_TYPE), args.get(self.KEY_REPORTER),
                                            args.get(self.KEY_SOURCE_SUBDOMAIN), args.get('sourceDomainOrIp')):
                    self._logger.info(f'Domain cap reached for: {source}')
                    raise Exception(f'{generic_error} There is an existing open ticket.')

        try:
            payload = self._datastore.create_post_payload(args)
            response = self._datastore.post_request(f'/{self.TICKET_TABLE_NAME}', payload)

            snow_data = json.loads(response.content)
        except Exception as e:
            self._logger.error(f'Error creating ticket {source} {e}.')
            raise Exception(generic_error)

        if response.status_code != codes.created:
            self._logger.error(f'Expected status code {codes.ok} got status {response.status_code}.')
            raise Exception(generic_error)

        # SNOW ticket created successfully

        if not self._db_impacted:
            args[self.KEY_TICKET_ID] = snow_data[self.KEY_RESULT][self.KEY_U_NUMBER]
            json_for_middleware = {key: args.get(key, None) for key in MIDDLEWARE_MODEL}

            # The metadata sub-document to contain the fraud_score key
            if args.get(self.KEY_METADATA):
                json_for_middleware[self.KEY_METADATA] = args[self.KEY_METADATA]

            # Checking for info field for evidence tracking purposes
            if args.get(self.KEY_INFO):
                json_for_middleware['evidence'] = {
                    'snow': True
                }

            if _is_trusted_reporter:
                json_for_middleware[self.KEY_ABUSE_VERIFIED] = True

            ticket_id = json_for_middleware.get(self.KEY_TICKET_ID)

            # When _db_impacted is True MongoDB is unavailable and normal DB operations cannot be performed
            self._db.add_new_incident(ticket_id, json_for_middleware)

            # Adds acknowledgement email data into acknowledge_email collection in the DB.
            # email data = {source, email, created}
            if reporter_email:
                self._emaildb.add_new_email({self.KEY_SOURCE: source, self.KEY_EMAIL: reporter_email})

            self._send_to_middleware(json_for_middleware)

        return snow_data[self.KEY_RESULT][self.KEY_U_NUMBER]

    def update_ticket(self, args):
        """
        Update the SNOW ticket with provided args, and close the ticket if closed and close_reason is provided.
        :param args:
        :return:
        """
        if self._db_impacted:
            # When _db_impacted is True MongoDB is unavailable and normal DB update operations cannot be performed
            raise Exception('This operation is currently unavailable')

        ticket_id = args.get(self.KEY_TICKET_ID)
        generic_error = f'Unable to update ticket {ticket_id}.'

        if args.get(self.KEY_CLOSED) and not args.get(self.KEY_CLOSE_REASON):
            raise Exception(f'{generic_error} close_reason not provided.')

        if args.get(self.KEY_CLOSED) and args.get(self.KEY_CLOSE_REASON) not in SUPPORTED_CLOSURES:
            raise Exception(f'{generic_error} Invalid close reason provided {args.get(self.KEY_CLOSE_REASON)}.')

        sys_id = self._get_sys_id(ticket_id)
        if not sys_id:
            raise Exception(generic_error)

        try:
            payload = self._datastore.create_post_payload(args)
            query = f'/{self.TICKET_TABLE_NAME}/{sys_id}'
            response = self._datastore.patch_request(query, payload)
        except Exception as e:
            self._logger.error(f'{generic_error} {e}')
            raise Exception(generic_error)

        if response.status_code != codes.ok:
            self._logger.error(f'Expected status code {codes.ok} got status {response.status_code}.')
            raise Exception(generic_error)

        if args.get(self.KEY_CLOSED):
            self._logger.info(f'Closing ticket {ticket_id} with close_reason {args.get(self.KEY_CLOSE_REASON)}.')
            self._db.close_incident(ticket_id, dict(close_reason=args.get(self.KEY_CLOSE_REASON)))
        self.__sync_to_hubstream(ticket_id)

    def get_tickets(self, args):
        """
        Finds all tickets that match Q parameters provided in args and returns the resulting ticketIds and pagination.
        :param args:
        :return:
        """
        generic_error = f'Unable to retrieve tickets matching {args}.'
        args['sysparm_fields'] = self.KEY_U_NUMBER

        try:
            created_start = args.pop('createdStart', None)
            created_end = args.pop('createdEnd', None)
            param_query = self._datastore.create_param_query(created_start, created_end)
            url_args = self._datastore.create_url_parameters(args) + param_query
            query = f'/{self.TICKET_TABLE_NAME}{url_args}'
            response = self._datastore.get_request(query)

            snow_data = json.loads(response.content)
        except Exception as e:
            self._logger.error(f'{generic_error} {e}.')
            raise Exception(generic_error)

        if response.status_code != codes.ok:
            self._logger.info(f'Expected status code {codes.ok} got status {response.status_code}.')
            raise Exception(generic_error)

        if not snow_data.get(self.KEY_RESULT):
            raise Exception(generic_error)

        ticket_dict = {}

        store = response.headers._store
        if 'x-total-count' in store and len(store['x-total-count']) > 1:
            total_records = int(store['x-total-count'][1])
            ticket_dict['pagination'] = SNOWHelper.create_pagination_links(args['offset'], args['limit'],
                                                                           total_records)

        ticket_dict['ticketIds'] = [ticket.get(self.KEY_U_NUMBER) for ticket in snow_data.get(self.KEY_RESULT, [])]
        return ticket_dict

    def get_ticket(self, args):
        """
        Retrieves all SNOW information for a provided ticket_id
        :param args:
        :return:
        """
        ticket_id = args.get(self.KEY_TICKET_ID)
        generic_error = f'Unable to retrieve ticket information for {ticket_id}.'

        ext_user_clause = '&u_reporter=' + args.get(self.KEY_REPORTER) if args.get(self.KEY_REPORTER) else ''
        try:
            query = f'/{self.TICKET_TABLE_NAME}?sysparam_limit=1&u_number={ticket_id}{ext_user_clause}'
            response = self._datastore.get_request(query)

            snow_data = json.loads(response.content)
        except Exception as e:
            self._logger.error(f'{generic_error} {e}')
            raise Exception(generic_error)

        if response.status_code != codes.ok:
            self._logger.error(f'Expected status code {codes.ok} got {response.status_code}.')
            raise Exception(generic_error)

        if not snow_data.get(self.KEY_RESULT):
            raise Exception(generic_error)

        ticket_data = snow_data[self.KEY_RESULT][0]

        # Necessary evil for converting unicode to bool
        ticket_data['u_closed'] = True if 'true' in ticket_data['u_closed'].lower() else False
        return {v: ticket_data[k] for k, v in REPORTER_MODEL.items()}

    def check_duplicate(self, source: str, reclassified_from: str = None) -> tuple:
        """
        Determines whether or not there is an open ticket with an identical source to the one provided.
        :param source: The source of the incoming duplicate check.
        :param reclassified_from: An optional parameter specifying a ticket to exclude from
                                  the duplicate check. Used for the reclassify workflow.
        :return:
        """
        if not source:
            raise Exception('Invalid source provided. Failed to check for duplicate ticket.')

        try:
            url_args = self._datastore.create_url_parameters({self.KEY_CLOSED: 'false',
                                                              self.KEY_SOURCE: quote_plus(source)})
            query = f'/{self.TICKET_TABLE_NAME}{url_args}'
            response = self._datastore.get_request(query)
            snow_data = json.loads(response.content)
            results = snow_data.get(self.KEY_RESULT, [])
            _duplicate_ticket_ids = [
                d.get(self.KEY_U_NUMBER) for d in results if d.get(self.KEY_U_NUMBER) != reclassified_from
            ]
            return len(_duplicate_ticket_ids) > 0, _duplicate_ticket_ids
        except Exception as e:
            self._logger.error(f'Unable to determine if {source} is a duplicate {e}.')
            raise Exception('Unable to complete your request at this time.')

    def _get_sys_id(self, ticket_id):
        """
        Given a ticket_id, attempt to retrieve the associated sys_id which is SNOW's unique identifier
        :param ticket_id:
        :return:
        """
        try:
            query = f'/{self.TICKET_TABLE_NAME}?u_number={ticket_id}'
            response = self._datastore.get_request(query)

            snow_data = json.loads(response.content)
        except Exception as e:
            self._logger.error(f'Unable to retrieve SysId for ticket {ticket_id} {e}.')
            return

        if response.status_code != codes.ok:
            self._logger.error(f'Expected status code {codes.ok} got {response.status_code}.')
            return

        if self.KEY_RESULT not in snow_data:
            self._logger.error(f'"result" does not exist in snow_data {snow_data}.')
            return

        if not snow_data.get(self.KEY_RESULT):
            self._logger.error(f'No records found for {ticket_id}.')
            return

        return snow_data[self.KEY_RESULT][0]['sys_id']

    def _send_to_middleware(self, payload):
        """
        A helper function to send Celery tasks to the Middleware Queue with the provided payload
        :param payload:
        :return:
        """
        try:
            self._logger.info(f'Sending payload to Middleware {payload}.')
            celery = get_celery()
            celery.send_task('run.process', (payload,))
        except Exception as e:
            self._logger.error(f'Unable to send payload to Middleware {payload} {e}.')

    def __sync_to_hubstream(self, ticket_id: str) -> None:
        try:
            self._logger.info(f'Sending payload to GDBS {ticket_id} for Hubstream sync')
            celery = get_celery()
            celery.send_task('run.hubstream_sync', ({self.KEY_TICKET_ID: ticket_id},))
        except Exception as e:
            self._logger.error(f'Error sending payload to GDBS {ticket_id} for Hubstream sync {e}')
