import json
import urllib

from celery import Celery
from dcdatabase.phishstorymongo import PhishstoryMongo
from flask import Response
from flask import make_response

from celeryconfig import CeleryConfig

from service.api.interface import DataStore
from service.classlogger import class_logger
from service.connectors.snow import SnowAccess


@class_logger
class ServiceNowDataStore(DataStore):
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

    TICKET_TABLE_NAME = 'u_dcu_ticket'
    DEFAULT_ERROR_CODE = 422

    def __init__(self, app_settings):
        self._datastore = SnowAccess(app_settings)
        self._db = PhishstoryMongo(app_settings)

        self._capp = Celery().config_from_object(CeleryConfig(app_settings.api_task, app_settings.api_queue))

    def clean_for_middleware(self, json_string):
        middleware_keys = ['ticketId',
                           'type',
                           'source',
                           'sourceDomainOrIp',
                           'sourceSubDomain',
                           'target',
                           'proxy',
                           'reporter']

        ticket_json = json.loads(json_string)
        return {key: ticket_json[key] for key in middleware_keys}

    def check_dupe(self, source):
        if not source:
            self._logger.error("Source URL value was either Null or blank")
            raise ValueError("Unable to determine source url")

        # Check to see if there is an existing open ticket with same source url
        url_args = self._create_url_params_string({'closed': 'false', 'source': urllib.quote_plus(source)})

        query = '/{table_name}{url_args}'.format(table_name=self.TICKET_TABLE_NAME, url_args=url_args)
        response = self._datastore.get_request(query)

        query_dict = json.loads(response.content)

        if 'result' not in query_dict:
            self._logger.error("A database error occurred when querying for {}".format(source))

            api_resp = make_response('{{"message":"{We are unable to complete your request at this time}"}}')
            api_resp.status_code = self.DEFAULT_ERROR_CODE

            return api_resp

        return bool(query_dict['result'])

    def create_ticket(self, args):
        """
        Test for IP and make sure goes to domain (change name) in ticket table
        Method to extract domain from source url, post domain to ticket table and
        get back ticket number and ticket sys id

        :param args: a dictionary containing all the values needed to get an attachment from a ticket
        :return: a response object containing string of the unique ticket id
        """
        try:

            # This is where we define which fields we want returned from SNOW
            #  When someone submits an abuse report, we only want to return: {"u_number": "DCU000036506"}
            args['sysparm_fields'] = 'u_number'

            is_duplicate = self.check_dupe(args.get('source'))
            if isinstance(is_duplicate, Response):
                return is_duplicate

            # Check to see if the abuse report has been previously submitted for this URI
            if is_duplicate:
                message = "We have already been informed of the abuse reported at this URL and are " \
                          "looking into the matter: {url}".format(url=args.get('source'))
                api_resp = make_response('{{"message":"{msg}"}}'.format(msg=message))
                api_resp.status_code = self.DEFAULT_ERROR_CODE

            else:

                response = self._datastore.post_request('/{table_name}'.format(table_name=self.TICKET_TABLE_NAME),
                                                        self._create_json_string(args))

                resp_dict = json.loads(response.content)

                # api_resp is what ends up being returned to the user who submitted the abuse report
                api_resp = make_response(json.dumps({'u_number': resp_dict.get('result', {}).get('u_number')}))
                api_resp.status_code = response.status_code

                # SNOW ticket created successfully
                if response.status_code == 201:
                    ticket_info = json.loads(response.content)

                    # Extract the id of the newly created SNOW ticket
                    args['ticketId'] = ticket_info['result']['u_number']

                    if args.get('type') in ['PHISHING', 'MALWARE', 'SPAM', 'NETWORK_ABUSE']:

                        middleware_data = self.get_ticket_info(args)

                        json_for_middleware = self.clean_for_middleware(middleware_data.data)

                        if args.get('metadata'):
                            json_for_middleware['metadata'] = args.get('metadata')

                        self._db.add_new_incident(args['ticketId'], json_for_middleware)

                        self._logger.info("Payload sent to middleware: {}".format(json_for_middleware))
                        self._capp.send_task(self.credentials.api_task, (json_for_middleware,))
            return api_resp
        except Exception as e:
            api_resp = make_response('{{"message":"EXCEPTION: %s"}}' % e.message)
            api_resp.status_code = self.DEFAULT_ERROR_CODE
            return api_resp

    def update_ticket(self, args):
        """
        :param args: a dictionary containing all the values needed to get an attachment from a ticket
        :return: a response object containing a string either stating success of the reason for failure
        """
        self._logger.info("Updating ticket {}".format(args))
        try:
            if args.get('closed') and not args.get('close_reason'):
                raise Exception('close_reason not provided')

            ''' get the SysID of ticket being updated.  Returns tuple
                if not successful, ticket sys id string if successful
            '''

            successful, sys_id_return_val = self._get_sys_id(args)
            self._logger.info("GetSysId {} {}".format(successful, sys_id_return_val))

            if successful:
                ticket_sys = sys_id_return_val

                # Updating Ticket table
                self._logger.info("Updating ticket: {}".format(ticket_sys))

                query = '/{table_name}/{sys_id}'.format(table_name=self.TICKET_TABLE_NAME, sys_id=ticket_sys)
                response = self._datastore.patch_request(query, self._create_json_string(args))

                # api_resp is what gets returned to the user api call
                self._logger.info("RESPONSE CONTENT: {}".format(response.content))

                api_resp = make_response(response.content)
                api_resp.status_code = response.status_code

                if response.status_code == 200:
                    api_resp.status_code = 204
                    if args.get('closed'):
                        self._db.close_incident(args['ticketId'], dict(close_reason=args.get('close_reason')))

            else:
                api_resp = make_response(sys_id_return_val[0])
                api_resp.status_code = sys_id_return_val[1]

        except Exception as e:
            self._logger.error("Error updating ticket {}:".format(args['ticketId']), exc_info=1)
            api_resp = make_response('{{"message":"EXCEPTION: {msg}"}}'.format(msg=e.message))
            api_resp.status_code = self.DEFAULT_ERROR_CODE

        finally:
            return api_resp

    def get_tickets(self, args):
        """
        :param args: a dictionary containing all the values needed to get an attachment from a ticket
            Valid keys include (by table):
                    Ticket:
                                limit: max number of tickets to return
                                offset: return tickets starting after given index
                                domain: suspected domain
                                start_date: tickets created on or after date
                                end_date: tickets created on or before date
                                status: ticket status
                                type: abuse ticket type
                                ip: source ip
                                target: victim or attack target
                    Reporter:
                                reporter: reporter email
        :return: a response object containing a list of unique ticket ids
        """

        try:
            # Add entries to args dictionary for pagination
            args['sysparm_fields'] = 'u_number'

            url_args = self._create_url_params_string(args) + '&sysparm_query=active=true^ORDERBYDESCu_number'

            ''' The primary qualifying arguments are the reporter email address and
                the reporter key.  Get the reporter key and then look up related
                source records
            '''

            query = '/{table_name}{url_args}'.format(table_name=self.TICKET_TABLE_NAME, url_args=url_args)
            response = self._datastore.get_request(query)

            # api_resp is what gets returned to the user api call
            api_resp = make_response(response.content)
            api_resp.status_code = response.status_code

            # Service now call was successful
            if response.status_code == 200:

                ticket_numbers = []
                ticket_dict = {}

                json_result = json.loads(response.content)

                for ticket in json_result.get('result', None):
                    ticket_numbers.append(ticket.get('u_number', 'UNKNOWN'))

                ticket_dict['ticket_ids'] = ticket_numbers

                # This gets returned to the user in the RAW
                api_resp.data = json.dumps(ticket_dict)

        except Exception as e:
            api_resp = make_response('{{"message":"EXCEPTION: {msg}"}}'.format(msg=e.message))
            api_resp.status_code = self.DEFAULT_ERROR_CODE

        finally:
            return api_resp

    def get_ticket_info(self, args):
        """
        :param args: a dictionary containing all the values needed to get an attachment from a ticket
        :return: a response object containing a dictionary of all values we want to return to a user,
            from a single ticket
        """

        try:
            query = '/{table_name}?sysparam_limit=1&u_number={ticket_id}'.format(
                table_name=self.TICKET_TABLE_NAME,
                ticket_id=args('ticketId'))
            response = self._datastore.get_request(query)

            # api_resp is what gets returned to the user api call
            api_resp = make_response(response.content)
            api_resp.status_code = response.status_code

            if response.status_code == 200:
                query_dict = json.loads(response.content)

                if query_dict.get('result'):
                    api_resp.data = query_dict['result'][0]
                else:
                    api_resp.status_code = 404

        except Exception as e:
            api_resp = make_response('{{"message":"EXCEPTION: {msg}"}}'.format(msg=e.message))
            api_resp.status_code = 500

        finally:
            return api_resp

    def _create_url_params_string(self, params):
        """
        :param params: A dictionary containing values to convert into URL params
        :return: A URL parameters string

        Used to create a GET style URL parameter string for SNOW API calls.
        Need a special case for GET TICKETS createdStart and createdEnd, so that
        they employ >= or <= instead of just =
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

    def _get_sys_id(self, data):
        self._logger.info("Attempting to retrieve SysId for {}".format(data.get('ticketId')))

        try:
            query = '/{table}?u_number={ticket}'.format(table=self.TICKET_TABLE_NAME, ticket=data.get('ticketId'))
            response = self._datastore.get_request(query)
        except Exception as e:
            return False, ("Exception while performing Get Request {}".format(e.message), 500)

        if response.status_code != 200:
            return False, (response.content, response.status_code)

        try:
            query_dict = json.loads(response.content)
        except Exception as e:
            return False, ("Exception while unmarshaling JSON: {}".format(e.message), 500)

        if 'result' not in query_dict:
            self._logger.error("An error occurred when retrieving SysId for {} ".format(data.get('ticketId')))
            return False, ("We are unable to complete your request at this time", 500)

        if not query_dict.get('result'):
            return False, ("No records found for {}".format(data.get('ticketId')), 404)

        return True, query_dict['result'][0]['sys_id']
