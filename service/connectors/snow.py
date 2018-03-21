import json

from requests import sessions


class SNOWHelper(object):
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

    get_headers = {'Accept': 'application/json'}
    post_headers = dict(list(get_headers.items()) + list({'Content-Type': 'application/json'}.items()))

    default_timeout = 5  # Default timeout duration for all SNOW API calls

    def __init__(self, app_settings):
        self._url = app_settings.SNOW_URL
        self._user = app_settings.SNOW_USER
        self._pass = app_settings.SNOW_PASS

    def get_request(self, url_string):
        with sessions.session() as session:
            return session.get(self._url + url_string,
                               auth=(self._user, self._pass),
                               headers=self.post_headers,
                               timeout=self.default_timeout)

    def patch_request(self, snow_table, json_data_string):
        with sessions.session() as session:
            return session.patch(self._url + snow_table,
                                 auth=(self._user, self._pass),
                                 headers=self.post_headers,
                                 data=json_data_string,
                                 timeout=self.default_timeout)

    def post_request(self, snow_table, json_data_string):
        with sessions.session() as session:
            return session.post(self._url + snow_table,
                                auth=(self._user, self._pass),
                                headers=self.post_headers,
                                data=json_data_string,
                                timeout=self.default_timeout)

    def create_url_parameters(self, args):
        """
        Used to create a GET style URL parameter string for SNOW API calls.
        Need a special case for GET TICKETS createdStart and createdEnd, so that
        they employ >= or <= instead of just =

        :param args: A dictionary containing values to convert into URL params
        :return: A URL parameters string
        """
        if not args:
            return ''

        query = []

        created_start = '>='
        created_end = '<='
        all_other = '='

        for key, val in args.iteritems():
            operator = all_other
            if key == 'createdStart':
                operator = created_start
            elif key == 'createdEnd':
                operator = created_end

            k = self.HTML2SNOW[key] if key in self.HTML2SNOW else str(key)
            query.append(k + operator + str(val))
        return '?' + '&'.join(query)

    def create_post_payload(self, args):
        """
        Used to create a POST style JSON payload string for SNOW API calls
        :return: A JSON string
        """
        params_list = {}

        for key, val in args.iteritems():
            k = self.HTML2SNOW[key] if key in self.HTML2SNOW else key
            params_list[k] = val
        return json.dumps(params_list)

    @staticmethod
    def create_pagination_links(offset, limit, total_records):
        """ Refer to the Enterprise Standards for Pagination
            https://github.secureserver.net/Enterprise-Standards/api-design#pagination

            Links to provide are first, previous (if applicable), next (if applicable),
            last and total.
        """
        # There is always a first link and its offset is zero
        pagination = {'limit': limit, 'total': total_records, 'firstOffset': 0}

        # Check for previous links
        if offset:
            prev_starting_record = offset - limit
            pagination['previousOffset'] = 0 if prev_starting_record < 0 else prev_starting_record

        next_starting_record = offset + limit
        last_starting_record = (total_records / limit) * limit

        # Check for next links
        if total_records > next_starting_record:
            pagination['nextOffset'] = next_starting_record

        # Check for final paginated card in the deck
        ''' As an example of the code below, if there are 30 records, and the limit is 10, the last starting record is 
            20, unlike the situation when there are 31 records, which would cause the last starting record to be 30.
        '''
        if total_records % limit == 0:
            last_starting_record -= 1

        if next_starting_record < last_starting_record or total_records <= next_starting_record:
            pagination['lastOffset'] = last_starting_record

        return pagination
