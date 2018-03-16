from requests import sessions


class SNOWHelper(object):
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
