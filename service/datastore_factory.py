import os

from service.api.servicenow_impl import ServiceNowDataStore


class DataStoreFactory:
    @staticmethod
    def makeDataStore():
        ds = None

        instance = os.environ['API_INSTANCE']
        mode = os.environ['API_MODE']

        if instance.upper() == 'SNOW':
            ds = ServiceNowDataStore(mode.upper())
        return ds
