import abc


class DataStore:
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def create_ticket(self, data):
        '''
        :param data: a dictionary containing all values needed
        :return: a string of the unique ticket id
        '''
        return

    @abc.abstractmethod
    def update_ticket(self, data):
        '''
        :param data: a dictionary containing all values to update including the unique ticket id
        :return: a string either stating success of the reason for failure
        '''
        return

    @abc.abstractmethod
    def get_tickets(self, data):
        '''
        :param data: a dictionary of all values to use as filters for searching the data store
        :return:a list of unique ticket ids
        '''
        return

    @abc.abstractmethod
    def get_ticket_info(self, data):
        '''
        :param data: a dictionary containing all values to update including the unique ticket id
        :return: a dictionary of all values we want to return to a user
        '''
        return