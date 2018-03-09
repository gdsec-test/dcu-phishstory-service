import abc


class DataStore(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def create_ticket(self, args):
        """
        :param args: a dictionary containing all values needed
        :return: a string of the unique ticket id
        """
        pass

    @abc.abstractmethod
    def update_ticket(self, args):
        """
        :param args: a dictionary containing all values to update including the unique ticket id
        :return: a string either stating success of the reason for failure
        """
        pass

    @abc.abstractmethod
    def get_tickets(self, args):
        """
        :param args: a dictionary of all values to use as filters for searching the data store
        :return: a list of unique ticket ids
        """
        pass

    @abc.abstractmethod
    def get_ticket_info(self, args):
        """
        :param args: a dictionary containing all values to update including the unique ticket id
        :return: a dictionary of all values we want to return to a user
        """
        pass
