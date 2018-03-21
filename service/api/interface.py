import abc


class DataStore:
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def create_ticket(self, args):
        """
        :param args: a dictionary containing all values needed
        :return: a string of the unique ticket id
        """

    @abc.abstractmethod
    def update_ticket(self, args):
        """
        :param args: a dictionary containing all values to update including the unique ticket id
        :return:
        """

    @abc.abstractmethod
    def get_tickets(self, args):
        """
        :param args: a dictionary of all values to use as filters for searching the data store
        :return:a list of unique ticket ids and optional pagination
        """

    @abc.abstractmethod
    def get_ticket(self, args):
        """
        :param args: a dictionary of arguments to retrieve ticket information about
        :return: a dictionary of all values we want to return to a user
        """
