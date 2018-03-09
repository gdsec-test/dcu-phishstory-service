import os
import yaml
import logging
import logging.config


# Set up logging config
def get_logging():
    if len(logging.Logger.root.handlers) == 0:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        # logging.yml in the base project directory is where all
        #  logging configuration should reside
        path = '{}/logging.yml'.format(dir_path)
        value = os.getenv('LOG_CFG', None)
        if value:
            path = value
        if os.path.exists(path):
            with open(path, 'rt') as f:
                lconfig = yaml.safe_load(f.read())
            logging.config.dictConfig(lconfig)
        else:
            logging.basicConfig(level=logging.INFO)
    return logging


# - - - DECORATOR FUNCTION FOR CLASSES - - - #
# ALL logging configuration exists in the newman/logging.yml file.
#  decorated is the actual object that is being decorated, such as
#  Mailman() or Persist(), and this decorator simply adds the _logger
#  class variable to it.
# Usage: Add following above class declaration: @class_logger
def class_logger(decorated):
    validated_logger = get_logging()
    decorated._logger = validated_logger.getLogger(decorated.__module__)
    return decorated


# - - - DECORATOR FUNCTION FOR FUNCTIONS - - - #
# Will print all arguments passed to the function
# Usage: Add following above function declaration: @function_args_logger
def function_args_logger(decorated):
    def the_decorator(*args, **kwargs):
        validated_logger = get_logging()
        logger = validated_logger.getLogger(__name__)
        if len(args) == 0:
            logger.info('Function "{}" received no args'.format(decorated.func_name))
        else:
            args_as_string = str(args)
            if args_as_string.endswith(',)'):
                args_as_string = args_as_string[:-2] + ')'
            logger.info('Function "{}" was passed in args: {}'.format(decorated.func_name, args_as_string))
        decorated(*args, **kwargs)
    return the_decorator
