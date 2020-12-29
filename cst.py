""" Variables definition. """
TRUSTED_LIST_NAME = 'trusted_list'
THREAT_LIST_NAME = 'threat_list'


def print_err(err_str):
    """ Print red color error. """
    print(f"\033[91m{err_str}\033[0m")


def print_ok(ok_str):
    """ Print green color success. """
    print(f"\033[92m{ok_str}\033[0m")
