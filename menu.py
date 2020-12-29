""" Menu for guard duty boto3. """
import sys
from cst import TRUSTED_LIST_NAME, THREAT_LIST_NAME, print_err, print_ok
import gd
import s3


def zero():
    """ Select enable guard duty. """
    gd.enable(gd.get_us_aws_regions())
    print_ok("Guard duty enabled for US regions.")


def one():
    """ Select disable guard duty. """
    gd.disable(gd.get_us_aws_regions())
    print_ok("Guard duty disabled for US regions.")


def two():
    """ Add trusted and threat IP lists to guard duty. """
    choice = ''
    while len(choice) == 0:
        choice = input('Enter S3 Bucket name: ')
    if s3.check_threat_trusted_files(choice):
        detectors_in_regions = gd.get_detectors_ids(gd.get_us_aws_regions())
        gd.create_ip_sets(detectors_in_regions, choice)
        gd.create_threat_sets(detectors_in_regions, choice)
        print_ok('Lists added to guard duty.')
    else:
        print_err('Threat and trusted files not exist. Check S3.')


def three():
    """ Delete trusted and threat files from S3. """
    choice = ''
    while len(choice) == 0:
        choice = input('Enter S3 Bucket name: ')
    if s3.delete_tt_files_from_s3(choice):
        print_ok('Threat and trusted files deleted from s3.')


def four():
    """ Add new trusted and threat files to S3. """
    choice = ''
    while len(choice) == 0:
        choice = input('Enter S3 Bucket name: ')
    if s3.add_new_tt_files_to_s3(choice):
        print_ok('New threat and trusted files added to s3.')
    s3.cleanup_tmp_dir()


def five():
    """ Add to trusted file. """
    choice = ''
    data = ''
    s3.cleanup_tmp_dir()
    s3.create_tmp_dir()
    while len(choice) == 0:
        choice = input('Enter S3 Bucket name: ')
    if s3.check_threat_trusted_files(choice):
        while len(data) == 0:
            data = input('Enter value to add: ')
        s3.download_file_from_s3(choice, TRUSTED_LIST_NAME)
        s3.add_rule_to_file(TRUSTED_LIST_NAME, data)
        s3.upload_tt_file(choice, TRUSTED_LIST_NAME)
        print_ok("New value added to trusted file.")
    else:
        print_err('Threat or trusted files not exist. Check S3.')
    s3.cleanup_tmp_dir()


def six():
    """ Edit trusted file. """
    choice = ''
    rule_num = ''
    rule_val = ''
    s3.cleanup_tmp_dir()
    s3.create_tmp_dir()
    while len(choice) == 0:
        choice = input('Enter S3 Bucket name: ')
    if s3.check_threat_trusted_files(choice):
        s3.download_file_from_s3(choice, TRUSTED_LIST_NAME)
        s3.list_rules_in_file(TRUSTED_LIST_NAME)
        while len(rule_num) == 0:
            rule_num = input('Enter rule number to replace: ')
        while len(rule_val) == 0:
            rule_val = input('Enter new rule: ')
        s3.replace_rule_in_file(TRUSTED_LIST_NAME, rule_num, rule_val)
        s3.upload_tt_file(choice, TRUSTED_LIST_NAME)
        print_ok('Trusted file edited.')
    else:
        print_err('Threat and trusted files not exist. Check S3.')
    s3.cleanup_tmp_dir()


def seven():
    """ Remove from trusted file. """
    choice = ''
    rule_num = ''
    s3.cleanup_tmp_dir()
    s3.create_tmp_dir()
    while len(choice) == 0:
        choice = input('Enter S3 Bucket name: ')
    if s3.check_threat_trusted_files(choice):
        s3.download_file_from_s3(choice, TRUSTED_LIST_NAME)
        if s3.check_rules_in_file_exist(TRUSTED_LIST_NAME):
            s3.list_rules_in_file(TRUSTED_LIST_NAME)
            while len(rule_num) == 0:
                rule_num = input('Enter rule number to delete: ')
            s3.remove_rule_from_file(TRUSTED_LIST_NAME, rule_num)
            s3.upload_tt_file(choice, TRUSTED_LIST_NAME)
            print_ok('Rule removed from trusted.')
        else:
            print_err("Empty trusted file. Add entry before remove.")
    else:
        print_err('Threat and trusted files not exist. Check S3.')
    s3.cleanup_tmp_dir()


def eight():
    """ Add to threat file. """
    choice = ''
    data = ''
    s3.cleanup_tmp_dir()
    s3.create_tmp_dir()
    while len(choice) == 0:
        choice = input('Enter S3 Bucket name: ')
    if s3.check_threat_trusted_files(choice):
        while len(data) == 0:
            data = input('Enter value to add: ')
        s3.download_file_from_s3(choice, THREAT_LIST_NAME)
        s3.add_rule_to_file(THREAT_LIST_NAME, data)
        s3.upload_tt_file(choice, THREAT_LIST_NAME)
        print_ok("New value added to threat file.")
    else:
        print_err('Threat or trusted files not exist. Check S3.')
    s3.cleanup_tmp_dir()


def nine():
    """ Edit threat file. """
    choice = ''
    rule_num = ''
    rule_val = ''
    s3.cleanup_tmp_dir()
    s3.create_tmp_dir()
    while len(choice) == 0:
        choice = input('Enter S3 Bucket name: ')
    if s3.check_threat_trusted_files(choice):
        s3.download_file_from_s3(choice, THREAT_LIST_NAME)
        s3.list_rules_in_file(THREAT_LIST_NAME)
        while len(rule_num) == 0:
            rule_num = input('Enter rule number to replace: ')
        while len(rule_val) == 0:
            rule_val = input('Enter new rule: ')
        s3.replace_rule_in_file(THREAT_LIST_NAME, rule_num, rule_val)
        s3.upload_tt_file(choice, THREAT_LIST_NAME)
        print_ok('Threat file edited.')
    s3.cleanup_tmp_dir()


def ten():
    """ Remove from threat file. """
    choice = ''
    rule_num = ''
    s3.cleanup_tmp_dir()
    s3.create_tmp_dir()
    while len(choice) == 0:
        choice = input('Enter S3 Bucket name: ')
    if s3.check_threat_trusted_files(choice):
        s3.download_file_from_s3(choice, THREAT_LIST_NAME)
        if s3.check_rules_in_file_exist(THREAT_LIST_NAME):
            s3.list_rules_in_file(THREAT_LIST_NAME)
            while len(rule_num) == 0:
                rule_num = input('Enter rule number to delete: ')
            s3.remove_rule_from_file(THREAT_LIST_NAME, rule_num)
            s3.upload_tt_file(choice, THREAT_LIST_NAME)
            print_ok('Rule removed from threat.')
        else:
            print_err("Empty threat file. Add entry before remove.")
    else:
        print_err('Threat and trusted files not exist. Check S3.')
    s3.cleanup_tmp_dir()


def eleven():
    """ Exit from the script. """
    print_ok('Exiting...')
    sys.exit(0)


CHOICES = [
    {'func': zero, 'msg': 'Enable guard duty for US regions.'},
    {'func': one, 'msg': 'Disable guard duty for US regions.'},
    {'func': two, 'msg': 'Add trusted and threat IP lists to guard duty.'},
    {'func': three, 'msg': 'Delete trusted and threat files from S3.'},
    {'func': four, 'msg': 'Add new trusted and threat files to S3.'},
    {'func': five, 'msg': 'Add to trusted file.'},
    {'func': six, 'msg': 'Edit trusted file.'},
    {'func': seven, 'msg': 'Remove from trusted file.'},
    {'func': eight, 'msg': 'Add to threat file.'},
    {'func': nine, 'msg': 'Edit threat file.'},
    {'func': ten, 'msg': 'Remove from threat file.'},
    {'func': eleven, 'msg': 'Exit from the script.'}
]


# Menu for script
def get_menu_choice():
    """ Menu list. """
    print(30 * '-', 'menu', 30 * '-')
    for i, elem in enumerate(CHOICES):
        print(i, elem['msg'])
    print(66 * '-')
