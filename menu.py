"""
 Menu for guard duty boto3.
"""

from guard_duty import *
from s3_files import *
from main import TRUSTED_LIST_NAME
from main import THREAT_LIST_NAME


# Menu func definitions
def one():
    enable_guard_duty(get_us_aws_regions())
    print("one")


def two():
    disable_guard_duty(get_us_aws_regions())


def three():
    choice = ''
    while len(choice) == 0:
        choice = input('Enter S3 Bucket name:')
    if check_treat_trusted_files(choice):
        detectors_in_regions = get_detectors_ids_in_regions(get_us_aws_regions())
        create_ip_sets(detectors_in_regions, choice)
        create_threat_sets(detectors_in_regions, choice)
    else:
        print('Treat and trusted files not exists. Check S3.')


def four():
    print('Remove trusted and threat IP lists from guard duty. MOCK!!!')


def five():
    choice = ''
    while len(choice) == 0:
        choice = input('Enter S3 Bucket name:')
    delete_tt_files_from_s3(choice)


def six():
    choice = ''
    while len(choice) == 0:
        choice = input('Enter S3 Bucket name:')
    add_new_tt_files_to_s3(choice)
    cleanup_tmp_dir()


def seven():
    choice = ''
    data = ''
    cleanup_tmp_dir()
    create_tmp_dir()
    while len(choice) == 0:
        choice = input('Enter S3 Bucket name:')
    while len(data) == 0:
        data = input('Enter value to add:')
    if check_treat_trusted_files(choice):
        download_file_from_s3(choice, TRUSTED_LIST_NAME)
        add_rule_to_file(TRUSTED_LIST_NAME, data)
        upload_tt_file(choice, TRUSTED_LIST_NAME)
    cleanup_tmp_dir()


def eight():
    choice = ''
    rule_num = ''
    rule_val = ''
    cleanup_tmp_dir()
    create_tmp_dir()
    while len(choice) == 0:
        choice = input('Enter S3 Bucket name:')
    if check_treat_trusted_files(choice):
        download_file_from_s3(choice, TRUSTED_LIST_NAME)
        list_rules_in_file(TRUSTED_LIST_NAME)
        while len(rule_num) == 0:
            rule_num = input('Enter rule number to replace:')
        while len(rule_val) == 0:
            rule_val = input('Enter new rule:')
        replace_rule_in_file(TRUSTED_LIST_NAME, rule_num, rule_val)
    upload_tt_file(choice, TRUSTED_LIST_NAME)
    cleanup_tmp_dir()


def nine():
    choice = ''
    data = ''
    cleanup_tmp_dir()
    create_tmp_dir()
    while len(choice) == 0:
        choice = input('Enter S3 Bucket name:')
    while len(data) == 0:
        data = input('Enter value to add:')
    if check_treat_trusted_files(choice):
        download_file_from_s3(choice, THREAT_LIST_NAME)
        add_rule_to_file(THREAT_LIST_NAME, data)
        upload_tt_file(choice, THREAT_LIST_NAME)
    cleanup_tmp_dir()


def ten():
    choice = ''
    rule_num = ''
    rule_val = ''
    cleanup_tmp_dir()
    create_tmp_dir()
    while len(choice) == 0:
        choice = input('Enter S3 Bucket name:')
    if check_treat_trusted_files(choice):
        download_file_from_s3(choice, THREAT_LIST_NAME)
        list_rules_in_file(THREAT_LIST_NAME)
        while len(rule_num) == 0:
            rule_num = input('Enter rule number to replace:')
        while len(rule_val) == 0:
            rule_val = input('Enter new rule:')
        replace_rule_in_file(THREAT_LIST_NAME, rule_num, rule_val)
    upload_tt_file(choice, THREAT_LIST_NAME)
    cleanup_tmp_dir()


def eleven():
    exit(0)


CHOICES = {
    '1': one,
    '2': two,
    '3': three,
    '4': four,
    '5': five,
    '6': six,
    '7': seven,
    '8': eight,
    '9': nine,
    '10': ten,
    '11': eleven
}


# Menu for script
def get_menu_choice():
    print(30 * '-', 'menu', 30 * '-')
    print('1. Enable guard duty for US regions.')
    print('2. Disable guard duty for US regions.')
    print('3. Add trusted and threat IP lists to guard duty.')
    print('4. Remove trusted and threat IP lists from guard duty.')
    print('5. Delete trusted and threat files from S3.')
    print('6. Add new trusted and threat files to S3.')
    print('7. Add to trusted file.')
    print('8. Edit trusted file.')
    print('9. Add to threat file.')
    print('10. Edit threat file.')
    print('11. Exit from the script.')
    print(66 * '-')
