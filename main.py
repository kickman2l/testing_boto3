"""
 Guard Duty boto3 for US regions.
"""
import menu

# Vars definition
TRUSTED_LIST_NAME = 'trusted_list'
THREAT_LIST_NAME = 'threat_list'

if __name__ == '__main__':
    while True:
        menu.get_menu_choice()
        choice = input('Enter your choice: ')
        menu.CHOICES.get(choice)()
