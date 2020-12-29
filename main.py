""" Guard Duty boto3 for US regions. """
import menu

if __name__ == '__main__':
    while True:
        menu.get_menu_choice()
        choice = input('Enter your choice: ')
        menu.CHOICES[int(choice)].get('func')()
