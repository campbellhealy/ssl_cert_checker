# main.py
'''
    Controls the other ssl check modules
'''

from os import system


def main_controller():
    system('cls')
    print('Preparing for the next scheduled run.')
    # Visa list must be first
    system('python visa_certs_check.py') # Visa list
    system('python node4_certs_check.py') # Node 4 list
    system('python nasstar_certs_check.py') # Nasstar list
    main_controller()


if __name__ == '__main__':
    main_controller()