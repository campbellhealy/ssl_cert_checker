# main.py
'''
    Controls the other ssl check modules
'''

from os import system


def main_controller():
    system('cls')
    system('python visa_certs_check.py') # Visa list
    print('Task 1 Complete')
    system('python node4_certs_check.py') # Node 4 list
    print('Task 2 Complete')
    # system('python nasstar_certs_check.py') # Nasstar list
    # print('Task 3 Complete')
    main_controller()


if __name__ == '__main__':
    main_controller()