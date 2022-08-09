# main.py
'''
    Controls the other ssl checks
'''

from os import system

def main_controller():
    system('python visa_certs_check.py')
    system('python node_four_check.py')
    # system('python nasstar_certs_check.py')


if __name__ == '__main__':
    main_controller()