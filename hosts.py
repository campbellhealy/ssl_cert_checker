# hosts.py
'''
    Dependancy to: 
                    visa_certs_check.py
                    nasstar_certs_check.py
                    node4_certs_check.py
                    
    This module is used to extract a list from the spreadsheet.
    This could be converted into a list of url, as we won't need any of the other
    information. Although a spreadsheet would keep it simple for anyone updating
    the list. (Create a single column spreadsheet, listing all of the URL)

    The next part of the function is to add (sort of) the port number to each to 
    URL prior to the checking, as a tech point it is not needed to be known at a 
    service management level. 
'''

import pandas as pd


def get_hosts():
    '''
        This is for the Visa List.
        A number of the  entries from the MASTER sheet did not read causing errors.
        Therefore a duplicate spreadsheet was made and those entries deleted.
    '''
    hosts_list = []
    # df = pd.read_excel('cbo_cert_list_MASTER.xlsx', sheet_name='Visa HOPS Certificates 2022') # Add sheet_name= to get the specific sheet
    df = pd.read_excel('cbo_cert_list.xlsx', sheet_name='Visa HOPS Certificates 2022') # Add sheet_name= to get the specific sheet
    df_list = df['Certificate Name'].tolist()
    port = 443

    for x in df_list:
        '''
            Iterating through the list of URL to add in the 443 port to get the tuples
            Using code to perform this means it is only a list of url that needs stored.
            Also the port number can be changed on mass if, EVER, needed. < I doubt it!
        '''
        temp_list = [x, port]
        tuple_item = tuple(temp_list)
        hosts_list.append(tuple_item)
    with open('host_list.txt', 'w')as f:
        f.write(str(hosts_list))
    return hosts_list

def get_hosts_nasstar():
    '''
        This gets the list from the Nasstar worksheet.
        Not only does it select the correct worksheet, the URL detailed all had
        an additional extension to the url and this had tp be removed before checking
        in with the certificate. (This could be removed when creating a list)
    '''
    hosts_list = []
    # df = pd.read_excel('cbo_cert_list.xlsx') # Add sheet_name= to get the specific sheet
    df = pd.read_excel('cbo_cert_list.xlsx', sheet_name='Nasstar TMS Certificates 2022')
    df_list = df['Certificate Name'].tolist()
    port = 443

    for x in df_list:
        '''
            Iterating through the list of URL to add in the 443 port to get the tuples
            Using code to perform this means it is only a list of url that needs stored.
            Also the port number can be changed on mass if, EVER, needed. < I doubt it!
        '''
        x = x[:-4]
        temp_list = [x, port]
        tuple_item = tuple(temp_list)
        hosts_list.append(tuple_item)

    with open('host_list.txt', 'w')as f:
        f.write(str(hosts_list))
    return hosts_list


def get_hosts_node_four():
    '''
        This is for the Node 4 worksheet.
        The URL have an additional extension that needs removed before checking
        the certificate.
    '''
    hosts_list = []
    df = pd.read_excel('cbo_cert_list.xlsx', sheet_name='Node4 Certificates 2022')
    # df = pd.read_excel('cbo_cert_list.xlsx') # Add sheet_name= to get the specific sheet
    df_list = df['Certificate Name'].tolist()
    port = 443

    for x in df_list:
        '''
            Iterating through the list of UIRL to add in the 443 port to get the tuples
            Using code to perform this means it is only a list of url that needs stored.
            Also the port number can be changed on mass if, EVER, needed. < I doubt it!
        '''
        x = x[:-4]
        temp_list = [x, port]
        tuple_item = tuple(temp_list)
        hosts_list.append(tuple_item)
    with open('host_list.txt', 'w')as f:
        f.write(str(hosts_list))
    return hosts_list
