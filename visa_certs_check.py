# visa_certs_check.py
'''
    Check a list of the Visa SSL Certificates
    Add file to the local MySQL database

    Dependancies:
                    hosts.py  < Locate in the same root folder
'''

import schedule
import idna   
import pandas as pd
import pymysql

from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime
from OpenSSL import SSL
from os import system               # My pool cleaner
from socket import socket
from sqlalchemy import create_engine, text
from time import sleep

from hosts import get_hosts


def main_function():
    '''
        main_function is the controller function. Managing all the tasks.
        All the tasks are farmed out to separate functions to give easier editing.
    '''
    system('cls')  # cleans up the pool
    today = datetime.now() # Used as a point of reference 
    df = pd.DataFrame()
    HOSTS = get_hosts() # gets the list of certificate url with port
    # HOSTS = [('rsp.swa.seft.ecebs.com', 443),('rsp.swa.seft.ecebs.com', 443) ]
    count = len(HOSTS) # This identifies how many certificates are being checked
    try:
        for item, ppp in HOSTS:
            host = item
            port = ppp
            cert = get_certificate(host, port)

            commonname = get_commonname(cert)
            SAN = get_altname(cert)
            issuer= get_issuer(cert)
            notbefore= cert.not_valid_before
            notafter= cert.not_valid_after

            # Creating the column and how long until a cert expires labelling
            if (notafter - today).days > 365:
                checker = 'More Than one year' 
            elif (notafter - today).days < 31:
                checker = 'LESS THAN A MONTH'
            elif (notafter - today).days < 81:
                   checker = 'Less than 3 months'
            elif (notafter - today).days < 182:
                   checker = 'Less than 6 months'
            elif (notafter - today).days < 365:
                   checker = 'Less than a Year'

            # Gets the information from each certificate check
            df_data = {'Common Name': [commonname],'SAN': [SAN],'Issuer': [issuer],'Expires Not Before': [notbefore],'Expires Not After': [notafter], 'Date Check': [checker]}
            df2 = pd.DataFrame(data = df_data)
            # Console information, (Which certificate is being checked and how many checks are left for the code)
            print(commonname)
            print(count)
            count -=1
            # Adds the latest check information to the main DataFrame
            df = pd.concat([df,df2], ignore_index=True)

    except SSL.Error:
        '''
            This was intended to capture any faults in the check whilst I was testing the code.
            To keep the checks going, and highlight any faults to go back and look at manually
        '''
        print("OpenSSL.SSL.Error: [('SSL routines', '', 'unexpected eof while reading')]")
        df_data = {'Common Name': [commonname],'SAN': [SAN],'Issuer': [issuer],'Expires Not Before': [notbefore],'Expires Not After': [notafter], 'Date Check': ['CONNECTION ERROR']}
        print(count)
        count -=1
        df = pd.concat([df,df2], ignore_index=True)
    
    # Main dataframe cleansing
    df = df.sort_values(by=['Expires Not After'], ascending=True)
    df = df.reset_index(drop=True) # Tidies up the index numbering
    # write_to_sql(df) 
    write_to_mysql(df) 
    print('Visa Task Complete')


def write_to_mysql(df):
    hostname= '127.0.0.1'
    dbname  = 'ssl_checker'
    uname   = 'root'
    pwd     = '1234qwe'
    tableName = 'visa_ssl'
    table_drop = text('DROP TABLE IF EXISTS visa_ssl;')

    try:
        # Create SQLAlchemy engine to connect to MySQL Database
        engine = create_engine("mysql+pymysql://{user}:{pw}@{host}/{db}"
                        .format(host=hostname, db=dbname, user=uname, pw=pwd))
        # Use this to delete the table
        engine.execute(table_drop)
        # Convert dataframe to sql table                                   
        df.to_sql(tableName, engine, index=False)

    except ValueError:
        print(ValueError)
    except Exception:   
        print(Exception)
    else:
        print("Table %s created successfully."%tableName)   
    return

def get_certificate(hostname, port):
    '''
        This is the certificate check
    '''
    hostname_idna = idna.encode(hostname)
    sock = socket()

    sock.connect((hostname, port))
    # peername = sock.getpeername()
    ctx = SSL.Context(SSL.SSLv23_METHOD) # most compatible
    ctx.check_hostname = False
    ctx.verify_mode = SSL.VERIFY_NONE

    sock_ssl = SSL.Connection(ctx, sock)
    sock_ssl.set_connect_state()
    sock_ssl.set_tlsext_host_name(hostname_idna)
    sock_ssl.do_handshake()
    cert = sock_ssl.get_peer_certificate()
    crypto_cert = cert.to_cryptography()
    sock_ssl.close()
    sock.close()

    return (crypto_cert) #, peername, hostname)


def get_commonname(cert):
    '''
        commonname == url
    '''
    try:
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None


def get_altname(cert):
    '''
        altname = SAN - Rarely given but it is available where possible
    '''
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return None


def get_issuer(cert):
    '''
        This should be ATOC across most others are also noted.
    '''
    try:
        names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None


if __name__ == '__main__':
    # Documentation for schedule - https://schedule.readthedocs.io/en/stable/
    schedule.every().day.at("08:55").do(main_function) # Set this time prior to Node 4
    while True:
        schedule.run_pending()
        sleep(1)

