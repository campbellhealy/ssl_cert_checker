'''
    Check a list of the Nasstar SSL Certificates
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

from auth import hostname, dbname,uname, pwd
from hosts import get_hosts_nasstar


def main_function():
    system('cls')
    today = datetime.now()
    df = pd.DataFrame()
    HOSTS = get_hosts_nasstar()
    # HOSTS = host_list
    count = len(HOSTS)
    try:
        for item, ppp in HOSTS:
            print(item)
            print(count)
            host = item
            port = ppp
            cert = get_certificate(host, port)

            commonname = get_commonname(cert)
            SAN = get_altname(cert)
            issuer= get_issuer(cert)
            notbefore= cert.not_valid_before
            notafter= cert.not_valid_after

            if (notafter - today).days > 365:
                checker = 'More Than one year' 
            elif (notafter - today).days < 0:
                checker = '** EXPIRED **'
            elif (notafter - today).days < 31:
                checker = 'LESS THAN A MONTH'
            elif (notafter - today).days < 81:
                   checker = 'Less than 3 months'
            elif (notafter - today).days < 182:
                   checker = 'Less than 6 months'
            elif (notafter - today).days < 365:
                   checker = 'Less than a Year'

            df_data = {'Common Name': [commonname],'SAN': [SAN],'Issuer': [issuer],'Expires Not Before': [notbefore],'Expires Not After': [notafter], 'Date Check': [checker]}
            df2 = pd.DataFrame(data = df_data)
            count -=1
            df = pd.concat([df,df2], ignore_index=True)
    except SSL.Error:
        print("OpenSSL.SSL.Error: [('SSL routines', '', 'unexpected eof while reading')]")
    
    df = df.sort_values(by=['Expires Not After'], ascending=True)
    df = df.reset_index(drop=True) # Helps the eye see the specific hostname
    write_to_mysql(df, hostname, dbname,uname, pwd) 
    print('Nasstar Task Complete')
    return


def write_to_mysql(df, hostname, dbname,uname, pwd):
    tableName = 'nasstar_ssl'
    table_drop = text(f'DROP TABLE IF EXISTS {tableName};')
    try:
        # Create SQLAlchemy engine to connect to MySQL Database
        engine = create_engine("mysql+pymysql://{user}:{pw}@{host}/{db}"
                        .format(host=hostname, db=dbname, user=uname, pw=pwd))
        # Use this to delete the table
        engine.execute(table_drop)
        # Convert dataframe to sql table                                   
        df.to_sql(tableName, engine, index=False)
    finally:
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
    main_function()
    # Documentation for schedule - https://schedule.readthedocs.io/en/stable/
    # schedule.every().day.at("12:25").do(main_function) # Set this time after Visa
    # while True:
    #     schedule.run_pending()
    #     sleep(1)
