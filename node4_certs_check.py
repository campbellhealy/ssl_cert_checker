'''
    Check a list of the Node 4 SSL Certificates
'''

import idna   
import pandas as pd
import sqlite3

from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime
from OpenSSL import SSL
from os import system               # My pool cleaner
from socket import socket
from sqlalchemy import create_engine #, text, insert, sql

from hosts import get_hosts_node_four


def main_function():
    system('cls')
    today = datetime.now()
    df = pd.DataFrame()
    HOSTS = get_hosts_node_four()
    count = len(HOSTS)
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
            print(commonname)
            print(count)
            count -=1
            df = pd.concat([df,df2], ignore_index=True)
    except SSL.Error:
        print("OpenSSL.SSL.Error: [('SSL routines', '', 'unexpected eof while reading')]")
    
    df = df.sort_values(by=['Expires Not After'], ascending=True)
    df = df.reset_index(drop=True) # Helps the eye see the specific hostname
    write_to_sql(df) 
    print('Task Complete')



def write_to_sql(df):
    '''
        Changing the DataFrame into a database.
        This is a new feature to me and I went with the sqlite db as
        I knew what I was doing with that. any db could be used and 
        once understood, I would only need to change this one function
    '''
    engine = create_engine("sqlite+pysqlite:///:memory:", echo=True, future=True)
    df.to_sql('ssl_cert', con = engine)

    conn = sqlite3.connect('node_four_database.sql')
    c = conn.cursor()
    conn.commit()
    # db Updating
    df.to_sql('ssl_certs', conn, if_exists='replace', index = False)

    # Print to console checker
    c.execute('''  
    SELECT * FROM ssl_certs
            ''')
    for row in c.fetchall():
        print (row)
    return  # Back to main function to console that the task was completed


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

