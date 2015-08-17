#! /usr/bin/python
# -*- coding: cp1251 -*-
import sys
from datetime import *

# Datababe connection config
CONF_PATH = '/etc/ossim/ossim_setup.conf'
def get_db_connection_data ():
    with open(CONF_PATH,'r') as conf:
        lines = conf.readlines()
        for line in lines:
            (name,value)=('','')
            if '=' in line:
                (name,value) = line.strip().split('=',1)
            if name == 'db_ip':
                dbhost = value
            if name == 'pass':
                dbpass = value
            if name == 'user':
                dbuser = value
    conf.close()
    return (dbhost,dbuser,dbpass)

def check_that_first_later(first,second):
    ft=datetime.strptime(first,'%Y-%m-%d %H:%M:%S')
    st=datetime.strptime(second,'%Y-%m-%d %H:%M:%S')
    if ft > st:
        return True
    else:
        return False
