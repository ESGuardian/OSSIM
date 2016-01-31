#! /usr/bin/python
# -*- coding: cp1251 -*-
import sys
from datetime import *
from netaddr import *

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

def get_place(reader, src, mycharset):
    # reader - объект класса reader из модуля geoip2.database
    # src - строка с ip адресом
    # mycharset - кодировка в которой работает вызывающая функцию программа
    # В базе geoip2 есть проблемы с кодировкой записей, они могут не конвертнутся в нужную кодировку 
    # в вызывающей программе, это вызовет ошибку и остановку программы. По этой причине здесь проверяется 
    # возможность конвертировать результат перед его возвратом. Если конвертировать нельзя, 
    # возврощаем строку 'Хренпоймигде'. decode('utf8') на этой строке - это правильно. Долго объяснять почему. 
    
    ip = IPAddress(src)
    if ip.is_private():
        place = u'Local'
        return place
    try:
        response = reader.city(src)
        place =  response.city.name
        if place is None:
            place = response.country.name
        if place is None:
            place = u'Unknown'
    except:
        place = u'Unknown'
    try:
        place.encode(mycharset)
    except:
        place = 'Хренпоймигде'.decode('utf8')
    return place
