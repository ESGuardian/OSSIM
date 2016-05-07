#! /usr/bin/python
# -*- coding: utf8 -*-
# версия 0.0.1 

import os
import sys
import MySQLdb
import codecs
from datetime import date, timedelta

def mystr (v):
    return unicode(v).replace(';',':').replace(',',':').strip()

(dbhost, dbuser, dbpass, dbschema, dbcharset)=('host-ip', 'username', 'userpass', 'oramon', 'utf8') # MySQL connection params for oramon db

select_except = " and not((alert_code = 7 or alert_code = 6) and uname = 'tb-user') " # Исключение
# select_except = " "

select = "SELECT * FROM ossim_log where (timestamp >= timestamp(CURRENT_DATE() - INTERVAL %s DAY, '09:00:00') and timestamp < timestamp(CURRENT_DATE(), '09:00:00'))" + select_except + "order by id"

colheader = u"log_id, Timestamp, Alert_code, Alert, UserName, Host, Host_ip, ORA_User, ORA_Object, Message, RAW_id\n"

period=1
if len(sys.argv) > 1:
    period=int(sys.argv[1])
    
today = date.today()
enddate=today.strftime('%Y:%m:%d')
startdate=(today - timedelta(days=period)).strftime('%Y:%m:%d')
outfilename='ORA-' + today.strftime('%Y-%m-%d') + '.csv'
outfullpath='/usr/local/ossim_reports/' + outfilename

tabheader=u'\n\n\nСобытия ORACLE за период ' + startdate + ' - ' + enddate + '\n\n'
mycharset = 'cp1251'

conn = MySQLdb.connect(host=dbhost, user=dbuser, passwd=dbpass, db=dbschema, charset=dbcharset)
cursor = conn.cursor()
cursor.execute(select,(period,))
with codecs.open(outfullpath, 'a', encoding=mycharset) as out:
    out.write(tabheader + colheader) 
    row = cursor.fetchone() 
    while row:
        out.write(u';'.join([mystr(c) for c in row]) + u'\n')
        row = cursor.fetchone()
out.close()
conn.close()        