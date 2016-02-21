#! /usr/bin/python
# -*- coding: utf8 -*-
# автор esguardian@outlook.com
# версия 2.0.1
# Отчет о событиях удаленного доступа
# Собирает от стандартного плагина cisco-asa (события cisco AnyConnect) и моего плагина activesync-monitor
# включает данные геолокации
# будьте внимательны вы должны предварительно установить geoip2 python module
# его нет в системе по-умолчанию. Это можно сделать пользуя PIP
# но его тоже нет в системе. Так что сначала
# wget https://bootstrap.pypa.io/get-pip.py --no-check-certificate
# python get-pip.py
# pip install geoip2
# 
# и вы должны загрузить GeoLite2-City database:
# http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz
# распаковать и поместить в
#/usr/share/geoip/GeoLite2-City.mmdb
# 
import sys
import MySQLdb
import codecs
from datetime import date, timedelta
# import GeoIP
import geoip2.database
from OSSIM_helper import get_db_connection_data, get_place


# Datababe connection config.
(dbhost,dbuser,dbpass) = get_db_connection_data()
dbshema='alienvault_siem'
# --- End of Database config

# ---- Init 

period=1
if len(sys.argv) > 1:
    period=int(sys.argv[1])


today=date.today()
enddate=today.strftime('%Y:%m:%d')
endtime=enddate + ' 06:00:00' # UTC time
startdate=(today - timedelta(days=period)).strftime('%Y:%m:%d')
starttime=startdate + ' 06:00:00'

outfilename='RA-' + today.strftime('%Y-%m-%d') + '.csv'
outfullpath='/usr/local/ossim_reports/' + outfilename

mytz="'+03:00'"
mycharset='cp1251'
dbcharset='utf8'


conn = MySQLdb.connect(host=dbhost, user=dbuser, passwd=dbpass, db=dbshema, charset=dbcharset) 
cursor = conn.cursor() 

reader=geoip2.database.Reader("/usr/share/geoip/GeoLite2-City.mmdb")

# ---- End of Init
when = "timestamp between '" + starttime + "' and '" + endtime + "'"

# start
tabheader=u'\n\n\nУдаленный доступ через Cisco AnyConnect за период ' + startdate + ' - ' + enddate + '\n\n'
colheader=u'Время;Источник;Место;Пользователь;Назначенный адрес\n'

what="convert_tz(timestamp,'+00:00'," + mytz +") as time, substring_index(substring_index(userdata4,'IP <',-1),'>',1), username, substring_index(substring_index(userdata4,'IPv4 Address <',-1),'>',1) from acid_event join extra_data on (acid_event.id=extra_data.event_id)"
where="acid_event.plugin_id=1636 and acid_event.plugin_sid=722051"
select="select  " + what + " where " + where + " and " + when + " order by time"
cursor.execute(select)
#
# Так уж вышло, что Cisco-ASA почему-то дублирует в логе нужные мне события.
# Вслед за ней и стандартный плагин дублирует их в базу.
# По этой причине будем устранять "дубли" при подготовке отчета
#
double_stime = ""
double_source = ""
double_username = ""
with codecs.open(outfullpath, 'a', encoding=mycharset) as out:
     out.write(tabheader + colheader) 
     row = cursor.fetchone() 
     while row: 
         stime = str(row[0]).decode(dbcharset).strip()
         source = str(row[1]).decode(dbcharset).strip()
         username = str(row[2]).decode(dbcharset).strip()
         if double_stime != stime or double_source != source or double_username != username:
             double_stime = stime
             double_source = source
             double_username = username
             place = get_place(reader, source, mycharset)
             local_ip = str(row[3]).decode(dbcharset).strip()
             outstr = stime + ';' + source + ';' + place + ';' + username + ';' + local_ip + '\n'
             out.write(outstr)
         row = cursor.fetchone()
out.close()

# Now collect activesync-monitor data

tabheader=u'\n\n\nДоступ к Exchange ActiveSync за период ' + startdate + ' - ' + enddate + '\n\n'
colheader=u'Время;Пользователь;Устройство;ИД устройства;Адрес подключения;Место;Событие\n'

what="convert_tz(timestamp,'+00:00'," + mytz +") as time, username, userdata1, userdata2, userdata3, inet_ntoa(conv(HEX(ip_src), 16, 10)) from acid_event join extra_data on (acid_event.id=extra_data.event_id)"
where="acid_event.plugin_id=9007"
select="select  " + what + " where " + where + " and " + when + " order by time"
cursor.execute(select)
with codecs.open(outfullpath, 'a', encoding=mycharset) as out:
     out.write(tabheader + colheader) 
     row = cursor.fetchone() 
     while row: 
         stime = str(row[0]).decode(dbcharset).strip()
         source = str(row[5]).decode(dbcharset).strip()
         place = get_place(reader, source, mycharset)
         username = str(row[1]).decode(dbcharset).strip()
         dev_type = str(row[2]).decode(dbcharset).strip()
         dev_id = str(row[3]).decode(dbcharset).strip()
         info = str(row[4]).decode(dbcharset).strip()
         outstr = stime + ';' + username + ';' + dev_type + ';' + dev_id + ';' + source + ';' + place + ';' + info + '\n'
         out.write(outstr)
         row = cursor.fetchone()
out.close()
# --- End of All
reader.close()
conn.close()
