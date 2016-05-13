#! /usr/bin/python
# -*- coding: utf8 -*-
# автор esguardian@outlook.com
# версия 1.1.0
# ----------
# 06.05.2016. Исправлены мелкие ошибки.
# 09.09.2015. вырезание данных из payload перенесено из SQL запроса в тело скрипта
# так быстрее работает
# -----------------------
# Отчет о действиях с учетными записями 
# Собирает из базы данные плагина OSSEC о добавлении/удалении пользователей в группы
# создании/удалении/блокировке/разблокировке учетных записей
# создании/удалении групп
# для эффективной работы нужен сбор логов OSSEC с контроллеров доменов 
# и (желательно) с рабочих станций  
#
import sys
import string
import MySQLdb
import codecs
from datetime import date, timedelta
from OSSIM_helper import get_db_connection_data


# Datababe connection config.
(dbhost,dbuser,dbpass) = get_db_connection_data()
dbshema='alienvault_siem'
asset_dbschema='alienvault'
# --- End of Database config
def mystr (v,charset):
    return str(v).decode(charset).replace(';',':').replace(',',':').strip()
# ---- Init 

period=1
if len(sys.argv) > 1:
    period=int(sys.argv[1])


today=date.today()
enddate=today.strftime('%Y:%m:%d')
endtime=enddate + ' 06:00:00' # UTC time
startdate=(today - timedelta(days=period)).strftime('%Y:%m:%d')
starttime=startdate + ' 06:00:00'

outfilename='AC-' + today.strftime('%Y-%m-%d') + '.csv'
outfullpath='/usr/local/ossim_reports/' + outfilename

mytz="'+03:00'"
mycharset='cp1251'
dbcharset='utf8'
colheader=u'Действие;Время;Оператор;Объект;Компьютер;Данные\n'


conn = MySQLdb.connect(host=dbhost, user=dbuser, passwd=dbpass, db=dbshema, charset='utf8') 
cursor = conn.cursor() 

# ---- End of Init
when = "timestamp between '" + starttime + "' and '" + endtime + "'"

# Account change
tabheader=u'\n\n\nИзменение учетных записей за период ' + startdate + ' - ' + enddate + '\n\n'
what = "userdata3 as action, convert_tz(timestamp,'+00:00'," + mytz +") as time, userdata8 as operator, username as object, inet_ntoa(conv(HEX(ip_src), 16, 10)) as source, data_payload as info from acid_event join extra_data on (acid_event.id=extra_data.event_id)"
where = "acid_event.plugin_id=7043 and (acid_event.plugin_sid=18110 or acid_event.plugin_sid=18112 or acid_event.plugin_sid=18142)"
select = "select  " + what + " where " + where + " and " + when + " order by time"
cursor.execute(select)
with codecs.open(outfullpath, 'a', encoding=mycharset) as out:
    out.write(tabheader + colheader) 
    row = cursor.fetchone() 
    while row:
        outstr = unicode(row[0]).replace(';',':').replace(',',':').strip()
        outstr = outstr + ';' + unicode(row[1]).replace(';',':').replace(',',':').strip()
        outstr = outstr + ';' + unicode(row[2]).replace(';',':').replace(',',':').strip()
        outstr = outstr + ';' + unicode(row[3]).replace(';',':').replace(',',':').strip()
        outstr = outstr + ';' + unicode(row[4]).replace(';',':').replace(',',':').strip()
        # Извлекаем из payload строку с описанием операции
        try:
            info = row[5].split('.inbank.msk: ', 1)[-1].split('Subject:',1)[0]
        except:
            info = row[5]
        outstr = outstr + ';' + mystr(info,dbcharset)
        out.write(outstr + '\n')
        row = cursor.fetchone()
out.close()
# ---
# global and universal group change
tabheader=u'\n\n\nИзменение глобальных групп за период ' + startdate + ' - ' + enddate + '\n\n'

with codecs.open(outfullpath, 'a', encoding=mycharset) as out:
    out.write(tabheader + colheader) 
    # global group create
    what = "userdata3 as action, convert_tz(timestamp,'+00:00'," + mytz +") as time, username as operator, inet_ntoa(conv(HEX(ip_src), 16, 10)) as source, data_payload as info from acid_event join extra_data on (acid_event.id=extra_data.event_id)"
    where = "acid_event.plugin_id=7099 and acid_event.plugin_sid=18202"
    select = "select " + what + " where " + where + " and " + when  + " order by time"
    cursor.execute(select)
    row = cursor.fetchone() 
    while row:
        outstr = unicode(row[0]).replace(';',':').replace(',',':').strip()
        outstr = outstr + ';' + unicode(row[1]).replace(';',':').replace(',',':').strip()
        outstr = outstr + ';' + unicode(row[2]).replace(';',':').replace(',',':').strip()
        # извлекаем название группы из payload
        try:
            object = row[4].split('Group Name: ',1)[-1].split('Group',1)[0]
        except:
            object = 'None'
        outstr = outstr + ';' + mystr(object,dbcharset)
        outstr = outstr + ';' + unicode(row[3]).replace(';',':').replace(',',':').strip()
        # извлекаем описание операции из payload, если не получится запишем payload как есть
        try:
            info = row[4].split('.inbank.msk: ', 1)[-1].split('Subject:',1)[0]
        except:
            info = row[4]
        outstr = outstr + ';' + mystr(info,dbcharset)
        out.write(outstr + '\n')
        row = cursor.fetchone()
        
    # global group member add or remove and universal group member remove
    what = "userdata3 as action, convert_tz(timestamp,'+00:00'," + mytz +") as time, username as operator, inet_ntoa(conv(HEX(ip_src), 16, 10)) as source, data_payload as info from acid_event join extra_data on (acid_event.id=extra_data.event_id)"
    where = "acid_event.plugin_id=7107 and (acid_event.plugin_sid=18203 or acid_event.plugin_sid=18204 or acid_event.plugin_sid=18215)"
    select = "select " + what + " where " + where + " and " + when  + " order by time"
    cursor.execute(select)
    row = cursor.fetchone() 
    while row:
        outstr = unicode(row[0]).replace(';',':').replace(',',':').strip()
        outstr = outstr + ';' + unicode(row[1]).replace(';',':').replace(',',':').strip()
        outstr = outstr + ';' + unicode(row[2]).replace(';',':').replace(',',':').strip()
        # извлекаем название группы из payload
        try:
            object = row[4].split('Group Name: ',1)[-1].split('Group',1)[0]
        except:
            object = 'None'
        outstr = outstr + ';' + mystr(object,dbcharset)
        outstr = outstr + ';' + unicode(row[3]).replace(';',':').replace(',',':').strip()
        # извлекаем имя пользователя из payload, если не получится запишем payload как есть
        try:
            info = string.capwords(row[4].lower().split('cn=', 1)[-1].split(',ou=',1)[0])
        except:
            info = row[4]
        outstr = outstr + ';' + mystr(info,dbcharset)
        out.write(outstr + '\n')
        row = cursor.fetchone()
    # Universal group member add 
    # Ooops, ossim save this record in other format than "member removed" I think this is ossec agent bug
    # so I need to do additional select
    what = "userdata3 as action, convert_tz(timestamp,'+00:00'," + mytz +") as time, inet_ntoa(conv(HEX(ip_src), 16, 10)) as source, data_payload as info from acid_event join extra_data on (acid_event.id=extra_data.event_id)"
    where = "acid_event.plugin_id=7107 and acid_event.plugin_sid=18214"
    select = "select " + what + " where " + where + " and " + when  + " order by time"
    cursor.execute(select)
    row = cursor.fetchone() 
    while row:
        outstr = unicode(row[0]).replace(';',':').replace(',',':').strip()
        outstr = outstr + ';' + str(row[1]).decode(dbcharset).replace(';',':').replace(',',':').strip()
        try:
            operator = row[3].split('Group: Security ID:',1)[-1].split(' Account Domain:',1)[0].split('Account Name: ')[-1]
        except:
            operator = 'None'
        outstr = outstr + ';' + mystr(operator,dbcharset)
        # извлекаем название группы из payload
        try:
            object = row[3].split('Account Domain',1)[-1].split('Account Name: ',1)[-1].split('Account Name: ',1)[-1].split(' Account',1)[0]
        except:
            object = 'None'
        outstr = outstr + ';' + mystr(object,dbcharset)
        outstr = outstr + ';' + unicode(row[2]).replace(';',':').replace(',',':').strip()
        # извлекаем имя пользователя из payload, если не получится запишем payload как есть
        try:
            info = string.capwords(row[3].lower().split('cn=', 1)[-1].split(',ou=',1)[0])
        except:
            info = row[3]
        outstr = outstr + ';' + mystr(info,dbcharset)
        out.write(outstr + '\n')
        row = cursor.fetchone()
out.close()
# ---
# Local group change
tabheader=u'\n\n\nИзменение локальных групп за период ' + startdate + ' - ' + enddate + '\n\n'

with codecs.open(outfullpath, 'a', encoding=mycharset) as out:
     out.write(tabheader + colheader) 
     # in this cause ossec agent don't recognize account name by SID, so I use SID as "member"
     what = "userdata3 as action, convert_tz(timestamp,'+00:00'," + mytz +") as time, username as operator, inet_ntoa(conv(HEX(ip_src), 16, 10)) as source, data_payload as info from acid_event join extra_data on (acid_event.id=extra_data.event_id)"
     where = "acid_event.plugin_id=7107 and (acid_event.plugin_sid=18207 or acid_event.plugin_sid=18208)"
     select="select " + what + " where " + where + " and " + when  + " order by time"
     cursor.execute(select)
     row = cursor.fetchone() 
     while row:
        outstr = unicode(row[0]).replace(';',':').replace(',',':').strip()
        outstr = outstr + ';' + unicode(row[1]).replace(';',':').replace(',',':').strip()
        outstr = outstr + ';' + unicode(row[2]).replace(';',':').replace(',',':').strip()
        # извлекаем название группы из payload
        try:
            object = row[4].split('Group Name: ',1)[-1].split('Group',1)[0]
        except:
            object = 'None'
        outstr = outstr + ';' + mystr(object,dbcharset)
        outstr = outstr + ';' + unicode(row[3]).replace(';',':').replace(',',':').strip()
        # извлекаем имя пользователя из payload, если не получится запишем payload как есть
        try:
            info = row[4].split('Member: ', 1)[-1].split(' Account',1)[0]
        except:
            info = row[4]
        outstr = outstr + ';' + mystr(info,dbcharset)
        out.write(outstr + '\n')
        row = cursor.fetchone()
out.close()
# ---
# ORACLE Account change
conn_av = MySQLdb.connect(host=dbhost, user=dbuser, passwd=dbpass, db=asset_dbschema, charset=dbcharset)
cursor_av = conn_av.cursor() 
tabheader=u'\n\n\nИзменение учетных записей Oracle (АБС) за период ' + startdate + ' - ' + enddate + '\n\n'
what = "plugin_sid as action, convert_tz(timestamp,'+00:00'," + mytz +") as time, username as operator, userdata3 as object, userdata1 as source, userdata4 as info from acid_event left outer join extra_data on (acid_event.id=extra_data.event_id)"
where = "acid_event.plugin_id=9009 and (acid_event.plugin_sid=24 or acid_event.plugin_sid=26)"
select = "select  " + what + " where " + where + " and " + when + " order by time"
cursor.execute(select)
with codecs.open(outfullpath, 'a', encoding=mycharset) as out:
    out.write(tabheader + colheader) 
    row = cursor.fetchone() 
    while row:
        # Получаем название сигнатуры
        signature_name = u'Unknown'
        cursor_av.execute("select name from plugin_sid where plugin_id=9009 and sid=%s", (row[0],))
        row_av = cursor_av.fetchone()
        signature_name = unicode(row_av[0])
        
        outstr = signature_name
        outstr = outstr + ';' + unicode(row[1])
        outstr = outstr + ';' + unicode(row[2])
        if row[0] == 26:
            grantee = unicode(row[5]).split('granted for')[-1].split('by')[0].strip()
            outstr = outstr + ";" + grantee
        else:
            outstr = outstr + ';' + unicode(row[3])
        outstr = outstr + ';' + unicode(row[4])
        if row[0] == 26:
            if unicode(row[3]) != u'None':
                outstr += ';' + unicode(row[3])                
            else:
                outstr += ';' + unicode(row[5]).split('ora_role')[-1].split('granted')[0].strip()
        else:
            outstr = outstr + ';' + unicode(row[5])
        out.write(outstr + '\n')
        row = cursor.fetchone()
out.close()

# --- End of All
conn.close()
