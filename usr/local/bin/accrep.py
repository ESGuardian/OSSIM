#! /usr/bin/python
# -*- coding: cp1251 -*-
# автор esguardian@outlook.com
# версия 1.0.1
# Отчет о действиях с учетными записями 
# Собирает из базы данные плагина OSSEC о добавлении/удалении пользователей в группы
# создании/удалении/блокировке/разблокировке учетных записей
# создании/удалении групп
# для эффективной работы нужен сбор логов OSSEC с контроллеров доменов 
# и (желательно) с рабочих станций
#
import sys
import MySQLdb
import codecs
from datetime import date, timedelta
from OSSIM_helper import get_db_connection_data


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

outfilename='AC-' + today.strftime('%Y-%m-%d') + '.csv'
outfullpath='/usr/local/ossim_reports/' + outfilename

mytz="'+03:00'"
mycharset='cp1251'
colheader='Действие;Время;Оператор;Объект;Компьютер;Данные\n'.decode(mycharset)


conn = MySQLdb.connect(host=dbhost, user=dbuser, passwd=dbpass, db=dbshema, charset='utf8') 
cursor = conn.cursor() 

# ---- End of Init
when = "timestamp between '" + starttime + "' and '" + endtime + "'"

# Account change
tabheader='\n\n\nИзменение учетных записей за период '.decode(mycharset) + startdate + ' - ' + enddate + '\n\n'
what="userdata3 as action, convert_tz(timestamp,'+00:00'," + mytz +") as time, userdata8 as operator, username as object, inet_ntoa(conv(HEX(ip_src), 16, 10)) as source, substring_index(substring_index(data_payload,'.inbank.msk: ',-1),' Subject:',1) as info from acid_event join extra_data on (acid_event.id=extra_data.event_id)"
where="acid_event.plugin_id=7043 and (acid_event.plugin_sid=18110 or acid_event.plugin_sid=18112 or acid_event.plugin_sid=18142)"
select="select  " + what + " where " + where + " and " + when + " order by time"
cursor.execute(select)
with codecs.open(outfullpath, 'a', encoding=mycharset) as out:
     out.write(tabheader + colheader) 
     row = cursor.fetchone() 
     while row:
         out.write(';'.join([str(c).replace(';',',').strip() for c in row]) + '\n')
         row = cursor.fetchone()
out.close()
# ---
# global and universal group change
tabheader='\n\n\nИзменение глобальных групп за период '.decode(mycharset) + startdate + ' - ' + enddate + '\n\n'

with codecs.open(outfullpath, 'a', encoding=mycharset) as out:
     out.write(tabheader + colheader) 
     # global group create
     what ="userdata3 as action, convert_tz(timestamp,'+00:00'," + mytz +") as time, username as operator, substring_index(substring_index(data_payload,'Group Name: ',-1),' Group',1) as object, inet_ntoa(conv(HEX(ip_src), 16, 10)) as source, substring_index(substring_index(data_payload,'.inbank.msk: ',-1),' Subject:',1) as info from acid_event join extra_data on (acid_event.id=extra_data.event_id)"
     where = "acid_event.plugin_id=7099 and acid_event.plugin_sid=18202"
     select="select " + what + " where " + where + " and " + when  + " order by time"
     cursor.execute(select)
     row = cursor.fetchone() 
     while row:
         out.write(';'.join([str(c).replace(';',',').strip() for c in row]) + '\n')
         row = cursor.fetchone()
     # global group member add or remove and universal group member remove
     what = "userdata3 as action, convert_tz(timestamp,'+00:00'," + mytz +") as time, username as operator, substring_index(substring_index(data_payload,'Group Name: ',-1),' Group',1) as object, inet_ntoa(conv(HEX(ip_src), 16, 10)) as source, substring_index(substring_index(data_payload,'CN=',-1),',OU=',1) as info from acid_event join extra_data on (acid_event.id=extra_data.event_id)"
     where = "acid_event.plugin_id=7107 and (acid_event.plugin_sid=18203 or acid_event.plugin_sid=18204 or acid_event.plugin_sid=18215)"
     select="select " + what + " where " + where + " and " + when  + " order by time"
     cursor.execute(select)
     row = cursor.fetchone() 
     while row:
         out.write(';'.join([str(c).replace(';',',').strip() for c in row]) + '\n')
         row = cursor.fetchone()
     # Universal group member add 
     # Ooops, ossim save this record in other format than "member removed" I think this is ossec agent bug
     # so I need to do additional select
     what = "userdata3 as action, convert_tz(timestamp,'+00:00'," + mytz +") as time, substring_index(substring_index(substring_index(data_payload,'Group: Security ID:',-1),' Account Domain:',1),'Account Name: ',-1) as operator, substring_index(substring_index(data_payload,'Account Name: ',-1),' Account',1) as object, inet_ntoa(conv(HEX(ip_src), 16, 10)) as source, substring_index(substring_index(data_payload,'CN=',-1),',OU=',1) as info from acid_event join extra_data on (acid_event.id=extra_data.event_id)"
     where = "acid_event.plugin_id=7107 and acid_event.plugin_sid=18214"
     select="select " + what + " where " + where + " and " + when  + " order by time"
     cursor.execute(select)
     row = cursor.fetchone() 
     while row:
         out.write(';'.join([str(c).replace(';',',').strip() for c in row]) + '\n')
         row = cursor.fetchone()
out.close()
# ---
# Local group change
tabheader='\n\n\nИзменение локальных групп за период '.decode(mycharset) + startdate + ' - ' + enddate + '\n\n'

with codecs.open(outfullpath, 'a', encoding=mycharset) as out:
     out.write(tabheader + colheader) 
     # in this cause ossec agent don't recognize account name by SID, so I use SID as "member"
     what = "userdata3 as action, convert_tz(timestamp,'+00:00'," + mytz +") as time, username as operator, substring_index(substring_index(data_payload,'Group Name: ',-1),' Group',1) as object, inet_ntoa(conv(HEX(ip_src), 16, 10)) as source, substring_index(substring_index(data_payload,'Member: ',-1),' Account',1) as info from acid_event join extra_data on (acid_event.id=extra_data.event_id)"
     where = "acid_event.plugin_id=7107 and (acid_event.plugin_sid=18207 or acid_event.plugin_sid=18208)"
     select="select " + what + " where " + where + " and " + when  + " order by time"
     cursor.execute(select)
     row = cursor.fetchone() 
     while row:
         out.write(';'.join([str(c).replace(';',',').strip() for c in row]) + '\n')
         row = cursor.fetchone()
out.close()
# ---
# --- End of All
conn.close()
