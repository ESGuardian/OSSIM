#! /usr/bin/python
# -*- coding: cp1251 -*-
# автор esguardian@outlook.com
# версия 1.0.1
# 
# создает два рабочих файла  /var/cache/logon-monitor/logon-history.list и /var/cache/logon-monitor/logon-<today_date>.list 
# и записывает в /var/log/user-logon-monitor.log 5 типов событий:
# 1 - Hello! If a user is logged the first time today and is already registered in the past 5 days
# 2 - Wellcome back! If a user is logged the first time today and has last recorded more than 5 but less than 20 days ago
# 3 - Wow... Last time I saw you NN days ago! If a user last recorded more then 20 days ago
# 4 - New kid in town! If a user never been regestered before
# 5 - Error! if a script has stoped by error when.
# К этому монитору полагается мой соответствующий плагин user-logon-monitor (см /etc/ossim/plugins/user-logon-monitor.cfg),
# который читает этот лог и записывает события в базу OSSIM.
# Файлы в  /var/cache/logon-monitor интересны и сами по себе. Они сохраняются в формате csv (user@domain;time) 
# и могут быть открыты в Excel. History содержит информацию о последнем соединении, today  - о первом соединении сегодня.
# In user@domain 'domain' означает 'host' для локального логона Linux или Windows  
# слово 'Remote' означет логон на Cisco AnyConnect.
#
# 
# Отслеживает события: OSSEC Windows logon success (domain и local), pam unix logon, 
# cisco-asa remote access (AnyConnect) ip to user assined.
#


import sys
import MySQLdb
import codecs
import subprocess
import os
# import syslog
from datetime import *
from OSSIM_helper import get_db_connection_data


# Datababe connection config.
(dbhost,dbuser,dbpass) = get_db_connection_data()
dbschema='alienvault_siem'
asset_dbschema='alienvault'
# --- End of Database config

# ---- Init 

mytz="'+03:00'"
mycharset='cp1251'
dbcharset='utf8'
mylogpath='/var/log/user-logon-monitor.log'
# my domain names synonims (netbios and dns)
# first element of tuple is "canonical" name for use in
# logon and logon_history.list, 
# then two variants of domain names which may be in event record in database
my_doms_list = [('inbank.msk','inbankmsk','inbank.msk')]


today=date.today()
log_cache_fullpath='/var/cache/logon-monitor/logon-' + today.strftime('%Y-%m-%d') + '.list'
log_history_fullpath='/var/cache/logon-monitor/logon-history.list'

# read today logon hash
logon_dict={}
if os.path.isfile(log_cache_fullpath):
    with codecs.open(log_cache_fullpath, 'r', encoding=mycharset) as f:
        for line in f:
            (user,ltime) = line.strip().split(';') 
            logon_dict[user] = ltime
    f.close()    
else:
    if not os.path.exists('/var/cache/logon-monitor'):
        os.makedirs('/var/cache/logon-monitor')
    open(log_cache_fullpath,'a').close()
# read logon history hash    
logon_history_dict={}
if os.path.isfile(log_history_fullpath):
    with codecs.open(log_history_fullpath, 'r', encoding=mycharset) as f:
        for line in f:
            (user,ltime) = line.strip().split(';') 
            logon_history_dict[user] = ltime
    f.close()
else:
    open(log_history_fullpath,'a').close()
#
#
# set time interval for mySQL Select
period = 8
end_time=datetime.utcnow().strftime('%Y:%m:%d %H:%M:%S')
start_time=(datetime.utcnow() - timedelta(minutes=period)).strftime('%Y:%m:%d %H:%M:%S')



conn = MySQLdb.connect(host=dbhost, user=dbuser, passwd=dbpass, db=dbschema, charset=dbcharset) 
cursor = conn.cursor() 

when = "timestamp between '" + start_time + "' and '" + end_time + "'"

# ---- End of Init

# now start
mylog = codecs.open(mylogpath, 'a', encoding=mycharset)
# collect usernames in format username@domain (username@host) from siem database:
# ossec windows logon events, osses pam.unix logon, cisco-asa remote coonection (ip to user assign)
what = "username, case plugin_sid when 18107 then userdata6 when 5501 then substring_index(substring_index(data_payload,'HOSTNAME: ',-1),';',1) when 722051 then 'remote' end as udom, convert_tz(timestamp,'+00:00'," + mytz +") as time, inet_ntoa(conv(HEX(ip_src), 16, 10)), inet_ntoa(conv(HEX(ip_dst), 16, 10)) from acid_event join extra_data on id=extra_data.event_id"
where = "(plugin_id=7009 and (plugin_sid=18107 or plugin_sid=5501) or plugin_id=1636 and plugin_sid=722051) and not username='' and not userdata6='NT AUTHORITY' and locate('$',username)=0"

select="select  " + what + " where " + where + " and " + when + " order by time"
cursor.execute(select)
row=cursor.fetchone()
try:
    while row:
        uname = str(row[0]).decode(dbcharset)   
        uname = uname.strip().lower()
        udom = str(row[1]).decode(dbcharset) 
        udom = udom.strip().strip('"').lower()
        syslog_message = ' at ' + str(row[2]).decode(dbcharset).strip() + '; src ip: ' + str(row[3]).decode(dbcharset).strip() + '; dst ip: ' + str(row[4]).decode(dbcharset).strip() + '\n'
        if not '@' in uname:
            for i in my_doms_list:
                if i[1] == udom or i[2] == udom:
                    udom = i[0]
                    break
            uname = uname + '@' + udom
        if uname in logon_dict:
            logon_history_dict[uname] = str(row[2]).decode(dbcharset).strip()
        else:
            logon_dict[uname] = str(row[2]).decode(dbcharset).strip()
            with codecs.open(log_cache_fullpath, 'a', encoding=mycharset) as out:
                out.write(uname + ';' + logon_dict[uname] + '\n')
            out.close()
            if uname in logon_history_dict:
                dt = datetime.strptime(logon_history_dict[uname],'%Y-%m-%d %H:%M:%S')
                dd = (row[2] - dt).days
                if dd <5:
                    mylog.write('=1; Hello! ' + uname + syslog_message)
                elif dd < 20:
                    mylog.write('=2; Wellcome back! ' + uname + syslog_message)
                else:
                    mylog.write('=3; Wow ... Last time I saw you ' + str(dd) + ' days ago! ' + uname + syslog_message)
                logon_history_dict[uname] = str(row[2]).decode(dbcharset).strip()
            else:
                mylog.write('=4; New kid in town! ' + uname + syslog_message)
                logon_history_dict[uname] = str(row[2]).decode(dbcharset).strip()
        row=cursor.fetchone()
    with codecs.open(log_history_fullpath, 'w', encoding=mycharset) as out:
        for key in logon_history_dict.keys():
            out.write(key + ';' + logon_history_dict[key] + '\n')
    out.close()
except Exception:
    mylog.write('=100;Error! no_user at ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '; src ip 0.0.0.0; dst ip 0.0.0.0 '+ str(sys.exc_info()[0]) + '\n')
    raise
mylog.close()
conn.close()

