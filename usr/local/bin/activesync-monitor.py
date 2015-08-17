#! /usr/bin/python
# -*- coding: cp1251 -*-
# author Eugene Sokolov esguardian@outlook.com
# version 1.0.1
# монитор событий ActiveSync на основе собираемых журналов MS TMG
# Для работы необходим мой плагин tmg-web (см /etc/ossim/plugins/tmg-web.cfg)
#
# создает два рабочих файла /var/cache/logon-monitor/as-access-history.list и /var/cache/logon-monitor/as-access-<today_date>.list 
# и записывает в /var/log/activesync-access-monitor.log 5 типов событий:
# 1 - Hello! If a user is logged the first time today and is already registered in the past 5 days
# 2 - Wellcome back! If a user is logged the first time today and has last recorded more than 5 but less than 20 days ago
# 3 - Wow... Last time I saw you NN days ago! If a user last recorded more then 20 days ago
# 4 - New user-device pair! If a user-device pair never been regestered before
# 5 - User device change address! If source ip address changed from last access.
# 100 - Error! if a script has stoped by error when.
# К этому монитору полагается мой соответствующий плагин activesync-monitor (см /etc/ossim/plugins/activesync-monitor.cfg),
# который читает этот лог и записывает события в базу OSSIM.
# Файлы в  /var/cache/logon-monitor интересны и сами по себе. Они сохраняются в формате csv (user@domain;device_type;device-id;ip_address;time)
# и могут быть открыты в Excel. History содержит информацию о последнем соединении, today  - о первом соединении сегодня.
# 
#
# 
# Контролируемое событие: появление команды ActiveSync Sync в URI в логе TMG.
#
# 

import sys
import MySQLdb
import codecs
import subprocess
import os
# import syslog
from datetime import *
from OSSIM_helper import get_db_connection_data, check_that_first_later


# Datababe connection config.
(dbhost,dbuser,dbpass) = get_db_connection_data()
dbschema='alienvault_siem'
asset_dbschema='alienvault'
# --- End of Database config

# ---- Init 

mytz="'+03:00'"
mycharset='cp1251'
dbcharset='utf8'
mylogpath='/var/log/activesync-access-monitor.log'
mydebuglogpath='/var/log/mydebug.log'
# my domain names synonims (netbios and dns)
# first element of tuple is "canonical" name for use in
# logon and logon_history.list, 
# then two variants of domain names which may be in event record in database
my_doms_list = [('inbank.msk','inbankmsk','inbank.msk')]


today=date.today()
log_cache_fullpath='/var/cache/logon-monitor/as-access-' + today.strftime('%Y-%m-%d') + '.list'
log_history_fullpath='/var/cache/logon-monitor/as-access-history.list'

# read today logon hash
logon_dict={}
if os.path.isfile(log_cache_fullpath):
    with codecs.open(log_cache_fullpath, 'r', encoding=mycharset) as f:
        for line in f:
            (user,dev_type,dev_id,astr,ltime) = line.strip().split(';')
            udev = user + ';' + dev_type + ';' + dev_id 
            logon_dict[udev] = (astr,ltime)
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
            (user,dev_type,dev_id,astr,ltime) = line.strip().split(';')
            udev = user + ';' + dev_type + ';' + dev_id 
            logon_history_dict[udev] = (astr,ltime)
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
# mydebuglog = open(mydebuglogpath, 'a')
mylog = codecs.open(mylogpath, 'a', encoding=mycharset)
#
# collect usernames in format username@domain (username@host) from siem database:
# tmg-web Exchange ActiveSync events and create hash tables on key 'username;device_type;device_id'
#
what = "username, userdata9, convert_tz(timestamp,'+00:00'," + mytz +") as time, inet_ntoa(conv(HEX(ip_src), 16, 10)) from acid_event join extra_data on id=extra_data.event_id"
where = "plugin_id=9004 and plugin_sid=2"

select="select  " + what + " where " + where + " and " + when + " order by time"
cursor.execute(select)
row=cursor.fetchone()
try:
    while row:
        row_0=str(row[0]).decode(dbcharset).strip().lower()   
        syslog_message = ' at ' + str(row[2]).decode(dbcharset).strip() + '; src ip: ' + str(row[3]).decode(dbcharset).strip() + '\n'
        #
        # reading username and domain from database row
        # we don't know format in wich username has stored 
        # "dom\user", "user@dom" or just "user"
        #
        if '\\' in row_0:
            (udom,rest) = row_0.split('\\')  
            if '@' in rest:
                uname = rest.split('@')[0]
            else:
                uname = rest
        elif '@' in row_0:
            (uname,udom) = row_0.split('@')
        else:
            uname = row_0
            udom = 'undefined'
        #
        # reading ActiveSync command params stored in URI
        # 
        paramlist=[]   
        paramlist = str(row[1]).decode(dbcharset).split('&')
        param_user=""
        for param in paramlist:
            if 'DeviceId=' in param:
                dev_id = param.split('=')[-1]
            if 'DeviceType=' in param:
                dev_type = param.split('=')[-1]
            if 'User=' in param:
                param_user = param.split('=')[-1]
        #
        # if previosly obtained from database username is "anonymous" 
        # try to obtain it from ActiveSync command params stored in URI
        #
        if uname == 'anonymous':
            if '%40' in param_user:
                (uname,udom) = param_user.split('%40')
            elif '%5C' in param_user:
                (udom,uname) = param_user.split('%5C')
            else:
                uname = param_user
        #
        # normalize username as user@domain
        #
        for i in my_doms_list:
            if i[1] == udom or i[2] == udom:
                udom = i[0]
                break
        uname = uname + '@' + udom
        #
        # creating userdevice key for dictionary
        #
        udev = uname + ';' + dev_type + ';' + dev_id 
        #
        # check today logons and history for this userdevice and generate event
        #
        new_ip = str(row[3]).decode(dbcharset).strip()
        evtime = str(row[2]).decode(dbcharset).strip()             
        if udev in logon_dict:
            if check_that_first_later(evtime,logon_history_dict[udev][1]) and new_ip != logon_history_dict[udev][0]:
                mylog.write('=5; User device change address! '  + uname + ' with ' + dev_type + ' ' + dev_id + syslog_message)
                logon_history_dict[udev] = (new_ip, evtime)
        else:
            logon_dict[udev] = (new_ip, evtime)
            #
            # uppend today logons if new 
            #
            with codecs.open(log_cache_fullpath, 'a', encoding=mycharset) as out:
                out.write(udev + ';' + logon_dict[udev][0] + ';' + logon_dict[udev][1] + '\n')
            out.close()
            #
            if udev in logon_history_dict:
                dt = datetime.strptime(logon_history_dict[udev][1],'%Y-%m-%d %H:%M:%S')
                dd = (row[2] - dt).days
                if dd <5:
                    mylog.write('=1; Hello! ' + uname + ' with ' + dev_type + ' ' + dev_id + syslog_message)
                elif dd < 20:
                    mylog.write('=2; Wellcome back! ' + uname + ' with ' + dev_type + ' ' + dev_id + syslog_message)
                else:
                    mylog.write('=3; Wow ... Last time I saw you ' + str(dd) + ' days ago! ' + uname + ' with ' + dev_type + ' ' + dev_id + syslog_message)
                logon_history_dict[udev] = (new_ip, evtime)
            else:
                mylog.write('=4; New user-device pair! ' + uname  + ' with ' + dev_type + ' ' + dev_id + syslog_message)
                logon_history_dict[udev] = (new_ip, evtime)
        #
        # next row
        #
        row=cursor.fetchone()
    # 
    # write history file
    #
    with codecs.open(log_history_fullpath, 'w', encoding=mycharset) as out:
        for key in logon_history_dict.keys():
            out.write(key + ';' + logon_history_dict[key][0] + ';' + logon_history_dict[key][1] + '\n')
    out.close()
except Exception:
    mylog.write('=100;Error! no_user at ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '; src ip 0.0.0.0; dst ip 0.0.0.0 '+ str(sys.exc_info()[0]) + '\n')
    raise
mylog.close()
# mydebuglog.close()
conn.close()

