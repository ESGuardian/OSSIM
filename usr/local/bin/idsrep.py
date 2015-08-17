#! /usr/bin/python
# -*- coding: cp1251 -*-
# author Eugene Sokolov esguardian@outlook.com
# version 1.0.1 
# команда: 
# idsrep.py number host_group_name
# где: 
# number - число дней от "сегодня", если пропущено, то 1
# host_group_name - строковое имя группы хостов (asset group) предварительно созданной в OSSIM
# это имя не должно содержать пробелов или должно быть взято в кавычки (двойные)
# если имя не указано будут выданы события IDS (suricata) для всех хостов
# будьте внимательны, в этом случае объем файла может быть слишком большим для Excel,
# поскольку отчет будет содержать огромное количество неагрегированных данных netflow 
#
# 
# Скрипт создает csv со списком событий IDS, а затем для каждого "атакующего" список всех его Netwlow, 
# можно легко посмотреть, что происходило.
# 
# 
import os
import sys
import MySQLdb
import codecs
import subprocess
from datetime import date, timedelta
from OSSIM_helper import get_db_connection_data


# Datababe connection config.
(dbhost,dbuser,dbpass) = get_db_connection_data()
dbschema='alienvault_siem'
asset_dbschema='alienvault'
# --- End of Database config

# ---- Init 

period=1
asset_group_name=''
if len(sys.argv) > 1:
    for c in sys.argv:
        if c.isdigit():
            period = int(c)
        elif 'idsrep.py' not in c:
            asset_group_name = c.strip('"').strip("'")


# set time interval for mySQL Select
today=date.today()
enddate=today.strftime('%Y:%m:%d')
endtime=enddate + ' 06:00:00' # UTC time
startdate=(today - timedelta(days=period)).strftime('%Y:%m:%d')
starttime=startdate + ' 06:00:00'

#set time interval for nfdump search
nfdump_end = today.strftime('%Y/%m/%d') + '.09:00:00'
nfdump_start = (today - timedelta(days=period)).strftime('%Y/%m/%d') + '.09:00:00'
#set path to flow cache
nfdir = '/var/cache/nfdump/flows/live'
# ----- end of nfdump setting

outfilename='IDS-for-'+ asset_group_name.replace(' ','_') + '-' + today.strftime('%Y-%m-%d') + '.csv'
outfullpath='/usr/local/ossim_reports/' + outfilename

mytz="'+03:00'"
mycharset='cp1251'
dbcharset='utf8'
my_rep_data = {}
if os.path.isfile('/etc/my_ossim/my_reputation.data'):
    with codecs.open('/etc/my_ossim/my_reputation.data', 'r', encoding=mycharset) as f:
        for line in f:
            if '#' in line:
                (ip,rep) = line.strip().split('#')
                my_rep_data[ip] = rep.strip()
    f.close() 


conn_av = MySQLdb.connect(host=dbhost, user=dbuser, passwd=dbpass, db=asset_dbschema, charset=dbcharset)
cursor_av = conn_av.cursor() 
conn = MySQLdb.connect(host=dbhost, user=dbuser, passwd=dbpass, db=dbschema, charset=dbcharset) 
cursor = conn.cursor() 

when = "timestamp between '" + starttime + "' and '" + endtime + "'"

# ---- End of Init

# now start

# collect ip addresses for hosts in asset group
ip_adrs_str = ''
if asset_group_name != '':
    select = "select inet_ntoa(conv(HEX(ip), 16, 10)) from host_group join host_group_reference on id=host_group_reference.host_group_id join host_ip on host_group_reference.host_id=host_ip.host_id where name='" + asset_group_name + "'"
    cursor_av.execute(select)
    row_av = cursor_av.fetchone()
    if row_av is None:
        with codecs.open(outfullpath, 'a', encoding=mycharset) as out:
            out.write('Группа '.decode(mycharset) + asset_group_name + ' не найдена. Работа завершена без создания отчета'.decode(mycharset)) 
        out.close()
        conn_av.close() 
        sys.exit()
    ip_adrs_str = ';'
    # all ip placed in ;...; for carefull string search later  
    while row_av:
        for c in row_av:
            ip_adrs_str = ip_adrs_str + c + ';'
        row_av = cursor_av.fetchone()

# --- ip addresses collected. continue

colheader='Сигнатура;Время;Источник;Атакуемый хост;Репутация источника\n'.decode(mycharset)
tabheader='\n\nДанные IDS Suricata для группы ностов '.decode(mycharset) + asset_group_name +' за период '.decode(mycharset) + startdate + ' - ' + enddate + '\n\n'
# create and execute SELECT 

what="plugin_sid,convert_tz(timestamp,'+00:00'," + mytz +") as time, inet_ntoa(conv(HEX(ip_src), 16, 10)), inet_ntoa(conv(HEX(ip_dst), 16, 10)), rep_act_src from acid_event join extra_data on id=extra_data.event_id left join reputation_data on id=reputation_data.event_id"

if ip_adrs_str !='':
    where="plugin_id=1001 and locate(concat(';',concat(inet_ntoa(conv(HEX(ip_dst), 16, 10)),';')),'"+ip_adrs_str+"')"
else:
    where="plugin_id=1001"

select="select  " + what + " where " + where + " and " + when + " order by time"
cursor.execute(select)

list=[] # create list of returned data for later use
with codecs.open(outfullpath, 'a', encoding=mycharset) as out:
    out.write(tabheader + colheader) 
    row = cursor.fetchone() 
    while row:
        src = row[2].strip()       
        if row[4] is None:
            if src in my_rep_data:
                rep = my_rep_data[src]
            else:
                rep = 'None'
        else:
            rep = str(row[4]).decode(dbcharset) 
        if rep.lower() != 'false':
            outstr = str(row[1]).decode(dbcharset).replace(';',',').strip()        
            outstr = outstr + ';' + src
            outstr = outstr + ';' + row[3].strip()
            outstr = outstr + ';' + rep.replace(';',',')
            plugin_sid = str(row[0]).strip() 
            list.append(outstr)
            # now get signature name
            signature_name = 'Unknown'
            cursor_av.execute('select name from plugin_sid where plugin_id=1001 and sid=' + plugin_sid)
            row_av = cursor_av.fetchone()
            for c in row_av:
                signature_name = str(c).decode(dbcharset)
            outstr = signature_name.replace(';',',') + ';' + outstr
            out.write(outstr + '\n')
        row = cursor.fetchone()
    # and now add to the file netflow data for each event but deduplicate
    dup=[]
    for item in list:
        (time,src,dst,rep)=item.split(';')
        if src not in dup:
            dup.append(src)    
            # prepare nfdump command
            nf_dump_cmd = "/usr/bin/nfdump -R " + nfdir + " -q -m -t "+ nfdump_start + "-" + nfdump_end + " -o line " + "'ip " + src +  "'"
            p = subprocess.Popen (nf_dump_cmd, stdout=subprocess.PIPE, shell=True)
            (output,err) = p.communicate()
            p_stutus = p.wait()
            tabheader = '\nИнформация Netflow для '.decode(mycharset) + src + ' : ' + rep + '\n'
            colheader = 'Время;Период;Протокол;Источник;Получатель;Пакетов;Байт;Потоков\n'.decode(mycharset)
            out.write(tabheader + colheader)
            for line in output.splitlines():
                fields = line.rstrip().split()
                stime = fields[0] + ' ' + fields[1]
                sduration = fields[2]
                sproto = fields[3]
                ssrc=fields[4]
                sdst = fields[6]
                spackets = fields[7]
                sbytes = fields[8]
                sflows = fields[9]
                outstr=stime + ';' + sduration + ';' + sproto + ';' + ssrc + ';' + sdst + ';' + spackets + ';' + sbytes + ';' + sflows
                out.write(outstr + '\n')

out.close()
# --- End of All
conn.close()
conn_av.close()

