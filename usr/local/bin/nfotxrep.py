#! /usr/bin/python
# -*- coding: utf8 -*-
# автор esguardian@outlook.com
# версия 2.0.1 + данные geoip
# Отчет об обнаружении в Netflow адресов из списка "плохих" по версии OTX 
# собирает данные от плагина nfotx
# в отчет включается также полный список NetFlow для каждого "пойманного" хоста
#
import os
import sys
import MySQLdb
import codecs
import subprocess
from datetime import date, timedelta
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

outfilename='OTX-' + today.strftime('%Y-%m-%d') + '.csv'
outfullpath='/usr/local/ossim_reports/' + outfilename

mytz="'+03:00'"
mycharset='cp1251'
dbcharset='utf8'
colheader=u'Время;Источник;Внешний IP;Место;Репутация хоста\n'
my_rep_data = {}
if os.path.isfile('/etc/esguard_ossim/my_reputation.data'):
    with codecs.open('/etc/esguard_ossim/my_reputation.data', 'r', encoding=mycharset) as f:
        for line in f:
            if '#' in line:
                (ip,rep) = line.strip().split('#')
                my_rep_data[ip] = rep.strip()
    f.close() 

conn = MySQLdb.connect(host=dbhost, user=dbuser, passwd=dbpass, db=dbshema, charset=dbcharset) 
cursor = conn.cursor() 
reader=geoip2.database.Reader("/usr/share/geoip/GeoLite2-City.mmdb")
# ---- End of Init
when = "timestamp between '" + starttime + "' and '" + endtime + "'"

# start
tabheader=u'\n\n\nКоммуникации с известными вредоносными хостами за период ' + startdate + ' - ' + enddate + '\n\n'
what="convert_tz(timestamp,'+00:00'," + mytz +") as time, src_hostname, substring_index(substring_index(data_payload,'-> ',-1),':',1) as dst_ip, rep_act_dst from acid_event join extra_data on acid_event.id=extra_data.event_id left join reputation_data on id=reputation_data.event_id"
where="acid_event.plugin_id=90011 and acid_event.plugin_sid=1"
select="select  " + what + " where " + where + " and " + when + " order by time"
cursor.execute(select)
list=[] # create list of returned data for later use
dup=[] # Нам не нужны дублирующие записи. Они все равно будут в NetFlow
with codecs.open(outfullpath, 'a', encoding=mycharset) as out:
    out.write(tabheader + colheader) 
    row = cursor.fetchone() 
    while row:
        dst = row[2].strip()
        if dst not in dup: 
            dup.append(dst)        
            if row[3] is None:
                if dst in my_rep_data:
                    rep = my_rep_data[dst]
                else:
                    rep = 'None'
            else:
                rep = str(row[3]).decode(dbcharset) 
            if rep.lower() != 'false':
                place = get_place(reader, dst, mycharset)
                outstr = str(row[0]).decode(dbcharset).replace(';',',').strip()
                outstr = outstr + ';' + str(row[1]).decode(dbcharset).replace(';',',').strip() 
                outstr = outstr + ';' + dst
                outstr = outstr + ';' + place
                outstr = outstr + ';' + rep.replace(';',',').strip()             
                list.append(outstr)
                out.write(outstr + '\n')
        row = cursor.fetchone()
    # and now add to the file netflow data for each event
    for item in list:
        (time,src,dst,place,rep)=item.split(';')
        # prepare nfdump command
        nf_dump_cmd = "/usr/bin/nfdump -R " + nfdir + " -q -m -t "+ nfdump_start + "-" + nfdump_end + " -o line " + "'ip " + dst + "'"
        p = subprocess.Popen (nf_dump_cmd, stdout=subprocess.PIPE, shell=True)
        (output,err) = p.communicate()
        p_stutus = p.wait()
        tabheader = u'\n\n\nИнформация Netflow для ' + dst + ' : ' + place + ' : ' + rep + '\n'
        colheader = u'Время;Период;Протокол;Источник;Получатель;Пакетов;Байт;Потоков\n'
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
reader.close()
conn.close()
