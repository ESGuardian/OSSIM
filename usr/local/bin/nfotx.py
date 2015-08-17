#!/usr/bin/python

#Author esguardian@outlook.com
#Python variant of nfotx.pl created by AlienVault community user @PacketInspector
#Uses nfdump and looks for matches in otx and your own bad ip list
#your own ip list may be in free format, but each ip address must end with '#'

import os
import datetime
import syslog
import subprocess
import codecs

#Using syslog to make logs
syslog.openlog('nfotx')

#Polling interval.  Usually equal to watchdog interval (in minutes)
pi = datetime.timedelta(minutes=3)
#next string I have use for correcting system error with Moscow timezone. Now it's not necessary
#offset = datetime.timedelta(hours=1)

#Set some vars
#stats file is smaller...
otx_ip_repfile =  '/etc/ossim/server/reputation.data'
my_ip_repfile = '/etc/my_ossim/my_reputation.data'
mycharset = 'cp1251'

#You may want to extend this directory lower to a specific collector.  You probably don't want to run this against netflow from perimeter for instance
nfdir = '/var/cache/nfdump/flows/live'


#Make a polling date for nfdump to check
current_time = datetime.datetime.now()
nfdump_check_time = (current_time - pi).strftime("%Y/%m/%d.%H:%M:%S")
nfdump_check_now = current_time.strftime("%Y/%m/%d.%H:%M:%S")

#Open the OTX DB
with open(otx_ip_repfile, 'r') as f:
    otx_iprepdata = f.read()
f.close()

#Open the MY_REPUTATION DB
my_rep_data = {}
if os.path.isfile(my_ip_repfile):
    with codecs.open(my_ip_repfile, 'r', encoding=mycharset) as f:
        for line in f:
            if '#' in line:
                (ip,rep) = line.strip().split('#')
                my_rep_data[ip] = rep.strip()
    f.close() 


#Build cmd
nf_dump_cmd = '/usr/bin/nfdump -R ' + nfdir + ' -q -N -m -A srcip,dstip -t '+ nfdump_check_time + '-' + nfdump_check_now + ' -o extended'
p = subprocess.Popen (nf_dump_cmd, stdout=subprocess.PIPE, shell=True)
(output,err) = p.communicate()
p_stutus = p.wait()

#Initialize a hash to check for dupes, keep count for first match reference
dupes = {}
i = 0

for line in output.splitlines() :
    fields = line.rstrip().split()
#   Grab destination, only checking one source since flows are bi-directional
    (dst_ip, dst_port) = fields[6].split(':')
#   Skip if checked already
    if dupes.has_key(dst_ip) : 
        continue
    dupes[dst_ip] = i
#   Now search reputation.data
    search_ip = dst_ip + '#'
    if dst_ip in my_rep_data:
        if my_rep_data[dst_ip].lower() != 'false':
            syslog.syslog(line)
    elif search_ip in otx_iprepdata :
        syslog.syslog(line)
    i = i + 1


