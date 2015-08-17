#! /usr/bin/python
# -*- coding: latin1 -*-
import sys
#import codecs
import subprocess
cfg_path = '/etc/ossim/agent/config.cfg'
new_cfg_path = '/var/local/config.tmp'
encoding_exceptions = {'wmi-monitor':'utf8'}
my_encoding = 'cp1251'
with open (cfg_path,'r') as f:
   conf = f.read()
f.close
start_flag = False
continue_flag = True
need_update = False
out_lines=[]
for line in conf.splitlines():
    out_lines.append(line.strip())
    if  start_flag and continue_flag :
        if not '=' in out_lines[-1]:
            continue_flag = False
        elif not '|' in out_lines[-1]:
            key = out_lines[-1].split('=')[0]
            need_update = True
            if key in encoding_exceptions:
               out_lines[-1] = out_lines[-1] + '|' + encoding_exceptions[key]
            else:
               out_lines[-1] = out_lines[-1] + '|' + my_encoding
    if '[plugins]' in out_lines[-1]:
        start_flag = True
if need_update :
    with open(new_cfg_path,'w') as f:
        for line in out_lines:
            f.write(line + '\n')
    f.close          
    cmd = '/bin/cp -f /etc/ossim/agent/config.cfg /etc/ossim/agent/config.cfg.myreconfig.bak'
    p = subprocess.Popen (cmd, shell=True)
    p_stutus = p.wait()
    cmd = '/bin/cp -f /var/local/config.tmp /etc/ossim/agent/config.cfg'
    p = subprocess.Popen (cmd, shell=True)
    p_stutus = p.wait()
# check PerserUtil.py
pu_need_update = False
with open ('/usr/share/alienvault/ossim-agent/ParserUtil.py', 'r') as f:
    pu=f.read()
f.close()
if not 'my ParserUtil tail' in  pu:
    cmd = 'cp -f /usr/share/alienvault/ossim-agent/ParserUtil.py /usr/share/alienvault/ossim-agent/ParserUtil.py.myreconfig.bak'
    p = subprocess.Popen (cmd, shell=True)
    p_stutus = p.wait()
    
    cmd = 'cat /usr/local/bin/my_ParserUtil.tail >> /usr/share/alienvault/ossim-agent/ParserUtil.py'
    p = subprocess.Popen (cmd, shell=True)
    p_stutus = p.wait()
    
 