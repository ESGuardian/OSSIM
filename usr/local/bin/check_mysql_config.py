#! /usr/bin/python
# -*- coding: latin1 -*-
import sys
#import codecs
import subprocess
cfg_path = '/etc/mysql/my.cnf'
with open (cfg_path,'r') as f:
   conf = f.read()
f.close
if not '!includedir /usr/local/etc/mysql' in conf:
    cmd = 'cp -f /etc/mysql/my.cnf /etc/mysql/my.cnf.myreconfig.bak'
    p = subprocess.Popen (cmd, shell=True)
    p_stutus = p.wait()
    with open (cfg_path,'a') as f:
        f.write('\n!includedir /usr/local/etc/mysql\n')
    f.close
 