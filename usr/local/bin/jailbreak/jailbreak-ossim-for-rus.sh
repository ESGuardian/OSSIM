#! /bin/sh
####################################
#     jailbreak-ossim-for-rus      #
####################################
# скрипт для русификации AlienVault OSSIM
# так же может быть использован для AlienVault USM без изменений
# 
# Copyright Евгений Соколов (esguardian) esguardian@outlook.com 30.01.2016
#
# Использовать просто:
# Скопировать куда-нибудь на сервере OSSIM, лучше в /usr/local/bin/jailbreak, создав эту директорию.
# дать права на выполнение chmod 755 /usr/local/bin/jailbreak/jailbreak-ossim-for-rus.sh
# перейти в директорию со скриптом
# запустить ./jailbreak-ossim-for-rus.sh
#
############################
# Конфигурируем mysql      #
############################
#
# Проверяем наличие нашего собственного файла конфигурации и создаем его, если отсутствует
#
if [ ! -f /etc/mysql/conf.d/jailbreak-ossim-for-rus.cnf ]; then
    cat > /etc/mysql/conf.d/jailbreak-ossim-for-rus.cnf <<DELIM
# --- esguardian jailbreak for russian language
    [client]
    default-character-set=utf8
    [mysqld]
    skip-character-set-client-handshake
    collation-server = utf8_unicode_ci
    init-connect='SET collation_connection = utf8_unicode_ci'
    character-set-server = utf8
# ---   
DELIM
    chmod -R 755 /etc/mysql/conf.d/jailbreak-ossim-for-rus.cnf
fi
#
# Проверяем наличие нашего скрипта коррекции my.cnf перед стартом mysql 
# создаем скрипт, если его нет
#
if [ ! -f /usr/local/bin/jailbreak/check_mysql_config.py ]; then
    if [ ! -d /usr/local/bin/jailbreak ]; then
        mkdir /usr/local/bin/jailbreak
    fi
    cat > /usr/local/bin/jailbreak/check_mysql_config.py <<DELIM
#! /usr/bin/python
# -*- coding: latin1 -*-
import sys
#import codecs
import subprocess
cfg_path = '/etc/mysql/my.cnf'
with open (cfg_path,'r') as f:
   conf = f.read()
f.close
if '#!includedir /etc/mysql/conf.d/' in conf:
    cmd = 'sed -i -e "s:#!includedir /etc/mysql/conf.d/:!includedir /etc/mysql/conf.d/:" /etc/mysql/my.cnf'
    p = subprocess.Popen (cmd, shell=True)
    p_stutus = p.wait()
if not '!includedir /etc/mysql/conf.d/' in conf:
    cmd = 'cp -f /etc/mysql/my.cnf /etc/mysql/my.cnf.myreconfig.bak'
    p = subprocess.Popen (cmd, shell=True)
    p_stutus = p.wait()
    with open (cfg_path,'a') as f:
        f.write('\n!includedir /usr/local/etc/mysql\n')
    f.close    
DELIM
    chmod -R 755 /usr/local/bin/jailbreak
fi
#
# проверяем наличие в стартовом скрипте mysql строки с вызовом нашего скрипта корреции
# вставляем эту строку, если ее нет
#
if ! grep -q "/usr/local/bin/jailbreak/check_mysql_config.py" /etc/init.d/mysql; then
    cp /etc/init.d/mysql /usr/local/bin/jailbreak/mysql.old
    sed  -i -e "s:'start'):'start')\n    /usr/local/bin/jailbreak/check_mysql_config.py > /dev/null\n:" /etc/init.d/mysql
fi
#
#################################
# Конфигурируем ossim-agent     #
#################################
#
# Проверяем наличие нашего скрипта коррекции файла конфигурации агентов
# создаем файл, если его нет
#
if [ ! -f /usr/local/bin/jailbreak/check_encoding.py ]; then
    if [ ! -d /usr/local/bin/jailbreak ]; then
        mkdir /usr/local/bin/jailbreak
    fi
    cat > /usr/local/bin/jailbreak/check_encoding.py <<DELIM
#! /usr/bin/python
# -*- coding: latin1 -*-
import sys
#import codecs
import subprocess
cfg_path = '/etc/ossim/agent/config.cfg'
new_cfg_path = '/var/local/config.tmp'
encoding_exceptions = {'wmi-monitor':'utf-8','zgate':'utf-8','oramon':'utf-8'}
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
DELIM
    chmod -R 755 /usr/local/bin/jailbreak
fi
#
# проверяем наличие в стартовом скрипте ossim-agent строки с вызовом нашего скрипта корреции
# вставляем эту строку, если ее нет
#
if ! grep -q "/usr/local/bin/jailbreak/check_encoding.py" /etc/init.d/ossim-agent; then
    cp /etc/init.d/ossim-agent /usr/local/bin/jailbreak/ossim-agent.old
    sed  -i -e "s:d_start() {:d_start() {\n    /usr/local/bin/jailbreak/check_encoding.py > /dev/null\n:" /etc/init.d/ossim-agent
fi
#
#################################
# Конфигурируем freetds         #
#################################
#
if ! grep -q "jailbreak-ossim-for-rus" /etc/freetds/freetds.conf; then
    if [ -f /etc/freetds/freetds.conf ]; then
        cp /etc/freetds/freetds.conf /usr/local/bin/jailbreak/freetds.conf.old
        rm /etc/freetds/freetds.conf
    fi
    cat > /etc/freetds/freetds.conf <<DELIM
# This file is installed by jailbreak-ossim-for-rus  
#
# For information about the layout of this file and its settings, 
# see the freetds.conf manpage "man freetds.conf".  

# Global settings are overridden by those in a database
# server specific section
[global]
tds version = 7.0
# Whether to write a TDSDUMP file for diagnostic purposes
# (setting this to /tmp is insecure on a multi-user system)
; dump file = /tmp/freetds.log
; debug flags = 0xffff
# Command and connection timeouts
; timeout = 10
; connect timeout = 10
client charset = UTF-8

# If you get out-of-memory errors, it may mean that your client
# is trying to allocate a huge buffer for a TEXT field.  
# Try setting 'text size' to a more reasonable limit 
text size = 64512    
DELIM
    chmod 755 /etc/freetds/freetds.conf
fi
#
##########################################
# Конфигурируем apache2                  #
##########################################
#
if ! grep -q "jailbreak-ossim-for-rus" /etc/apache2/conf-available/charset.conf; then
    if [ -f /etc/apache2/conf-available/charset.conf ]; then
        cp /etc/apache2/conf-available/charset.conf /usr/local/bin/jailbreak/charset.conf.old
        rm /etc/apache2/conf-available/charset.conf
    fi
    cat > /etc/apache2/conf-available/charset.conf <<DELIM
# This file is installed by jailbreak-ossim-for-rus  
AddDefaultCharset UTF-8  
DELIM
    chmod 755 /etc/apache2/conf-available/charset.conf
fi
#
######################################
# Рестартуем сервисы                 #
######################################
#
/etc/init.d/mysql restart
/etc/init.d/ossim-agent restart