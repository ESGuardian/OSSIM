#! /bin/sh
#
#################################################
#     jailbreak-ossim-for-esguardian-plugins    #
#################################################
#
# скрипт для включения поддержки специфических плагинов для OSSIM
# нельзя использовать для USM
# 
# Copyright Евгений Соколов (esguardian) esguardian@outlook.com 30.01.2016
#
# Использовать просто:
# Скопировать куда-нибудь на сервере OSSIM, лучше в /usr/local/bin/jailbreak, создав эту директорию.
# дать права на выполнение chmod 755 /usr/local/bin/jailbreak/jailbreak-ossim-for-esguardian-plugins.sh
# перейти в директорию со скриптом
# запустить ./jailbreak-ossim-for-esguardian-plugins.sh
#

#
#################################
# Конфигурируем ossim-agent     #
#################################
#
# Проверяем наличие нашего скрипта коррекции файла конфигурации агентов
# создаем файл, если его нет
#
if [ ! -f /usr/local/bin/jailbreak/check_esguardian_config.py ]; then
    if [ ! -d /usr/local/bin/jailbreak ]; then
        mkdir /usr/local/bin/jailbreak
    fi
    cat > /usr/local/bin/jailbreak/check_esguardian_config.py <<DELIM
#! /usr/bin/python
# -*- coding: latin1 -*-
import sys
#import codecs
import subprocess

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
DELIM
    chmod -R 755 /usr/local/bin/jailbreak
fi
#
# проверяем наличие в стартовом скрипте ossim-agent строки с вызовом нашего скрипта корреции
# вставляем эту строку, если ее нет
#
if ! grep -q "/usr/local/bin/jailbreak/check_esguardian_config.py" /etc/init.d/ossim-agent; then
    cp /etc/init.d/ossim-agent /usr/local/bin/jailbreak/ossim-agent.old
    sed  -i -e "s:d_start() {:d_start() {\n    /usr/local/bin/jailbreak/check_esguardian_config.py > /dev/null\n:" /etc/init.d/ossim-agent
fi
# 
# Устанавливаем geoip2
#
if [ ! -f /usr/share/geoip/GeoLite2-City.mmdb ]; then
    cd /tmp
    wget https://bootstrap.pypa.io/get-pip.py --no-check-certificate
    python get-pip.py
    pip install geoip2
    wget http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz
    gunzip GeoLite2-City.mmdb.gz
    cp GeoLite2-City.mmdb /usr/share/geoip/GeoLite2-City.mmdb
    chmod 644 /usr/share/geoip/GeoLite2-City.mmdb
fi
#
######################################
# Рестартуем сервисы                 #
######################################
#
/etc/init.d/ossim-agent restart