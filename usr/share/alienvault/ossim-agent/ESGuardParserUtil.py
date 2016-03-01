#! /usr/bin/python
# -*- coding: utf8 -*-
# автор esguardian@outlook.com
# Для поддержки моих плагинов
#
import sys
import codecs

MONITORED_URLS=[]
UNMONITORED_URLS=[]
try:
    with open("/etc/esgurd_ossim/monitored_urls.list","r") as f:
        MONITORED_URLS=[line.rstrip() for line in f]
    f.close()
except:
    pass
try:
    with open("/etc/esgurd_ossim/unmonitored_urls.list","r") as f:
        UNMONITORED_URLS=[line.rstrip() for line in f]
    f.close()
except:
    pass
    
ZGATE_TRANSLATION_TABLE={}
try:
    with codecs.open("/etc/esguard_ossim/zgate_translation.table","r",encoding="utf8") as f:
        for line in f:
            (key,value) = line.split('=')
            ZGATE_TRANSLATION_TABLE[key.strip()]=int(value.strip())            
    f.close()
except:
    pass

def my_tmg_web_sid(bsent=0, breceived=0, url='0', uri=''):
    if 'Microsoft-Server-ActiveSync' in uri and 'Cmd=Sync' in uri:
        return 2
    sid = 1
    for elem in UNMONITORED_URLS:
        dot_elem="."+elem
        if elem == url or dot_elem in url:
           return 1
    bsent = int(bsent)
    breceived = int (breceived)
    if bsent > 1000000:
        return 2000
    if bsent > breceived:
        sid = sid + 10
    if bsent > 200000: 
        sid = sid + 100
    for elem in MONITORED_URLS:
        dot_elem="."+elem
        if elem == url or dot_elem in url:
           sid = sid + 1000
           break
    return sid

def zgate_sid(TypeSubject=''):
    key = TypeSubject.decode('utf8')    
    if key in ZGATE_TRANSLATION_TABLE:
        return ZGATE_TRANSLATION_TABLE[key]
    return 9999
    