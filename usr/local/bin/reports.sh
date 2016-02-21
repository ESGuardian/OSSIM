#!/bin/bash
/usr/local/bin/accrep.py $1
/usr/local/bin/apprep.py $1
/usr/local/bin/rarep.py $1
/usr/local/bin/tmgrep.py $1
/usr/local/bin/nfotxrep.py $1
/usr/local/bin/idsrep.py l=$1 g=telebank_online_jira f=/usr/local/etc/my_suricata_filter01

