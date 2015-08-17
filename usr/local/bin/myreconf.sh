#!/bin/bash
/usr/local/bin/check_my_config.py
/usr/local/bin/check_mysql_config.py
/etc/init.d/ossim-server restart
/etc/init.d/ossim-agent restart


