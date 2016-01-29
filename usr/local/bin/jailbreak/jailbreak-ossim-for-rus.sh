#! /bin/sh
sed  "s:'start'):'start')\n      /usr/local/bin/check_mysql_config.py > /dev/null\n:" /etc/init.d/mysql > /usr/local/bin/test
