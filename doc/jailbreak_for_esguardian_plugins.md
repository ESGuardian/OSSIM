## Модификации для поддержки моих плагинов и отчетов ##

Некоторые мои плагины используют модифицированный файл ParserUtil.py в хвост которого я добавляю декларации необходимых мне собственных функций. Кроме того, мои отчеты используют базу Maxmid GeoIP2, а в OSSIM используется устаревший формат geoip. Значит модуль GeoIP2 для python нужно устанавливать дополнительно.

По аналогии с jailbreak-ossim-for-rus.sh я написал скрипт jailbreak-ossim-for-esguardian-plugins.sh, который вносит необходимые изменения для поддержки моих плагинов и отчетов.

Лежит здесь: `/usr/local/bin/jailbreak/`

**Важно**. Я не обновляю базу данных GeoIP2 автоматически. Я периодически делаю это вручную, поэтому никаких скриптов обновления базы нет. Обновить базу можно последовательностью команд с консоли:

    cd /tmp
    rm GeoLite*
    wget http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz
    gunzip GeoLite2-City.mmdb.gz
    cp -f GeoLite2-City.mmdb /usr/share/geoip/GeoLite2-City.mmdb
    chmod 644 /usr/share/geoip/GeoLite2-City.mmdb
