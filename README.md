# README #

Это мой набор плагинов, отчетов, файлов конфигурации и модификации OSSIM.

### Истрория версий ###
* v.2.1.1

Добавлено решение, позволяющее сохранять поступающие на OSSIM логи в MongoDB (описание см. в директории logger-web). Для этого решения пока нет скрипта автоматической установки. Руки не доходят. Но делается просто. В описании всё есть.

В `jailbreak-ossim-for-rus.sh` внесено небольшое изменение. Вписана установка кодировки utf-8 для стандартного плагина fortigate. Это позволяет правильно читать лог с русскими буковками, например, русскими именами файлов в логе DLP. 

* v.2.1.0

Большая переделка `jailbreak-ossim-for-esguardian-plugins.sh` и всего джаилбрейка. Каталог `/etc/my_ossim` переименован в `/etc/esguard_ossim`. Соответственно изменены пути в некоторых отчетах и плагинах. 

Добавлена предварительная версия плагина для Zecurion Zgate.

Добавлена предварительная версия плагина oramon. Это монитор журналов аудита Oracle, сиотреть здесь репозитарий [oramon](https://bitbucket.org/esguardian/oramon)


**Важно**. Если применялся джайлбрейк более ранних версий, то необходимо вручную исправить файл `/usr/share/alienvault/ossim-agent/ParserUtil.py` удалив из него всё содержимое после строки `# my ParserUtil tail`. Кроме того необходимо предварительно уничтожить файл `/usr/local/bin/jailbreak/check_esguardian_config.py`. После чего заново выполнить `jailbreak-ossim-for-esguardian-plugins.sh`.

* v.2.0.1

Кодировки во всех скриптах изменены на utf8 для однообразия. Сохранение файлов отчетов для Excel осталось в cp1251.

* v.2.0.0  

Полностью переделана русификация OSSIM. Теперь это делается одним скриптом из 
дирекотрии /usr/local/bin/jailbreak.   
Этот скрипт применим как для OSSIM, так и для USM.  
Если кто-то собирается использовать мой плагин для MS TMG, то учтите, что он предназначен только для OSSIM на USM эта версия плагина работать не будет. Перед использованием плагина необходимо сделать другой jailbreak. Во-первых, необходимо скопировать все файлы из этого репозитария в соответствующие директории на сервере OSSIM. Во-вторых, необходимо выполнить скрипт /usr/local/bin/jailbreak/jailbreak-ossim-for-esguardian-plugins.sh
  
Документ с описанием русификации оставлен для справки. Однако теперь ничего править руками не надо.

Отчеты остались без изменений.  
Версия отчетов v.1.0.3.

* v.1.0.3

Многое поменял с момента первой публикации. 
В отчеты IDS и OTX вставил данные геолокации. 
Навел порядок с кодировками символов. 
Убрал в отдельный модуль "helper" функцию запроса данных геолокации. С базой geoip2 работать надо осторожно.
вызов методов объекта reader может привести к фатальной ошибке, например, если случайно попадется локальный адрес ip.
Кроме того в базе могут оказаться данные в не пойми какой кодировке, типа, на языке оригинала.
Текущая версия отчетов 1.0.3
Описание отчетов и русификации смотрите в директории /doc.
