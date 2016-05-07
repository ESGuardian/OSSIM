## Плагины ##

Я написал несколько собственных плагинов. Для работы некоторых плагинов нужны отдельные, написанные мной программки, которые поставляют для них данные. Какие именно - указано ниже по тексту в описаниях плагинов. 

### Плагин NFOTX. ###

Это небольшая переделка плагина предложенного Packetinspektor   

        Название:       NFOTX
        Функционал:     Ищет в потоке Netflow записи о коммуникации 
                        внутренних хостов с внешними и проверяет 
                        наличие внешних адресов в двух списках 
                        reputation.data (обновляемый список от Open Threat Exchange) и 
                        my_reputation.data (собственный файл)
    
        PluginID        90011
        PlaginCFG       nfotx.cfg
        DataSourceName  NfOTX
        Signature       Netflow OTX Match
     
        Размещение файлов:
            Программа необходимая для работы
                /usr/local/bin/nfotx.py
            Конф для rsyslog
                /etc/rsyslog.d/nfotx.conf
            собственно лог
                /var/log/nfotx.log
            Файл конфигурации ротации логов
                /etc/logrotate.d/my_ossim-devices
            Файл с собственным списком плохих адресов
                /etc/esguard_ossim/my_reputation.data
            Скрипт конфигурации mySQL для плагина
                /etc/esguard_ossim/nfotx.sql
            Собственно плагин
                /etc/ossim/agent/plugins/nfotx.cfg
            my_reputation.data
                /etc/esguard_ossim/my_reputation.data
 
Для просмотра событий на консоли использовать фильтр по DS Group “NFOTX”.


### Плагин myILO ###

        Название:       myILO
        Функционал:     Парсит логи iLO, поступающие на OSSIM, 
                        и выделяет события типа logon/logout.
                        
        PluginID        90012
        PlaginCFG       myILO.cfg
        DataSourceName  myILO
        Signature 
            iLO access IPMI         sid: 1
            iLO access Browser      sid: 2
            iLO logout              sid: 3
            iLO access FAILURE      sid: 4
            
        Размещение файлов:
            Программа необходимая для работы
                нет
            Конф для rsyslog
                /etc/rsyslog.d/ilo.conf
            собственно лог
                /var/log/ilo-access.log
            Файл конфигурации ротации логов
                /etc/logrotate.d/my_ossim-devices
            Скрипт конфигурации mySQL для плагина
                /etc/esguard_ossim/myILO.sql
            Собственно плагин
                /etc/ossim/agent/plugins/myILO.cfg
         
Для просмотра событий на консоли использовать фильтр по Data Source “myILO”.
 
### Плагин MSFEP ###

        Название:       msfep
        Функционал:     логирует  события вирусных заражений регистрируемых 
                        System Center Endpoint Protection.
        
        PluginID        9003
        PlaginCFG       msfep.cfg
        DataSourceName  msfep
        Signature 
            MSFEP Malware           sid: 1
            
        Размещение файлов:
            Программа необходимая для работы
                нет
            Конф для rsyslog
                нет
            собственно лог
                нет (источник БД MSSQL)
            Файл конфигурации ротации логов
                нет
            Скрипт конфигурации mySQL для плагина
                /etc/esguard_ossim/msfep.sql
            Собственно плагин
                /etc/ossim/agent/plugins/msfep.cfg
                
Для просмотра событий на консоли использовать фильтр по Data Source “msfep”. 

Для работы плагина внесены изменения в базу данных System Center Configuration Manager. Cоздана вьюха:

        create view dbo.MalwareView as select
         n.Type
         , n.RowID
         , n.Name
         , n.Description
         , n.Timestamp
         , n.SchemaVersion
         , n.ObserverHost
         , n.ObserverUser
         , n.ObserverProductName
         , n.ObserverProductversion
         , n.ObserverProtectionType
         , n.ObserverProtectionVersion
         , n.ObserverProtectionSignatureVersion
         , n.ObserverDetection
         , n.ObserverDetectionTime
         , n.ActorHost
         , n.ActorUser
         , n.ActorProcess
         , n.ActorResource
         , n.ActionType
         , n.TargetHost
         , n.TargetUser
         , n.TargetProcess
         , n.TargetResource
         , n.ClassificationID
         , n.ClassificationType
         , n.ClassificationSeverity
         , n.ClassificationCategory
         , n.RemediationType
         , n.RemediationResult
         , n.RemediationErrorCode
         , n.RemediationPendingAction
         , n.IsActiveMalware
         , i.IP_Addresses0 as 'SrcAddress' from v_AM_NormalizedDetectionHistory n
         , System_IP_Address_ARR i
         , v_RA_System_ResourceNames s
         , Network_DATA d
         where n.ObserverHost = s.Resource_Names0
         and s.ResourceID = d.MachineID
         and d.IPEnabled00 = 1
         and d.MachineID = i.ItemKey
         and i.IP_Addresses0 like '%.%.%.%';

Добавлен пользователь username с правами чтения этой вьюхи (метод аутентификации SQL native)


### Плагины для сбора логов TMG ###

Для работы этих плагинов на TMG установлен агент SNARE Epilog и настроен на отправку на ossim логов веб-прокси и файрвол-сервиса.

**Важно**. необходим `jailbreak-ossim-for-esguardian-plugins.sh` (смотрите `jailbreak_for_esguardian_plugins.md`)

        Название:       tmg-web
        Функционал:     Обрабатывает данные поступающие в syslog 
                        от агента SNARE Epilog, размещенного на сервере PRX. 
                        Читает и парсит ISAWEBLog в формате w3c. 
                        Отдельно отслеживает такие события, 
                        как подключение устройств по протоколу ActiveSync, 
                        передача данных на нежелательные URL (собственный список), 
                        передача данных в большем объеме, чем прием, 
                        передача "больших" объемов данных наружу одним махом (1 МБ и более).
                        
        PluginID        9004
        PlaginCFG       tmg-web.cfg
        DataSourceName  tmg-web
        
        Размещение файлов:
            Программа необходимая для работы
                нет
            Конф для rsyslog
                /etc/rsyslog.d/tmg.conf
            собственно лог
                /var/log/tmg-web.log
            Файл конфигурации ротации логов
                /etc/logrotate.d/my_ossim-devices
            Скрипт конфигурации mySQL для плагина
                /etc/esguard_ossim/tmg-web.sql
            Собственно плагин
                /etc/ossim/agent/plugins/tmg-web.cfg
            Файл со списком специально отслеживаемых URL
                /etc/esguard_ossim/monitored_urls.list
            Файл со списком специально не отслеживаемых URL
                /etc/esguard_ossim/unmonitored_urls.list

**Важно:** данные плагина `tmg-web` использует также плагин `activesync-monitor`.  

         
        Название:       tmg-fws
        Функционал:     Обрабатывает данные поступающие в syslog от агента SNARE Epilog, 
                        размещенного на сервере PRX. Читает и парсит ISAFWSLog в формате w3c. 
                        
        PluginID        9005
        PlaginCFG       tmg-fws.cfg
        DataSourceName  tmg-fws
        
        Размещение файлов:
            Программа необходимая для работы
                нет
            Конф для rsyslog
                /etc/rsyslog.d/tmg.conf
            собственно лог
                /var/log/tmg-fws.log
            Файл конфигурации ротации логов
                /etc/logrotate.d/my_ossim-devices
            Скрипт конфигурации mySQL для плагина
                /etc/esguard_ossim/tmg-fws.sql
            Собственно плагин
                /etc/ossim/agent/plugins/tmg-fws.cfg

### Плагин для отслеживания логонов пользователей и процессов. ###

        Название:       user-logon-monitor.
        Функционал:     Отслеживает события регистрации пользователей 
                        Windows (в домене и локально), 
                        Unix и Cisco AnyConnect. 
                        
        Различаются следующие события:
        
            Первая регистрация за текущие сутки и не более 4-х суток с момента последней регистрации;            
            От 5 до 20 суток с момента последней регистрации;            
            Более 20 суток с момента последней регистрации;            
            Первая регистрация за всю историю наблюдений.
                        
        Использует данные плагинов ossec и cisco-asa.
        Создает два рабочих файла, которые полезны сами по себе:
        /var/cache/logon-monitor/logon-history.list - файл с данными последней регистрации (юзер, время, ip хоста)
        /var/cache/logon-monitor/logon-[date].list - файл с данными первой регистрации за дату.
        
        PluginID        9006
        PlaginCFG       user-logon-monitor.cfg
        DataSourceName  user-logon-monitor

        Размещение файлов:
            Программа необходимая для работы
                /usr/local/bin/user-logon-monitor.py
            Конф для rsyslog
                не использует сислог
            собственно лог
                /var/log/user-logon-monitor.log
            Файл конфигурации ротации логов
                /etc/logrotate.d/esguard_ossim-devices
            Скрипт конфигурации mySQL для плагина
                /etc/esguard_ossim/user-logon-monitor.sql
            Собственно плагин
                /etc/ossim/agent/plugins/user-logon-monitor.cfg

### Плагин для отслеживания соединений ActiveSync. ###

**Важно:** использует данные плагина `tmg-web`.

        Название:       activesync-monitor
        Функционал:     Отслеживает получение команды Sync 
                        опубликованным на TMG сервисом Exchange. 
                        Регистрирует пользователя, 
                        тип и идентификатор устройства, 
                        ip адрес соединения.
                        
        Различаются следующие события:
            Первая регистрация данного юзера с данным устройством за текущие сутки 
            и не более 4-х суток с момента последней регистрации;
            От 5 до 20 суток с момента последней регистрации;
            Более 20 суток с момента последней регистрации;
            Первая регистрация за всю историю наблюдений.
            Смена ip адреса подключения (в текущих сутках).
            
        Использует данные плагина tmg-web.
        Создает два рабочих файла, которые полезны сами по себе:
        /var/cache/logon-monitor/as-access-history.list - файл с данными последней регистрации (юзер, девайс, время, ip девайса)
        /var/cache/logon-monitor/as-access-[date].list - файл с данными первой регистрации за дату.

        PluginID        9007
        PlaginCFG       activesync-monitor.cfg
        DataSourceName  activesync-monitor
        
        Размещение файлов:
            Программа необходимая для работы
                /usr/local/bin/activesync-monitor.py
            Конф для rsyslog
                не использует сислог
            собственно лог
                /var/log/activesync-monitor.log
            Файл конфигурации ротации логов
                /etc/logrotate.d/esguard_ossim-devices
            Скрипт конфигурации mySQL для плагина
                /etc/esguard_ossim/activesync-monitor.sql
            Собственно плагин
                /etc/ossim/agent/plugins/activesync-monitor.cfg

### Плагин Zgate ###

**Важно**. необходим `jailbreak-ossim-for-esguardian-plugins.sh` (смотрите `jailbreak_for_esguardian_plugins.md`)

        Название:       zgate
        Функционал:     логирует  события Zecurion Zgate.
        
        PluginID        9008
        PlaginCFG       zgate.cfg
        DataSourceName  zgate
        Signature 
            Загружен файл           sid: 1
			Отправлено письмо		sid: 2
			Получено сообщение 		sid: 3
			Отправлено сообщение 	sid: 4
			Исходящая почта 		sid: 5
			Изменен статус 			sid: 6
			Входящая почта 			sid: 7
			Новое событие			sid: 9999
            
        Размещение файлов:
            Программа необходимая для работы
                нет
            Конф для rsyslog
                нет
            собственно лог
                нет (источник БД MSSQL)
            Файл конфигурации ротации логов
                нет
            Скрипт конфигурации mySQL для плагина
                /etc/esguard_ossim/zgate.sql
            Собственно плагин
                /etc/ossim/agent/plugins/zgate.cfg
			Таблица сигнатур
				/etc/esguard_ossim/zgate_translation.table
                

Для работы плагина внесены изменения в базу данных zgate. Cоздана вьюха:

        CREATE VIEW ossim AS
		SELECT [zgate].[dbo].[ZMAIL_Message].[MessageID]
		      ,[DateTime]
		      ,[Subject]
		      ,[TypeSubject]
		      ,[RCPT]
		      ,[MAIL_FROM]
		      ,[FullAttFileList]
		      ,[DestFullName]
		      ,[ServiceName]
		      ,[InCarantine]
		      ,[zgate].[dbo].[ZMAIL_Categories].[CatName]
		  FROM [zgate].[dbo].[ZMAIL_Message] LEFT OUTER JOIN [zgate].[dbo].[ZMAIL_Message_Categories] ON [zgate].[dbo].[ZMAIL_Message].[MessageID]=[zgate].[dbo].[ZMAIL_Message_Categories].[MessageID] 
		  LEFT OUTER JOIN [zgate].[dbo].[ZMAIL_Categories] ON [zgate].[dbo].[ZMAIL_Message_Categories].[CatID]=[zgate].[dbo].[ZMAIL_Categories].[CatID]

Добавлен пользователь username с правами чтения этой вьюхи (метод аутентификации SQL native)

### Плагин oramon ###



        Название:       oraMON
        Функционал:     логирует  события Zecurion Zgate.
        
        PluginID        9009
        PlaginCFG       oramon.cfg
        DataSourceName  oramon
        Signature 
            Новый OS_USER                                   sid: 1
			Новое место подключения		                    sid: 2
			Новый ORACLE_USER     		                    sid: 3
			С возвращением!           	                    sid: 4
			Давно не виделись.   		                    sid: 5
			Прыг-скок        			                    sid: 6
			Четыре руки!     			                    sid: 7
            Много неудачных соединений                      sid: 8
            Этим логином Oracle давно не пользовались.      sid: 9
            Использован новый ORACLE_USER                   sid: 10
            Новая роль ORACLE                               sid: 11
            Использована новая роль ORACLE                  sid: 13
            Этой ролью ORACLE давно не пользовались         sid: 14
            Кое-кто давно не использовал эту роль ORACLE    sid: 15
            Ошибка при подключении к БД                     sid: 16
            Ошибка при назначении роли                      sid: 17
            Много ошибок                                    sid: 18
            Очень много ошибок!                             sid: 19
			Новое событие			                        sid: 9999
            
        Размещение файлов:
            Программа необходимая для работы
                нет
            Конф для rsyslog
                нет
            собственно лог
                нет (источник БД MySQL)
            Файл конфигурации ротации логов
                нет
            Скрипт конфигурации mySQL для плагина
                /etc/esguard_ossim/oramon.sql
            Собственно плагин
                /etc/ossim/agent/plugins/oramon.cfg
			
                

Для работы плагина необходим мой монитор журналов аудита Oracle. Смотреть здесь репозитарий [oramon](https://bitbucket.org/esguardian/oramon)

## Отчеты ##

Отчеты генерируются автоматически в 9:05 каждого рабочего дня и включают в себя данные с 9:00 предыдущего дня до 9:00 сегодня. А в понедельник с 9:00 прошедшей пятницы. Для чего в crontab вписано выполнение скрипта `/usr/local/bin/reports.sh`

Сами генераторы написаны на питоне:
**accrep.py** - отчет об изменении учетных записей (добавление/удаление в группах, блокировка/разблокировка и т.п.)  
**apprep.py** - отчет об установке/удалении программ, изменении контрольных сумм отслеживаемых файлов конфигурации.   
**idsrep.py** - отчет о событиях IDS Suricata, пополненный данными Netflow по каждому "атакующему" хосту.   
**nfotxrep.py** - отчет о выявлении коммуникаций с хостами, содержащимися в базе Open Threat Exchange, с данными Netflow по каждому хосту.   
**rarep.py** - отчет о подключениях удаленного доступа, как Cisco AnyConnect, так и ActiveSync.   
**tmgrep.py** - отчет о событиях отправки большого объема данных из внутренней сети на внешние адреса (DLP).  
**orarep.py** - отчет о событиях монитора журналов аудита Oracle. 

**Важно**. Для отчетов необходим `jailbreak-ossim-for-esguardian-plugins.sh` (смотрите `jailbreak_for_esguardian_plugins.md`)


