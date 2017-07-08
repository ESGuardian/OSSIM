# В USM 5.4 есть ошибка из-за которой для файлов в кодировке utf8
# не верно обрабатывается bookmark это вызавает краш плагина.
# В результате, при рестарте агента ossim, плагины типа "ParserLog" 
# не запускаются, если они работают с логами в кодировке utf8.
# Пока самый простой, известный мне способ обойти этот баг, сотоит в том,
# чтобы создать новый лог-файл. Для этого нужно изменить файлы конфигурации
# плагина и сервиса rsyslog и рестартовать rsyslog перед запуском агента 
# ossim.
#
# Приведенный здесь код делает это для плагина kasper_rus. Этот код следует
# дописать в хвост файла check_encoding.py, который появится после выполнения
# скрипта jailbreak-ossim-for-rus.sh
#
# Всё так сложно, потому что имя лог-файла должно быть уникальным.
#
# Это касается только коммерческой версии USM в OpenSource версии OSSIM этого
# бага нет, там вообще bookmark делается иначе, поэтому я не включаю этот код 
# в стандартный jailbreak.
# 
# Больше информации на https://esguardian.ru
#
import datetime
kasper_path = '/etc/ossim/agent/plugins/kasper_rus.cfg'
rsyslog_conf_path ='/etc/rsyslog.d/kasper.conf'
new_kasper_log = 'kasper-' + datetime.datetime.now().strftime("%Y-%m-%d.%H.%M.%S") + '.log'
cmd = "sed -i 's:location=/var/log/kasper.*:location=/var/log/" + new_kasper_log + ":' " + kasper_path
p = subprocess.Popen (cmd, shell=True)
p_stutus = p.wait()
cmd = "sed -i 's:-/var/log/kasper.*:-/var/log/" + new_kasper_log + ";kaspertpl:' " + rsyslog_conf_path
p = subprocess.Popen (cmd, shell=True)
p_stutus = p.wait()
cmd = 'service rsyslog stop'
p = subprocess.Popen (cmd, shell=True)
p_stutus = p.wait()
cmd = 'service rsyslog start'
p = subprocess.Popen (cmd, shell=True)
p_stutus = p.wait()
