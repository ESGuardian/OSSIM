#
# License:
#
# Copyright (c) 2003-2006 ossim.net
# Copyright (c) 2007-2014 AlienVault
#    All rights reserved.
#
#    This package is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; version 2 dated June, 1991.
#    You may not use, modify or distribute this program under any other version
#    of the GNU General Public License.
#
#    This package is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this package; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
#    MA  02110-1301  USA
#
#
# On Debian GNU/Linux systems, the complete text of the GNU General
# Public License can be found in `/usr/share/common-licenses/GPL-2'.
#
# Otherwise you can read it here: http://www.gnu.org/licenses/gpl-2.0.txt
#

#
# GLOBAL IMPORTS
#
import os
import re
import string
import sys
import uuid
import time
import MySQLdb
from pymongo import MongoClient
# from bson import BSON
# from bson.binary import Binary

#
# LOCAL IMPORTS
#
from Config import Conf, CommandLineOptions
from Event import Event
from Exceptions import AgentCritical
from Logger import Logger

#
# GLOBAL VARIABLES
#
logger = Logger.logger


class OutputPlugins:
    def _open_file(self, file):
        dir = file.rstrip(os.path.basename(file))

        if not os.path.isdir(dir):
            try:
                os.makedirs(dir, 0755)

            except OSError, e:
                raise AgentCritical("Error creating directory (%s): %s" % \
                                    (dir, e))

        try:
            fd = open(file, 'a')

        except IOError, e:
            raise AgentCritical("Error opening file (%s): %s" % (file, e))

        return fd

    #
    # the following methods must be overriden in child classes
    #
    def event(self, e):
        pass


    def shutdown(self):
        pass


    def plugin_state(self, msg):
        pass


class OutputPlain(OutputPlugins):
    def __init__(self, conf):
        self.conf = conf
        logger.info("Added Plain output")
        logger.debug("OutputPlain options: %s" % \
                     (self.conf.hitems("output-plain")))
        self.plain = self._open_file(self.conf.get("output-plain", "file"))
        self.activated = True


    def event(self, e):
        if self.activated:
            self.plain.write(str(e))
            self.plain.flush()


    def plugin_state(self, msg):
        if self.activated:
            self.plain.write(msg)
            self.plain.flush()


    def shutdown(self):
        logger.info("Closing Plain file..")
        self.plain.flush()
        self.plain.close()
        self.activated = False


class OutputServer(OutputPlugins):
    def __init__(self, conn):
        logger.info("Added Server output (%s:%s)" % (conn.ip,
                                                     conn.port))
        self.conn = conn
        self.activated = True
        self.send_events = False
        self.conf = Conf()
        self.options = CommandLineOptions().get_options()

        if self.options.config_file:
            conffile = self.options.config_file

        else:
            conffile = self.conf.DEFAULT_CONFIG_FILE

        self.conf.read([conffile], 'latin1')

        if self.conf.has_section("output-server"):
            if self.conf.getboolean("output-server", "send_events"):
                self.send_events = True


    def event(self, e):
        if self.activated and self.send_events:
            try:
                if self.conn.get_alive():
                    self.conn.send(e)

            except:
                return


    def plugin_state(self, msg):
        if self.activated:
            try:
                self.conn.send(msg)

            except:
                return


    def shutdown(self):
        self.conn.close()
        self.activated = False


class OutputCSV(OutputPlugins):
    def __init__(self, conf):

        self.conf = conf
        logger.info("Added CSV output")
        logger.debug("OutputCSV options: %s" % (self.conf.hitems("output-csv")))

        file = self.conf.get("output-csv", "file")
        first_creation = not os.path.isfile(file)
        self.csv = self._open_file(file)
        if first_creation:
            self.__write_csv_header()
        self.activated = True


    def __write_csv_header(self):

        header = ''

        for attr in Event.EVENT_ATTRS:
            header += "%s," % (attr)
        self.csv.write(header.rstrip(",") + "\n")
        self.csv.flush()


    def __write_csv_event(self, e):

        event = ''

        for attr in e.EVENT_ATTRS:
            if e[attr] is not None:
                event += "%s," % (string.replace(e[attr], ',', ' '))

            else:
                event += ","

        self.csv.write(event.rstrip(',') + "\n")
        self.csv.flush()


    def event(self, e):

        if self.activated:
            if e["event_type"] == "event":
                self.__write_csv_event(e)


    def shutdown(self):
        logger.info("Closing CSV file..")
        self.csv.flush()
        self.csv.close()
        self.activated = False


class OutputDB(OutputPlugins):
    from Database import DatabaseConn

    def __init__(self, conf):
        logger.info("Added Database output")
        logger.debug("OutputDB options: %s" % (conf.hitems("output-db")))

        self.conf = conf

        type = self.conf.get('output-db', 'type')
        host = self.conf.get('output-db', 'host')
        base = self.conf.get('output-db', 'base')
        user = self.conf.get('output-db', 'user')
        password = self.conf.get('output-db', 'pass')

        self.conn = OutputDB.DatabaseConn()
        self.conn.connect(type, host, base, user, password)
        self.activated = True


    def event(self, e):
        if self.conn is not None and e["event_type"] == "event" \
                and self.activated:

            # build query
            query = 'INSERT INTO event ('

            for attr in e.EVENT_ATTRS:
                query += "%s," % (attr)

            query = query.rstrip(',')
            query += ") VALUES ("

            for attr in e.EVENT_ATTRS:
                value = ''

                if e[attr] is not None:
                    value = e[attr]

                query += "'%s'," % (value)

            query = query.rstrip(',')
            query += ");"

            logger.debug(query)

            try:
                self.conn.exec_query(query)

            except Exception, e:
                logger.error(": Error executing query (%s)" % (e))


    def shutdown(self):
        logger.info("Closing database connection..")
        self.conn.close()
        self.activated = False

class OutputESGuard(OutputPlugins):
           
    def __init__(self, conf):
        
        logger.info("Added ESGuard output")
        logger.debug("OutputDB options: %s" % (conf.hitems("output-esguard")))

        self.conf = conf
        self.dbhost = self.conf.get('output-esguard', 'host')
        self.dbport = self.conf.get('output-esguard', 'port')
        self.dbschema = self.conf.get('output-esguard', 'base')
        self.dbuser = self.conf.get('output-esguard', 'user')
        self.dbpass = self.conf.get('output-esguard', 'pass')
        
        with open('/etc/ossim/ossim_setup.conf','r') as server_conf:
            lines = server_conf.readlines()
            for line in lines:
                (name,value)=('','')
                if '=' in line:
                    (name,value) = line.strip().split('=',1)
                if name == 'db_ip':
                    server_dbhost = value
                if name == 'pass':
                    server_dbpass = value
                if name == 'user':
                    server_dbuser = value
        server_conf.close()
        
        self.plugins_db = {}
        
        server_conn = MySQLdb.connect(host=server_dbhost, user=server_dbuser, passwd=server_dbpass, db='alienvault', charset='utf8') 
        server_cursor = server_conn.cursor()
        server_cursor.execute("select id, name from plugin")
        plugs = []
        row = server_cursor.fetchone() 
        while row :
            plugs.append((int(row[0]),str(row[1])))
            row = server_cursor.fetchone() 
        for (plug_id, plug_name) in plugs : 
            signatures = {}
            server_cursor.execute("select sid, name from plugin_sid where plugin_id = %s",(plug_id,))
            row = server_cursor.fetchone() 
            while row :
                signatures[int(row[0])] = unicode(row[1])
                row = server_cursor.fetchone() 
            self.plugins_db[plug_id] = (plug_name,signatures)
        server_conn.close()

        

        mongodbURI = "mongodb://" + self.dbuser + ":" + self.dbpass + "@" + self.dbhost + ":" + self.dbport + "/" + self.dbschema
        try :
            self.conn = MongoClient(mongodbURI)
            self.log_db = self.conn[self.dbschema]
            self.activated = True
        except Exception, e:
            logger.error(": Error connecting to Mongodb %s" % (e))

        
    def event(self, e):          
        
        if self.conn is not None and e["event_type"] == "event" \
                and self.activated:  
            # do not log "syslog message too large" from OSSEC
            if e['plugin_id'] == '7017' and e['plugin_sid'] == '1003' :
                return
                
            (plug_name,plug_sig) = self.plugins_db[int(e['plugin_id'])]
            plug_name = "" if plug_name is None else plug_name
            
            
            if plug_sig is None:
                sig_name = ""
            else :
                sig_name = plug_sig[int(e['plugin_sid'])]
                sig_name = "" if sig_name is None else sig_name         
            
            collection = "logger." + time.strftime("%Y%m%d",time.gmtime())
            try :
                self.log_db[collection].insert_one(e.to_esguard(plug_name,sig_name))
            except Exception, e:                 
                logger.error(": Error insert data to mongodb log collection.  %s" % (e))  
                    
      

    def shutdown(self):
        logger.info("Closing ESGuard output ..")
        self.conn.close()
        self.activated = False
        
    


class OutputIDM(OutputPlugins):
    def __init__(self, conn):
        logger.info("Added IDM output")
        self.conn = conn
        self.activated = True

    def event(self, e):
        if self.activated:
            try:
                if self.conn.get_alive():
                    self.conn.send(e)
            except:
                pass

    def shutdown(self):
        logger.info("Closing IDM connection");
        self.conn.close()
        self.activated = False


class Output:
    """Different ways to log ossim events (Event objects)."""

    _outputs = []
    _IDMoutputs = []
    plain_output = server_output = server_output_pro = csv_output = db_output = idm_output = esguard_output = False
    _printEvents = True

    @staticmethod
    def print_ouput_events(value):
        logger.debug("Setting printEvents to %s" % value)
        Output._printEvents = value


    @staticmethod
    def add_plain_output(conf):
        if Output.plain_output is False:
            Output._outputs.append(OutputPlain(conf))
            Output._IDMoutputs.append(OutputPlain(conf))
            Output.plain_output = True

    @staticmethod
    def add_server_output(conn):
        if Output.server_output is False:
            Output._outputs.append(OutputServer(conn))
            Output.server_output = True

    @staticmethod
    def add_csv_output(conf):
        if Output.csv_output is False:
            Output._outputs.append(OutputCSV(conf))
            Output.csv_output = True


    @staticmethod
    def add_db_output(conf):
        if Output.db_output is False:
            Output._outputs.append(OutputDB(conf))
            Output.db_output = True
    
    @staticmethod
    def add_esguard_output(conf):
        if Output.esguard_output is False:
            Output._outputs.append(OutputESGuard(conf))
            Output.esguard_output = True

    @staticmethod
    def add_idm_output(conn):
        if Output.idm_output is False:
            Output._IDMoutputs.append(OutputIDM(conn))
            Output.idm_output = True

    @staticmethod
    def event(e):
        output_list = Output._outputs
        if e.is_idm_event():
            output_list = Output._IDMoutputs
        if Output._printEvents:
            logger.info(str(e).rstrip())
        for output in output_list:
            output.event(e)

    @staticmethod
    def plugin_state(msg):
        for output in Output._outputs:
            output.plugin_state(msg)


    @staticmethod
    def shutdown():
        for output in Output._outputs:
            output.shutdown()



if __name__ == "__main__":
    event = Event()
    Output.add_server_output()
    Output.event(event)
    Output.add_csv_output()
    Output.event(event)
    

# vim:ts=4 sts=4 tw=79 expandtab:

