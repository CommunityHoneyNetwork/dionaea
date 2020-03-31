# ********************************************************************************
# *                               Dionaea
# *                           - catches bugs -
# *
# *
# *
# * Copyright (C) 2010  Mark Schloesser
# *
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
# *
# *
# *             contact nepenthesdev@gmail.com
# *
# *******************************************************************************/

from dionaea import IHandlerLoader
from dionaea.core import ihandler, incident, g_dionaea, connection
from dionaea.util import sha512file

import logging
import json
import datetime
from time import gmtime, strftime

try:
    from dionaea import pyev
except ImportError:
    pyev = None

import hpfeeds

logger = logging.getLogger('hpfeeds')
logger.setLevel(logging.DEBUG)

CONNCHAN = 'dionaea.connections'
CAPTURECHAN = 'dionaea.capture'
DCECHAN = 'dionaea.dcerpcrequests'
SCPROFCHAN = 'dionaea.shellcodeprofiles'
UNIQUECHAN = 'mwbinary.dionaea.sensorunique'


class HPFeedsHandlerLoader(IHandlerLoader):
    name = "hpfeeds"

    @classmethod
    def start(cls, config=None):
        handler = hpfeedihandler("*", config=config)
        return [handler]


def timestr():
    dt = datetime.datetime.now()
    my_time = dt.strftime("%Y-%m-%d %H:%M:%S.%f")
    timezone = strftime("%Z %z", gmtime())
    return my_time + " " + timezone


class hpfeedihandler(ihandler):
    default_reconnect_timeout = 10.0
    default_port = 10000

    def __init__(self, path, config=None):
        logger.debug('hpfeedhandler init')
        reconnect_timeout = config.get("reconnect_timeout")
        if reconnect_timeout is None:
            reconnect_timeout = self.default_reconnect_timeout
        try:
            reconnect_timeout = float(reconnect_timeout)
        except (TypeError, ValueError):
            logger.warning("Unable to convert value '%s' for reconnect timeout to float" % reconnect_timeout)
            reconnect_timeout = self.default_reconnect_timeout

        port = config.get("port")
        if port is None:
            port = self.default_port
        try:
            port = int(port)
        except (TypeError, ValueError):
            logger.warning("Unable to convert value '%s' for port to int" % port)
            port = self.default_port

        self.client = hpfeeds.client.new(
            config['server'],
            port,
            config['ident'],
            config['secret']
        )
        ihandler.__init__(self, path)

        self.tags = config['tags']
        logger.debug('Set tags to: {}'.format(self.tags))
        self.dynip_resolve = config.get('dynip_resolve', '')
        self.dynip_timer = None
        self.ownip = None
        if isinstance(self.dynip_resolve, str) and self.dynip_resolve.startswith("http"):
            if pyev is None:
                logger.debug('You are missing the python pyev binding in your dionaea installation.')
            else:
                logger.debug('hpfeedihandler will use dynamic IP resolving!')
                self.loop = pyev.default_loop()
                self.dynip_timer = pyev.Timer(2., 300, self.loop, self._dynip_resolve)
                self.dynip_timer.start()

    def stop(self):
        if self.dynip_timer:
            self.dynip_timer.stop()
            self.dynip_timer = None
            self.loop = None

    def _ownip(self, icd):
        if self.dynip_resolve and 'http' in self.dynip_resolve and pyev is not None:
            if self.ownip:
                return self.ownip
            else:
                raise Exception('Own IP not yet resolved!')
        return icd.con.local.host

    def __del__(self):
        # self.client.close()
        pass

    def connection_publish(self, icd, con_type):
        try:
            con = icd.con
            meta = {"tags": self.tags,
                    "connection_type": con_type,
                    "connection_transport": con.transport,
                    "connection_protocol": con.protocol,
                    "remote_host": con.remote.host,
                    "remote_port": con.remote.port,
                    "remote_hostname": con.remote.hostname,
                    "local_host": self._ownip(icd),
                    "local_port": con.local.port}
            self.client.publish(
                CONNCHAN,
                json.dumps(meta).encode('utf-8')
            )
        except Exception as e:
            logger.warning('exception when publishing: {0}'.format(e))

    def handle_incident(self, i):
        pass

    def handle_incident_dionaea_connection_tcp_listen(self, icd):
        self.connection_publish(icd, 'listen')
        con = icd.con
        logger.info("listen connection on %s:%i" %
                    (con.remote.host, con.remote.port))

    def handle_incident_dionaea_connection_tls_listen(self, icd):
        self.connection_publish(icd, 'listen')
        con = icd.con
        logger.info("listen connection on %s:%i" %
                    (con.remote.host, con.remote.port))

    def handle_incident_dionaea_connection_tcp_connect(self, icd):
        self.connection_publish(icd, 'connect')
        con = icd.con
        logger.info("connect connection to %s/%s:%i from %s:%i" %
                    (con.remote.host, con.remote.hostname, con.remote.port, self._ownip(icd), con.local.port))

    def handle_incident_dionaea_connection_tls_connect(self, icd):
        self.connection_publish(icd, 'connect')
        con = icd.con
        logger.info("connect connection to %s/%s:%i from %s:%i" %
                    (con.remote.host, con.remote.hostname, con.remote.port, self._ownip(icd), con.local.port))

    def handle_incident_dionaea_connection_udp_connect(self, icd):
        self.connection_publish(icd, 'connect')
        con = icd.con
        logger.info("connect connection to %s/%s:%i from %s:%i" %
                    (con.remote.host, con.remote.hostname, con.remote.port, self._ownip(icd), con.local.port))

    def handle_incident_dionaea_connection_tcp_accept(self, icd):
        self.connection_publish(icd, 'accept')
        con = icd.con
        logger.info("accepted connection from  %s:%i to %s:%i" %
                    (con.remote.host, con.remote.port, self._ownip(icd), con.local.port))

    def handle_incident_dionaea_connection_tls_accept(self, icd):
        self.connection_publish(icd, 'accept')
        con = icd.con
        logger.info("accepted connection from %s:%i to %s:%i" %
                    (con.remote.host, con.remote.port, self._ownip(icd), con.local.port))

    def handle_incident_dionaea_connection_tcp_reject(self, icd):
        self.connection_publish(icd, 'reject')
        con = icd.con
        logger.info("reject connection from %s:%i to %s:%i" %
                    (con.remote.host, con.remote.port, self._ownip(icd), con.local.port))

    def handle_incident_dionaea_connection_tcp_pending(self, icd):
        self.connection_publish(icd, 'pending')
        con = icd.con
        logger.info("pending connection from %s:%i to %s:%i" %
                    (con.remote.host, con.remote.port, self._ownip(icd), con.local.port))

    def handle_incident_dionaea_download_offer(self, icd):
        try:
            tstamp = timestr()
            meta = {"tags": self.tags,
                    "time": tstamp,
                    "saddr": icd.con.remote.host,
                    "sport": str(icd.con.remote.port),
                    "daddr": self._ownip(icd),
                    "dport": str(icd.con.local.port),
                    "url": icd.url}
            self.client.publish(
                CAPTURECHAN,
                json.dumps(meta).encode('utf-8')
            )
        except Exception as e:
            logger.warning('exception when publishing: {0}'.format(e))

    def handle_incident_dionaea_download_complete_hash(self, icd):
        try:
            tstamp = timestr()
            meta = {"tags": self.tags,
                    "time": tstamp,
                    "saddr": icd.con.remote.host,
                    "sport": str(icd.con.remote.port),
                    "daddr": self._ownip(icd),
                    "dport": str(icd.con.local.port),
                    "md5": icd.md5hash,
                    "url": icd.url,
                    "action": "download",
                    "status": "successful"}
            self.client.publish(
                CAPTURECHAN,
                json.dumps(meta).encode('utf-8')
            )
        except Exception as e:
            logger.warning('exception when publishing: {0}'.format(e))

    def handle_incident_dionaea_download_complete_unique(self, icd):
        self.handle_incident_dionaea_download_complete_again(icd)
        if not hasattr(id, 'con') or not self.client.connected:
            return
        logger.debug('unique complete, publishing md5 {0}, path {1}'.format(icd.md5hash, icd.file))
        try:
            self.client.sendfile(icd.file)
        except Exception as e:
            logger.warning('exception when publishing: {0}'.format(e))

    def handle_incident_dionaea_download_complete_again(self, icd):
        if not hasattr(icd, 'con') or not self.client.connected:
            return
        logger.debug('hash complete, publishing md5 {0}, path {1}'.format(icd.md5hash, icd.file))
        try:
            tstamp = timestr()
            sha512 = sha512file(icd.file)
            meta = {"tags": self.tags,
                    "time": tstamp,
                    "saddr": icd.con.remote.host,
                    "sport": str(icd.con.remote.port),
                    "daddr": self._ownip(icd),
                    "dport": str(icd.con.local.port),
                    "md5": icd.md5hash,
                    "sha512": sha512,
                    "url": icd.url}
            self.client.publish(
                CAPTURECHAN,
                json.dumps(meta).encode('utf-8')
            )
        except Exception as e:
            logger.warning('exception when publishing: {0}'.format(e))

    def handle_incident_dionaea_service_shell_listen(self, icd):
        try:
            tstamp = timestr()
            url = "bindshell://{}".format(str(icd.port))
            meta = {"tags": self.tags,
                    "time": tstamp,
                    "saddr": icd.con.remote.host,
                    "sport": str(icd.con.remote.port),
                    "daddr": self._ownip(icd),
                    "dport": str(icd.con.local.port),
                    "url": url}
            self.client.publish(
                CAPTURECHAN,
                json.dumps(meta).encode('utf-8')
            )
        except Exception as e:
            logger.warning('exception when publishing: {0}'.format(e))

    def handle_incident_dionaea_service_shell_connect(self, icd):
        try:
            tstamp = timestr()
            url = "connectbackshell://" + str(icd.host) + ":" + str(icd.port)
            meta = {"tags": self.tags,
                    "time": tstamp,
                    "saddr": icd.con.remote.host,
                    "sport": str(icd.con.remote.port),
                    "daddr": self._ownip(icd),
                    "dport": str(icd.con.local.port),
                    "url": url}
            self.client.publish(
                CAPTURECHAN,
                json.dumps(meta).encode('utf-8')
            )
        except Exception as e:
            logger.warning('exception when publishing: {0}'.format(e))

    def handle_incident_dionaea_modules_python_ftp_login(self, icd):
        try:
            tstamp = timestr()
            meta = {"tags": self.tags,
                    "time": tstamp,
                    "saddr": icd.con.remote.host,
                    "sport": str(icd.con.remote.port),
                    "daddr": self._ownip(icd),
                    "dport": str(icd.con.local.port),
                    "username": icd.username,
                    "password": icd.password}
            self.client.publish(
                CAPTURECHAN,
                json.dumps(meta).encode('utf-8')
            )
        except Exception as e:
            logger.warning('exception when publishing: {0}'.format(e))

    def handle_incident_dionaea_modules_python_smb_dcerpc_bind(self, icd):
        try:
            tstamp = timestr()
            meta = {"tags": self.tags,
                    "time": tstamp,
                    "saddr": icd.con.remote.host,
                    "sport": str(icd.con.remote.port),
                    "daddr": self._ownip(icd),
                    "dport": str(icd.con.local.port),
                    "smb_uuid": icd.uuid,
                    "smd_transfersyntax": icd.transfersyntax}
            self.client.publish(
                CAPTURECHAN,
                json.dumps(meta).encode('utf-8')
            )
        except Exception as e:
            logger.warning('exception when publishing: {0}'.format(e))

    def handle_incident_dionaea_modules_python_smb_dcerpc_request(self, icd):
        if not hasattr(icd, 'con') or not self.client.connected:
            return
        logger.debug('dcerpc request, publishing uuid {0}, opnum {1}'.format(icd.uuid, icd.opnum))
        try:
            meta = {"tags": self.tags,
                    "uuid": icd.uuid,
                    "opnum": icd.opnum,
                    "saddr": icd.con.remote.host,
                    "sport": str(icd.con.remote.port),
                    "daddr": self._ownip(icd),
                    "dport": str(icd.con.local.port)}
            self.client.publish(
                DCECHAN,
                json.dumps(meta).encode('utf-8')
            )
        except Exception as e:
            logger.warning('exception when publishing: {0}'.format(e))

    def handle_incident_dionaea_modules_python_mssql_login(self, icd):
        try:
            tstamp = timestr()
            meta = {"tags": self.tags,
                    "time": tstamp,
                    "saddr": icd.con.remote.host,
                    "sport": str(icd.con.remote.port),
                    "daddr": self._ownip(icd),
                    "dport": str(icd.con.local.port),
                    "username": icd.username,
                    "password": icd.password}
            self.client.publish(
                CAPTURECHAN,
                json.dumps(meta).encode('utf-8')
            )
        except Exception as e:
            logger.warning('exception when publishing: {0}'.format(e))

    def handle_incident_dionaea_modules_python_mssql_cmd(self, icd):
        try:
            tstamp = timestr()
            meta = {"tags": self.tags,
                    "time": tstamp,
                    "saddr": icd.con.remote.host,
                    "sport": str(icd.con.remote.port),
                    "daddr": self._ownip(icd),
                    "dport": str(icd.con.local.port),
                    "cmd": icd.cmd}
            self.client.publish(
                CAPTURECHAN,
                json.dumps(meta).encode('utf-8')
            )
        except Exception as e:
            logger.warning('exception when publishing: {0}'.format(e))

    def handle_incident_dionaea_modules_python_virustotal_report(self, icd):
        data = {'virustotal': dict()}
        md5 = icd.md5hash
        f = open(icd.path, mode='r')
        j = json.load(f)

        # file was known to virustotal
        if j['response_code'] == 1:
            permalink = j['permalink']
            date = j['scan_date']
            data['virustotal']['md5sum'] = md5
            data['virustotal']['permalink'] = permalink
            data['virustotal']['date'] = date
            data['virustotal']['results'] = []

            scans = j['scans']
            for av, val in scans.items():
                res = val['result']
                if res == '':
                    res = None
                result = {'av': av, 'status': res}
                data['virustotal']['results'].append(result)

            try:
                tstamp = timestr()
                meta = {"tags": self.tags,
                        "time": tstamp,
                        "saddr": icd.con.remote.host,
                        "sport": str(icd.con.remote.port),
                        "daddr": self._ownip(icd),
                        "dport": str(icd.con.local.port),
                        "virustotal": data['virustotal']}
                self.client.publish(
                    CAPTURECHAN,
                    json.dumps(meta).encode('utf-8')
                )
            except Exception as e:
                logger.warning('exception when publishing: {0}'.format(e))

    def handle_incident_dionaea_modules_python_mysql_login(self, icd):
        try:
            tstamp = timestr()
            meta = {"tags": self.tags,
                    "time": tstamp,
                    "saddr": icd.con.remote.host,
                    "sport": str(icd.con.remote.port),
                    "daddr": self._ownip(icd),
                    "dport": str(icd.con.local.port),
                    "username": icd.username,
                    "password": icd.password}
            self.client.publish(
                CAPTURECHAN,
                json.dumps(meta).encode('utf-8')
            )
        except Exception as e:
            logger.warning('exception when publishing: {0}'.format(e))

    def handle_incident_dionaea_modules_python_mysql_command(self, icd):
        try:
            tstamp = timestr()
            meta = {"tags": self.tags,
                    "time": tstamp,
                    "saddr": icd.con.remote.host,
                    "sport": str(icd.con.remote.port),
                    "daddr": self._ownip(icd),
                    "dport": str(icd.con.local.port),
                    "cmd": icd.cmd}
            self.client.publish(
                CAPTURECHAN,
                json.dumps(meta).encode('utf-8')
            )
        except Exception as e:
            logger.warning('exception when publishing: {0}'.format(e))

    def handle_incident_dionaea_modules_python_mqtt_connect(self, icd):
        try:
            tstamp = timestr()
            meta = {"tags": self.tags,
                    "time": tstamp,
                    "saddr": icd.con.remote.host,
                    "sport": str(icd.con.remote.port),
                    "daddr": self._ownip(icd),
                    "dport": str(icd.con.local.port),
                    "username": icd.username,
                    "password": icd.password,
                    "mqtt_action": "connect",
                    "mqtt_clientid": icd.clientid,
                    "mqtt_willtopic": icd.willtopic,
                    "mqtt_willmessage": icd.willmessage}
            self.client.publish(
                CAPTURECHAN,
                json.dumps(meta).encode('utf-8')
            )
        except Exception as e:
            logger.warning('exception when publishing: {0}'.format(e))

    def handle_incident_dionaea_modules_python_mqtt_publish(self, icd):
        try:
            tstamp = timestr()
            meta = {"tags": self.tags,
                    "time": tstamp,
                    "saddr": icd.con.remote.host,
                    "sport": str(icd.con.remote.port),
                    "daddr": self._ownip(icd),
                    "dport": str(icd.con.local.port),
                    "mqtt_action": "publish",
                    "mqtt_topic": icd.publishtopic,
                    "mqtt_message": icd.publishmessage}
            self.client.publish(
                CAPTURECHAN,
                json.dumps(meta).encode('utf-8')
            )
        except Exception as e:
            logger.warning('exception when publishing: {0}'.format(e))

    def handle_incident_dionaea_modules_python_mqtt_subscribe(self, icd):
        try:
            tstamp = timestr()
            meta = {"tags": self.tags,
                    "time": tstamp,
                    "saddr": icd.con.remote.host,
                    "sport": str(icd.con.remote.port),
                    "daddr": self._ownip(icd),
                    "dport": str(icd.con.local.port),
                    "mqtt_action": "subscribe",
                    "mqtt_topic": icd.subscribetopic,
                    "mqtt_message": icd.subscribemessage}
            self.client.publish(
                CAPTURECHAN,
                json.dumps(meta).encode('utf-8')
            )
        except Exception as e:
            logger.warning('exception when publishing: {0}'.format(e))

    def handle_incident_dionaea_module_emu_profile(self, icd):
        if not hasattr(icd, 'con') or not self.client.connected:
            return
        logger.debug('emu profile, publishing length {0}'.format(len(icd.profile)))
        try:
            self.client.publish(SCPROFCHAN, profile=icd.profile)
        except Exception as e:
            logger.warning('exception when publishing: {0}'.format(e))

    def handle_incident_dionaea_modules_python_sip_command(self, icd):

        def add_addr(_type, addr):
            logger.info("adding address: " + str(addr))

            addr_data = {'type': _type,
                         'display_name': addr['display_name'],
                         'uri_scheme': addr['uri']['scheme'],
                         'uri_username': addr['uri']['user'],
                         'uri_password': addr['uri']['password'],
                         'uri_host': addr['uri']['host'],
                         'uri_port': addr['uri']['port']}
            return addr_data

        def add_sdp_condata(c):
            con_data = {'network_type': c['nettype'],
                        'address_type': c['addrtype'],
                        'connection_address': c['connection_address'],
                        'ttl': c['ttl'],
                        'number_of_addresses': c['number_of_addresses']}
            return con_data

        def add_sdp_media(c):
            media_data = {'media': c['media'],
                          'port': c['port'],
                          'number_of_ports': c['number_of_ports'],
                          'protocol': c['proto']}
            return media_data

        def add_sdp_origin(o):
            origin_data = {'username': o['username'],
                           'session_id': o['sess_id'],
                           'session_version': o['sess_version'],
                           'network_type': o['nettype'],
                           'address_type': o['addrtype'],
                           'unicast_address': o['unicast_address']}
            return origin_data

        def calc_allow(a):
            b = {b'UNKNOWN': (1 << 0),
                 'ACK': (1 << 1),
                 'BYE': (1 << 2),
                 'CANCEL': (1 << 3),
                 'INFO': (1 << 4),
                 'INVITE': (1 << 5),
                 'MESSAGE': (1 << 6),
                 'NOTIFY': (1 << 7),
                 'OPTIONS': (1 << 8),
                 'PRACK': (1 << 9),
                 'PUBLISH': (1 << 10),
                 'REFER': (1 << 11),
                 'REGISTER': (1 << 12),
                 'SUBSCRIBE': (1 << 13),
                 'UPDATE': (1 << 14)
                 }
            allow = 0
            for i in a:
                if i in b:
                    allow |= b[i]
                else:
                    allow |= b[b'UNKNOWN']
            return allow

        data = {'sip_data': {
                    'method': icd.method,
                    'call_id': icd.call_id,
                    'user_agent': icd.user_agent,
                    'allow': calc_allow(icd.allow),
                    'sdp_origin': None,
                    'sdp_condata': None,
                    'sdp_media': []
               }}

        data['sip_data']['names'] = []
        for name in ('addr', 'to', 'contact'):
            data['sip_data']['names'].append(add_addr(name, icd.get(name)))

        for elem in icd.get('from'):
            data['sip_data']['names'].append(add_addr("from", elem))

        data['sip_data']['vias'] = []
        for via in icd.get('via'):
            via_data = {'protocol': via["protocol"],
                        'address': via["address"],
                        'port': via["port"]}
            data['sip_data']['vias'].append(via_data)

        sdp_data = icd.get("sdp")
        if sdp_data is not None:
            if 'o' in sdp_data:
                data['sip_data']['sdp_origin'] = add_sdp_origin(sdp_data['o'])
            if 'c' in sdp_data:
                data['sip_data']['sdp_condata'] = add_sdp_condata(sdp_data['c'])
            if 'm' in sdp_data:
                for media in sdp_data['m']:
                    data['sip_data']['sdp_media'].append(add_sdp_media(media))

        try:
            tstamp = timestr()
            meta = {"tags": self.tags,
                    "time": tstamp,
                    "saddr": icd.con.remote.host,
                    "sport": str(icd.con.remote.port),
                    "daddr": self._ownip(icd),
                    "dport": str(icd.con.local.port),
                    "sip_data": data['sip_data']}
            self.client.publish(
                CAPTURECHAN,
                json.dumps(meta).encode('utf-8')
            )
        except Exception as e:
            logger.warning('exception when publishing: {0}'.format(e))

    def _dynip_resolve(self, events, data):
        i = incident("dionaea.upload.request")
        i._url = self.dynip_resolve
        i._callback = "dionaea.modules.python.hpfeeds.dynipresult"
        i.report()

    def handle_incident_dionaea_modules_python_hpfeeds_dynipresult(self, icd):
        fh = open(icd.path, mode="rb")
        self.ownip = fh.read().strip().decode('utf8')
        logger.debug('resolved own IP to: {0}'.format(self.ownip))
        fh.close()
