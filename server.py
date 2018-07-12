#!/usr/bin/env python

import logging
import logging.handlers
import socket
import select
import sys
import time
from struct import pack, unpack
import struct
import random
import errno
import relay
import threading
import optparse

class RelayServer:
    def __init__(self, host, port, socket_with_server):
        self.input_list = []
        self.channel = {}
        self.last_ping_time = time.time()
        self.id_by_socket = {}
        self.pending_socks_clients = []
        self.socket_with_server = socket_with_server
        self.input_list.append(self.socket_with_server)
        self.remote_side_down = False

        logger.debug('Starting ping thread')

        self.ping_thread = threading.Thread(target=self.ping_worker)
        self.ping_thread.start()

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server.bind((host, port))
            self.server.listen(2000)
        except socket.error as (code, msg):
            logger.error('Error binding socks proxy. {0}'.format(msg))
            logger.error('Closing relay')
            socket_with_server.close()
            raise
        self.socks_client_socket = None

    def ping_worker(self):
        while True:
            time.sleep(10)
            current_time = time.time()
            if self.remote_side_down:
                logger.debug('Remote side down. Ping worker exiting')
                return
            if current_time - self.last_ping_time > relay.relay_timeout:
                logger.info('No response from remote side for {0} seconds. Restarting relay'.format(relay.relay_timeout))
                self.socket_with_server.close()
                return
            logger.debug('Sending ping')
            try:
                self.send_remote_cmd(self.socket_with_server, relay.PING_CMD)
            except socket.error as (code, msg):
                logger.debug('Ping thread got socket exception {0} {1}. Closing socket with remote side'.format(code, msg))
                self.socket_with_server.close()
                return
            except relay.RelayError:
                logger.debug('Ping worker caught RelayError. Exiting')
                self.shutdown()
                return

    def shutdown(self):
        relay.close_sockets(self.input_list)
        self.remote_side_down = True


    def main_loop(self):
        self.input_list.append(self.server)
        while True:
            time.sleep(relay.delay)

            try:
                logger.debug("Active channels: {0}".format(self.channel.keys()))
                inputready, outputready, exceptready = select.select(self.input_list, [], [])
            except socket.error as (code, msg):
                logger.debug('Socket error on select. Errno: {0} Msg: {1}'.format(errno.errorcode[code], msg))
                return
            except KeyboardInterrupt:
                logger.info('SIGINT received. Closing relay and exiting')
                self.shutdown()
                sys.exit(1)
            for self.selected_input_socket in inputready:
                if self.selected_input_socket == self.server:
                    self.on_accept()
                    break

                if self.selected_input_socket == self.socket_with_server:
                    try:
                        self.manage_remote_socket(self.selected_input_socket)
                    except relay.RelayError:
                        logger.debug('Main loop: got RelayError. Closing connection with remote side and exiting loop')
                        self.shutdown()
                        return
                elif self.selected_input_socket in self.pending_socks_clients:
                    self.pending_socks_clients.remove(self.selected_input_socket)
                    try:
                        ip, port = self.handle_new_socks_connection(self.selected_input_socket)
                    except relay.RelayError:
                        logger.debug("Closing socks client socket {0}".format(self.selected_input_socket))
                        self.input_list.remove(self.selected_input_socket)
                        self.selected_input_socket.close()
                        continue
                    #self.input_list.append(self.selected_input_socket)
                    new_channel_id = self.set_channel(self.selected_input_socket)
                    logger.debug("Sending command to open channel {0}".format(new_channel_id))
                    self.send_remote_cmd(self.socket_with_server, relay.CHANNEL_OPEN_CMD, new_channel_id, ip, port)


                elif self.selected_input_socket in self.id_by_socket:
                    self.manage_socks_client_socket(self.selected_input_socket)
                else:
                    logger.debug("Active socket {0} does not belong to channel. Closing it".format(self.selected_input_socket))
                    self.selected_input_socket.close()


    def parse_socks_header(self, data):
        try:
            (vn, cd, dstport, dstip) = unpack('>BBHI', data[:8])
        except struct.error:
            logger.debug('Invalid socks header! Got data: {0}'.format(repr(data)))
            raise relay.RelayError
        if vn != 4:
            logger.debug('Invalid socks header! Got data: {0}'.format(repr(data)))
            raise relay.RelayError
        str_ip = socket.inet_ntoa(pack(">L", dstip))
        logger.debug('Parsing socks header. Socks version: {0} Socks command: {1} Dstport: {2} Dstip: {3}'.format(vn, cd, dstport, str_ip))
        return str_ip, dstport

    def get_channel_data(self, sock):
        try:
            tlv_header = relay.recvall(sock, 4)
            channel_id, tlv_data_len = unpack('<HH', tlv_header)
            data = relay.recvall(sock, tlv_data_len)
        except socket.error as (code, msg):
            logger.debug('Exception on receiving tlv message from remote side. Exiting')
            logger.debug('Errno: {0} Msg: {1}'.format(errno.errorcode[code], msg))
            raise relay.RelayError
        return channel_id, data

    def manage_remote_socket(self, sock):
        channel_id, data = self.get_channel_data(sock)
        if channel_id == relay.COMMAND_CHANNEL:
            self.handle_remote_cmd(data)
        elif channel_id in self.channel:
            relay_to_sock = self.channel[channel_id]
            logger.debug('Got data to relay from remote side. Channel id {0}. Data length: {1}'.format(channel_id, len(data)))
            logger.debug('Data contents: {0}'.format(data.encode('hex')))
            self.relay(data, relay_to_sock)
        else:
            logger.debug('Relay from socket {0} with channel {1} not possible. Channel does not exist'.format(sock, channel_id))
            return

    def manage_socks_client_socket(self, sock):
        try:
            data = sock.recv(relay.buffer_size)
        except socket.error as (code, msg):
            logger.debug('Exception on reading socket {0} with channel id {1}'.format(sock, self.id_by_socket[sock]))
            logger.debug('Details: {0}, {1}'.format(errno.errorcode[code], msg))
            self.close_socks_connection(sock)
            return
        data_len = len(data)
        if data_len == 0:
            self.close_socks_connection(sock)
            return
        else:
            channel_id = self.id_by_socket[sock]
            tlv_header = pack('<HH', channel_id, len(data))
            logger.debug('Got data to relay from app side. Channel id {0}. Data length: {1}'.format(channel_id, len(data)))
            logger.debug('Preparint tlv header: {0}'.format(tlv_header.encode('hex')))
            logger.debug('Data contents: {0}'.format(data.encode('hex')))
            self.relay(tlv_header + data, self.socket_with_server)

    def handle_remote_cmd(self, data):
        cmd = data[0]
        logger.debug('Received cmd from remote side. Cmd: {0}'.format(relay.cmd_names[cmd]))
        if cmd == relay.CHANNEL_CLOSE_CMD:
            channel_id = unpack('<H', data[1:3])[0]
            logger.debug('Channel close request with id: {0}'.format(channel_id))
            if channel_id not in self.channel:
                logger.debug('Channel {0} already closed'.format(channel_id))
                return
            else:
                sock_to_close = self.channel[channel_id]
                self.input_list.remove(sock_to_close)
                self.unset_channel(channel_id)
                logger.debug('Closing socket {0}  with id: {1}'.format(sock_to_close, channel_id))
                sock_to_close.close()
        elif cmd == relay.FORWARD_CONNECTION_SUCCESS:
            channel_id = unpack('<H', data[1:3])[0]
            if channel_id in self.channel:
                logger.debug('Forward connection successful with id: {0}'.format(channel_id))
                sock = self.channel[channel_id]
                try:
                    sock.send(relay.socks_server_reply_success)
                except socket.error as (code, msg):
                    logger.error('Socket error on replying SUCCESS to socks client. Code {0}. Msg {1}'.format(code, cmd))
                    logger.debug('Closing client socket and sending channel close cmd to remote side')
                    sock = self.channel[channel_id]
                    self.input_list.remove(sock)
                    self.unset_channel(channel_id)
                    try:
                        sock.close()
                    except socket.error:
                        logger.debug('Error on closing socket')

                    self.send_remote_cmd(self.socket_with_server, relay.CHANNEL_CLOSE_CMD, channel_id)
            else:
                logger.debug('Forward connection successful with id: {0}. But channel already closed here'.format(channel_id))
        elif cmd == relay.FORWARD_CONNECTION_FAILURE:
            channel_id = unpack('<H', data[1:3])[0]
            logger.debug('Forward connection failed with id: {0}'.format(channel_id))
            if channel_id in self.channel:
                sock = self.channel[channel_id]
                try:
                    sock.send(relay.socks_server_reply_fail)
                except socket.error as (code, msg):
                    logger.error('Socket error on replying  FAILURE to socks client. Code {0}. Msg {0}'.format(code, cmd))
                self.input_list.remove(sock)
                self.unset_channel(channel_id)
                try:
                    sock.close()
                except socket.error:
                    logger.debug('Error on closing socket')
            else:
                logger.debug('Tried to close channel {0} that is already closed'.format(channel_id))

        elif cmd == relay.CLOSE_RELAY:
            logger.info('Got command to close relay. Closing connection with client.')
            raise relay.RelayError
        elif cmd == relay.PING_CMD:
            #logger.debug('Got ping response from remote side. Good.')
            self.last_ping_time = time.time()
        else:
            logger.error('Unknown cmd received! Exiting')
            raise relay.RelayError

    def send_remote_cmd(self, sock, cmd, *args):
        logger.debug('Sending cmd to remote side. Cmd: {0}'.format(relay.cmd_names[cmd]))
        if cmd == relay.CHANNEL_CLOSE_CMD:
            cmd_buffer = cmd + pack('<H', args[0])
            tlv_header = pack('<HH', relay.COMMAND_CHANNEL, len(cmd_buffer))
        elif cmd == relay.CHANNEL_OPEN_CMD:
            channel_id, ip, port = args
            cmd_buffer = cmd + pack('<H',  channel_id) + socket.inet_aton(ip) + pack('<H', port)
            tlv_header = pack('<HH', relay.COMMAND_CHANNEL, len(cmd_buffer))
        else:
            cmd_buffer = cmd
            tlv_header = pack('<HH', relay.COMMAND_CHANNEL, len(cmd_buffer))
        try:
            sock.send(tlv_header + cmd_buffer)
        except socket.error as (code, cmd):
            logger.error('Socket error on sending command to remote side. Code {0}. Msg {1}'.format(code, cmd))
            raise relay.RelayError

    def on_accept(self):
        socks_client_socket, clientaddr = self.server.accept()
        logger.debug("Socks client {0} has connected".format(clientaddr))
        self.input_list.append(socks_client_socket)
        self.pending_socks_clients.append(socks_client_socket)




    def handle_new_socks_connection(self, sock):
        try:
            logger.debug('Trying to recieve socks header from socks client')
            #data = relay.recvall(sock, 9)
            data = sock.recv(9)
            logger.debug('Got header data from socks client')
            if len(data) != 9:
                logger.debug('Error receiving socks header: corrupted header')
                raise relay.RelayError
            if data[-1] != '\x00':
                logger.debug('Error receiving socks header: corrupted header')
                raise relay.RelayError
        except socket.error as (code, msg):
            logger.debug('Error receiving socks header {0} {1}'.format(errno.errorcode[code], msg))
            raise relay.RelayError
        if len(data) == 0:
            logger.debug('Socks client prematurely ended connection')
            raise relay.RelayError
        return self.parse_socks_header(data)

    def set_channel(self, sock):
        new_channel_id = self.generate_new_channel_id()
        self.channel[new_channel_id] = sock
        self.id_by_socket[sock] = new_channel_id
        return new_channel_id

    def unset_channel(self, channel_id):
        sock = self.channel[channel_id]
        del self.id_by_socket[sock]
        del self.channel[channel_id]

    def generate_new_channel_id(self):
        channel_ids = self.channel.keys()
        while True:
            rint = random.randint(1, 65535)
            if rint not in channel_ids:
                return rint

    def close_socks_connection(self, sock):
        channel_id = self.id_by_socket[sock]
        logger.debug('Closing socks client socket {0} with id {1}'.format(sock, channel_id))
        logger.debug('Notifying remote side')
        self.unset_channel(channel_id)
        self.input_list.remove(sock)
        sock.close()
        self.send_remote_cmd(self.socket_with_server, relay.CHANNEL_CLOSE_CMD, channel_id)

    def relay(self, data, to_socket):
        if to_socket is None:
            return
        try:
            to_socket.send(data)
        except socket.error as (code, msg):
            logger.debug('Exception on relaying data to socket {0}'.format(to_socket))
            logger.debug('Errno: {0} Msg: {1}'.format(errno.errorcode[code], msg))
            if to_socket == self.socket_with_server:
                raise relay.RelayError
            else:
                logger.debug('Closing socket')
                to_socket.close()
                self.input_list.remove(to_socket)
                channel_id = self.id_by_socket[to_socket]
                self.unset_channel(channel_id)
                self.send_remote_cmd(self.socket_with_server, relay.CHANNEL_CLOSE_CMD, channel_id)


def run_server(host, port):
    while True:
        serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serversock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            serversock.bind((host, port))
            serversock.listen(5)
        except socket.error:
            logger.error('Exception binding server at {0} port {1}'.format(host, port))
            time.sleep(1)
            break

        try:
            (socket_with_remote_side, address) = serversock.accept()
        except KeyboardInterrupt:
            logger.info('SIGINT received. Shutting down')
            sys.exit(1)
        logger.info('New connection from host {0}, source port {1}'.format(address[0], address[1]))
        serversock.close()

        try:
            banner_rcv = socket_with_remote_side.recv(4096)
            if banner_rcv != relay.banner:
                logger.error("Wrong banner {0} from client. Closing connection".format(repr(banner_rcv)))
                socket_with_remote_side.close()
                continue
            socket_with_remote_side.send(relay.banner_response)
        except socket.error as (code, msg):
            logger.error("Caught socket error trying to establish connection with RPIVOT client. Code {0}. Msg {1}".format(code, msg))
            continue

        try:
            server = RelayServer(cmd_options.proxy_ip, int(cmd_options.proxy_port), socket_with_remote_side)

        except socket.error as (code, msg):
            logger.info('Error on running relay server. Restarting')
            continue
        try:
            server.main_loop()
        except relay.RelayError:
            logger.info('Got RelayError in server.main_loop(). Restarting relay')
            server.server.close()
            continue

        except KeyboardInterrupt:
            print "Ctrl C - Stopping server"
            sys.exit(1)


def main():
    global logger
    global cmd_options

    parser = optparse.OptionParser(description='Reverse socks server')
    parser.add_option('--server-ip', action="store", dest='server_ip', default='0.0.0.0')
    parser.add_option('--server-port', action="store", dest='server_port', default='9999')
    parser.add_option('--proxy-ip', action="store", dest='proxy_ip', default='127.0.0.1')
    parser.add_option('--proxy-port', action="store", dest='proxy_port', default='1080')
    parser.add_option('--verbose', action="store_true", dest="verbose", default=False)
    parser.add_option('--logfile', action="store", dest="logfile", default=None)



    cmd_options = parser.parse_args()[0]



    logger = logging.getLogger('root')
    logger.setLevel(logging.DEBUG)
    ch = None

    if cmd_options.logfile is None:
        ch = logging.StreamHandler()
    else:
        ch = logging.FileHandler(cmd_options.logfile)

    if cmd_options.verbose:
        ch.setLevel(logging.DEBUG)
    else:
        ch.setLevel(logging.INFO)

    logger.addHandler(ch)

    run_server(cmd_options.server_ip, int(cmd_options.server_port))


if __name__ == "__main__":
    main()



