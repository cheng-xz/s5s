#-*- coding:utf8 -*-

import socket
import errno
import Queue
import logging
from shadowsocks import eventloop,common,asyncdns
#import asyncdns
import time
import logging

from shadowsocks.common import parse_header

import traceback

# we clear at most TIMEOUTS_CLEAN_SIZE timeouts each time
TIMEOUTS_CLEAN_SIZE = 512

BUF_SIZE = 32 * 1024

WAIT_STATUS_INIT = 0
WAIT_STATUS_READING = 1
WAIT_STATUS_WRITING = 2
WAIT_STATUS_READWRITING = WAIT_STATUS_READING | WAIT_STATUS_WRITING

#定义socket5的相关内容
# SOCKS command definition
CMD_CONNECT = 1
CMD_BIND = 2
CMD_UDP_ASSOCIATE = 3

STAGE_INIT = 0
STAGE_ADDR = 1
STAGE_UDP_ASSOC = 2
STAGE_DNS = 3
STAGE_CONNECTING = 4
STAGE_STREAM = 5
STAGE_DESTROYED = -1


STREAM_UP = 0
STREAM_DOWN = 1


logging.basicConfig(level=logging.INFO,format='%(asctime)-16s %(levelname)-8s %(message)s')


class MyHandler(object):
    def __init__(self,server,fd_to_handlers,loop,local_sock,dns_resolver):
        self._server = server
        self._fd_to_handlers = fd_to_handlers
        self._loop = loop
        self._local_sock = local_sock

        self._remote_sock = None
        self._dns_resolver = dns_resolver

        self._stage = STAGE_INIT

        self._data_to_write_to_local = []
        self._data_to_write_to_remote = []

        self._downstream_status = WAIT_STATUS_INIT
        self._upstream_status = WAIT_STATUS_READING

        self._client_address = local_sock.getpeername()[:2]
        self._remote_address = None

        fd_to_handlers[local_sock.fileno()] = self
        local_sock.setblocking(False)
        local_sock.setsockopt(socket.SOL_TCP,socket.TCP_NODELAY,1)
        loop.add(local_sock,eventloop.POLL_IN | eventloop.POLL_ERR,
                 self._server)        

        self.last_activity = 0
        self._update_activity()

    def __hash__(self):
        return id(self)

    def _update_stream(self,stream,status):
        dirty = False
        if stream == STREAM_DOWN:
            if self._downstream_status != status:
                self._downstream_status = status
                dirty = True
        elif stream == STREAM_UP:
            if self._upstream_status != status:
                self._upstream_status = status
                dirty = True

        if dirty:
            if self._local_sock:
                event = eventloop.POLL_ERR
                if self._downstream_status & WAIT_STATUS_WRITING:
                    event |= eventloop.POLL_OUT
                if self._upstream_status & WAIT_STATUS_READING:
                    event |= eventloop.POLL_IN
                self._loop.modify(self._local_sock,event)
            if self._remote_sock:
                event = eventloop.POLL_ERR
                if self._downstream_status & WAIT_STATUS_READING:
                    event |= eventloop.POLL_IN
                if self._upstream_status & WAIT_STATUS_WRITING:
                    event |= eventloop.POLL_OUT
                self._loop.modify(self._remote_sock,event)


    #这里创建一个到远端的连接
    def _create_remote_socket(self, ip, port):
        addrs = socket.getaddrinfo(ip, port, 0, socket.SOCK_STREAM,
                                   socket.SOL_TCP)
        if len(addrs) == 0:
            raise Exception("getaddrinfo failed for %s:%d" % (ip, port))
        af, socktype, proto, canonname, sa = addrs[0]
        
        remote_sock = socket.socket(af, socktype, proto)
        #这里会保存到远端的连接
        self._remote_sock = remote_sock
        self._fd_to_handlers[remote_sock.fileno()] = self
        remote_sock.setblocking(False)
        remote_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        return remote_sock                

    def _write_to_sock(self,data,sock):
        if not data or not sock:
            return False
        uncomplete = False

        try:
            l = len(data)
            s = sock.send(data)
            if s < l:
                data = data[s:]
                uncomplete = True
        except (OSError, IOError) as e:
            error_no = eventloop.errno_from_exception(e)
            if error_no in (errno.EAGAIN, errno.EINPROGRESS,
                            errno.EWOULDBLOCK):
                uncomplete = True
                print 'error_no in others'
            else:
                print 'send error:%r' % e
                self.destroy()
                return False
            

        if uncomplete:
            if sock == self._local_sock:
                self._data_to_write_to_local.append(data)
                self._update_stream(STREAM_DOWN,WAIT_STATUS_WRITING)
            elif sock == self._remote_sock:
                self._data_to_write_to_remote.append(data)
                self._update_stream(STREAM_UP,WAIT_STATUS_WRITING)
            else:
                print 'write_all_to_sock:unkonwn sock'
        else:
            if sock == self._local_sock:
                self._update_stream(STREAM_DOWN,WAIT_STATUS_READING)
            elif sock == self._remote_sock:
                self._update_stream(STREAM_UP,WAIT_STATUS_READING)
            else:
                print 'write_all_to_sock:unkonwn sock'

        return True

    def _on_remote_read(self):
        data = None
        try:
            data = self._remote_sock.recv(BUF_SIZE)
        except (OSError,IOError) as e:
            if eventloop.errno_from_exception(e) in (errno.ETIMEDOUT,errno.EAGAIN,errno.EWOULDBLOCK):
                return

        if not data:
            self.destroy()
            return

        self._update_activity(len(data))

        try:
            self._write_to_sock(data,self._local_sock)
        except Exception as e:
            print 'write to sock error:%r' % e
            self.destroy()
  #这里也会处理到实际服务器的连接
    def _handle_stage_addr(self, data):
        try:
            cmd = common.ord(data[1])
            #这个暂时不知道是干嘛用的
            if cmd == CMD_UDP_ASSOCIATE: ##CMD_UDP_ASSOCIATE = 3
                logging.debug('UDP associate')
                if self._local_sock.family == socket.AF_INET6:
                    header = b'\x05\x00\x00\x04'
                else:
                    header = b'\x05\x00\x00\x01'
                addr, port = self._local_sock.getsockname()[:2]
                addr_to_send = socket.inet_pton(self._local_sock.family,
                                                    addr)
                port_to_send = struct.pack('>H', port)
                self._write_to_sock(header + addr_to_send + port_to_send,
                                    self._local_sock)
                #这里状态变成下一个状态了
                self._stage = STAGE_UDP_ASSOC
                # just wait for the client to disconnect
                return
            #如果是连接请求，将头也就是前面的\x05\x01\x00去掉，从第三位开始处理数据
            elif cmd == CMD_CONNECT:
                # just trim VER CMD RSV
                data = data[3:]
            else:
                logging.error('unknown command %d', cmd)
                self.destroy()
                return
            #这里专门用pasr_header来处理数据
            header_result = parse_header(data)
            if header_result is None:
                raise Exception('can not parse header')
            addrtype, remote_addr, remote_port, header_length = header_result
            #这里开始执行connect命令
            logging.info('connecting %s:%d from %s:%d' %
                         (common.to_str(remote_addr), remote_port,
                          self._client_address[0], self._client_address[1]))
            self._remote_address = (common.to_str(remote_addr), remote_port)
            # pause reading
            #这里是先更改上行流的状态为写，下面的将需要写道remote的数据放到_data_to_write_to_remote
            self._update_stream(STREAM_UP, WAIT_STATUS_WRITING)
            #更改状态到下一个状态
            self._stage = STAGE_DNS
            # forward address to remote
            #这里是响应客户端的响应，这个响应的内容其实没多大的意义
            self._write_to_sock((b'\x05\x00\x00\x01'
                                    b'\x00\x00\x00\x00\x10\x10'),
                                self._local_sock)
            # notice here may go into _handle_dns_resolved directly
            #这里直接将sserver服务器的域名解析为ip

            if len(data) > header_length:
                self._data_to_write_to_remote.append(data[header_length:])
            # notice here may go into _handle_dns_resolved directly
            self._dns_resolver.resolve(remote_addr,
                                        self._handle_dns_resolved)

            
        except Exception as e:
            print '_handle_stage_addr error:%r' % e
            traceback.print_exc()
            #self._log_error(e)
            self.destroy()

#这里是处理DNS解析结果的handler
    def _handle_dns_resolved(self, result, error):
        if error:
            print '_handle_dns_resolved error1:%r' % error
            #self._log_error(error)
            self.destroy()
            return
        if result:
            ip = result[1]
            if ip:

                try:
                    #这里更新了状态
                    self._stage = STAGE_CONNECTING
                    remote_addr = ip

                    remote_port = self._remote_address[1]

                        # else do connect
                    remote_sock = self._create_remote_socket(remote_addr,
                                                                remote_port)
                    try:
                        remote_sock.connect((remote_addr, remote_port))
                    except (OSError, IOError) as e:
                        if eventloop.errno_from_exception(e) == \
                                errno.EINPROGRESS:
                            pass
                    self._loop.add(remote_sock,
                                    eventloop.POLL_ERR | eventloop.POLL_OUT,
                                    self._server)
                    self._stage = STAGE_CONNECTING
                    self._update_stream(STREAM_UP, WAIT_STATUS_READWRITING)
                    self._update_stream(STREAM_DOWN, WAIT_STATUS_READING)

                    return
                except Exception as e:
                    print '_handle_dns_resolved error2:%r' % e
        self.destroy()            

    def _log_error(self, e):
        logging.error('%s when handling connection from %s:%d' %
                      (e, self._client_address[0], self._client_address[1]))            

   #本地读需要处理sock5协议的各种状态
    def _on_local_read(self):
        # handle all local read events and dispatch them to methods for
        # each stage
        if not self._local_sock:
            return
        data = None
        try:
            data = self._local_sock.recv(BUF_SIZE)
        except (OSError, IOError) as e:
            if eventloop.errno_from_exception(e) in \
                    (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK):
                return
        if not data:
            self.destroy()
            return
        self._update_activity(len(data))
        
        #这里到了最后一步，直接将数据进行加密后抛给远端服务器
        if self._stage == STAGE_STREAM:
            self._write_to_sock(data, self._remote_sock)
            return

        #这里是第一步的处理
        #返回\x05\x00 响应socket客户端，不需要鉴权
        elif self._stage == STAGE_INIT:
            # TODO check auth method
            self._write_to_sock(b'\x05\00', self._local_sock)
            self._stage = STAGE_ADDR
            return
        ##这是第四步，处理连接
        #这里不返回原因是下面的分支会判断状态，而_stage只有一个状态的
        elif self._stage == STAGE_CONNECTING:
            self._handle_stage_connecting(data)

        #这里是第二步处理，进行DNS查询处理
        elif self._stage == STAGE_ADDR:
            self._handle_stage_addr(data)

#这里是处理连接到远端
    def _handle_stage_connecting(self, data):
        self._data_to_write_to_remote.append(data)

    def _on_local_write(self):
        # handle local writable event
        if self._data_to_write_to_local:
            data = b''.join(self._data_to_write_to_local)
            self._data_to_write_to_local = []
            self._write_to_sock(data, self._local_sock)
        else:
            self._update_stream(STREAM_DOWN, WAIT_STATUS_READING)        
        
    def _on_remote_write(self):
        self._stage = STAGE_STREAM
        
        if self._data_to_write_to_remote:
            data = b''.join(self._data_to_write_to_remote)
            self._data_to_write_to_remote = []
            self._write_to_sock(data,self._remote_sock)
        else:
            self._update_stream(STREAM_UP,WAIT_STATUS_READING)

    def handle_event(self,sock,event):
        if self._stage == STAGE_DESTROYED:
            print 'ignore handle_event:destroyed'
            return

        if sock == self._remote_sock:
            if event & eventloop.POLL_ERR:
                print 'get remote error'
                self.destroy()
                if self._stage == STAGE_DESTROYED:
                    return
            if event & (eventloop.POLL_IN | eventloop.POLL_HUP):
                self._on_remote_read()
                if self._stage == STAGE_DESTROYED:
                    return
            if event & eventloop.POLL_OUT:
                self._on_remote_write()
        elif sock == self._local_sock:
            if event & eventloop.POLL_ERR:
                print 'get local error'
                self.destroy()
                if self._stage == STAGE_DESTROYED:
                    return
            if event & (eventloop.POLL_IN | eventloop.POLL_HUP):
                self._on_local_read()
                if self._stage == STAGE_DESTROYED:
                    return
            if event & eventloop.POLL_OUT:
                self._on_local_write()
        else:
            print 'unkown socket'
                
            
            

    def _update_activity(self,data_len=0):
        self._server.update_activity(self,data_len)
        

    def destroy(self):
        if self._stage == STAGE_DESTROYED:
            # this couldn't happen
            logging.debug('already destroyed')
            return
        self._stage = STAGE_DESTROYED
        if self._remote_address:
            logging.debug('destroy: %s:%d' %
                          self._remote_address)
        else:
            logging.debug('destroy')
        if self._remote_sock:
            logging.debug('destroying remote')
            self._loop.remove(self._remote_sock)
            del self._fd_to_handlers[self._remote_sock.fileno()]
            self._remote_sock.close()
            self._remote_sock = None
        if self._local_sock:
            logging.debug('destroying local')
            self._loop.remove(self._local_sock)
            del self._fd_to_handlers[self._local_sock.fileno()]
            self._local_sock.close()
            self._local_sock = None
        self._dns_resolver.remove_callback(self._handle_dns_resolved)
        self._server.remove_handler(self)

        

class MyServer(object):
    def __init__(self,dns_resolver):
        self._loop = None
        self._timeout = 10
        self._dns_resolver = dns_resolver
        server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        server_socket.setblocking(False)
        server_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        server_socket.bind(('0.0.0.0',8000))
        server_socket.listen(1024)

        self._server_socket = server_socket

        self._msg_queues = []

        self._fd_to_handlers = {}

        self._timeouts = []
        self._timeout_offset = 0
        self._handler_to_timeouts = {}

    def remove_handler(self,handler):
        index = self._handler_to_timeouts.get(hash(handler),-1)
        if index >= 0:
            self._timeouts[index] = None
            del self._handler_to_timeouts[hash(handler)]
        
    def add_to_loop(self,loop):
        if self._loop:
            raise Exception(u'already add to loop')
        self._loop = loop
        self._loop.add(self._server_socket,
                       eventloop.POLL_IN | eventloop.POLL_ERR,self)
        loop.add_periodic(self.handle_periodic)
        
    def handle_event(self,sock,fd,event):
        if sock == self._server_socket:
            if event & eventloop.POLL_ERR:
                raise Exception("server_socket error")
            try:
                client_conn = self._server_socket.accept()
                #print client_conn
                MyHandler(self,self._fd_to_handlers,self._loop,client_conn[0],self._dns_resolver)
            except Exception as e:
                print 'accept client error:%r' % e
        else:
            if sock:
                handler = self._fd_to_handlers.get(fd,None)
                if handler:
                    handler.handle_event(sock,event)
            else:
                print 'poll removed fd'

    def _sweep_timeout(self):
        # tornado's timeout memory management is more flexible than we need
        # we just need a sorted last_activity queue and it's faster than heapq
        # in fact we can do O(1) insertion/remove so we invent our own
        if self._timeouts:
            now = time.time()
            length = len(self._timeouts)
            pos = self._timeout_offset
            while pos < length:
                handler = self._timeouts[pos]
                if handler:
                    if now - handler.last_activity < self._timeout:
                        break
                    else:
                        handler.destroy()
                        self._timeouts[pos] = None  # free memory
                        pos += 1
                else:
                    pos += 1
            if pos > TIMEOUTS_CLEAN_SIZE and pos > length >> 1:
                # clean up the timeout queue when it gets larger than half
                # of the queue
                self._timeouts = self._timeouts[pos:]
                for key in self._handler_to_timeouts:
                    self._handler_to_timeouts[key] -= pos
                pos = 0
            self._timeout_offset = pos                
                    
    def update_activity(self, handler, data_len):

        # set handler to active
        now = int(time.time())
        #这里表示没有超时
        if now - handler.last_activity < eventloop.TIMEOUT_PRECISION:
            # thus we can lower timeout modification frequency
            return
        handler.last_activity = now
        index = self._handler_to_timeouts.get(hash(handler), -1)
        if index >= 0:
            # delete is O(n), so we just set it to None
            self._timeouts[index] = None
        length = len(self._timeouts)
        #这里的列表存放handler
        self._timeouts.append(handler)
        #这里实际存放的序列号
        self._handler_to_timeouts[hash(handler)] = length

        #print 'time out list:%r' % self._timeouts
      

    def handle_periodic(self):
        #这里不做关闭处理
        self._sweep_timeout()
        
        


def main():
    dns_resolver = asyncdns.DNSResolver()
    myserv = MyServer(dns_resolver)
    loop = eventloop.EventLoop()
    myserv.add_to_loop(loop)
    dns_resolver.add_to_loop(loop)

    loop.run()

if __name__ == "__main__":
    main()
