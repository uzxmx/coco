#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#

import threading
import time

try:
    import selectors
except ImportError:
    import selectors2 as selectors

from .session import Session
from .models import Server, TelnetServer
from .connection import SSHConnection, TelnetConnection
from .service import app_service
from .conf import config
from .utils import wrap_with_line_feed as wr, wrap_with_warning as warning, \
     get_logger, net_input, ugettext as _, ignore_error
from .agent import AgentRequestHandler


logger = get_logger(__file__)
BUF_SIZE = 4096
MANUAL_LOGIN = 'manual'
AUTO_LOGIN = 'auto'


class ProxyServer:
    def __init__(self, client, interactive, asset, system_user):
        self.client = client
        self.interactive = interactive
        self.asset = asset
        self.system_user = system_user
        self.server = None
        self.connecting = True

    def get_system_user_auth_or_manual_set(self):
        """
        获取系统用户的认证信息，密码或秘钥
        :return: system user have full info
        """
        password, private_key = \
            app_service.get_system_user_auth_info(self.system_user)
        if self.system_user.login_mode == MANUAL_LOGIN \
                or (not password and not private_key):
            prompt = "{}'s password: ".format(self.system_user.username)
            password = net_input(self.client, prompt=prompt, sensitive=True)
            private_key = None
        self.system_user.password = password
        self.system_user.private_key = private_key

    def check_protocol(self):
        if self.asset.protocol != self.system_user.protocol:
            msg = 'System user <{}> and asset <{}> protocol are inconsistent.'.format(
                self.system_user.name, self.asset.hostname
            )
            self.client.send_unicode(warning(wr(msg, before=1, after=0)))
            return False
        return True

    def get_system_user_username_if_need(self):
        if self.system_user.login_mode == MANUAL_LOGIN and \
                not self.system_user.username:
            username = net_input(self.client, prompt='username: ', before=1)
            self.system_user.username = username
            return True
        return False

    def proxy(self):
        if not self.check_protocol():
            return
        self.get_system_user_username_if_need()
        self.get_system_user_auth_or_manual_set()
        self.server = self.get_server_conn()
        if self.server is None:
            return
        if self.client.closed:
            self.server.close()
            return

        if self.interactive:
            session = Session.new_session(self.client, self.server)
            if not session:
                msg = _("Connect with api server failed")
                logger.error(msg)
                self.client.send_unicode(msg)
                self.server.close()

            try:
                session.bridge()
            finally:
                Session.remove_session(session.id)
                self.server.close()
                msg = 'Session end, total {} now'.format(
                    len(Session.sessions),
                )
                logger.info(msg)
        else:
            try:
                client = self.client
                server = self.server
                chan = server.chan
                chan.exec_command(client.request.meta['command'])
                sel = selectors.DefaultSelector()
                sel.register(client, selectors.EVENT_READ)
                sel.register(chan, selectors.EVENT_READ)
                finished = False
                while not finished:
                    events = sel.select(timeout=60)
                    for sock in [key.fileobj for key, _ in events]:
                        data = sock.recv(1024)
                        if sock == client:
                            if len(data) > 0:
                                server.send(data)
                            else:
                                sel.unregister(client)
                                chan.shutdown_write()
                        elif sock == chan:
                            # The data may come from stdout or stderr, it's not easy to distinguish, so here
                            # we just send the data to client stdout.
                            if len(data) > 0:
                                client.send(data)
                            else:
                                sel.unregister(chan)
                                finished = True
                                # Drain stdout/stderr stream.
                                while True:
                                    data = chan.recv(1024)
                                    if len(data) > 0:
                                        client.send(data)
                                    else:
                                        break
                                while True:
                                    data = chan.recv_stderr(1024)
                                    if len(data) > 0:
                                        client.send(data)
                                    else:
                                        break
                                break

                client.chan.send_exit_status(chan.recv_exit_status())
            finally:
                self.server.close()

    def validate_permission(self):
        """
        验证用户是否有连接改资产的权限
        :return: True or False
        """
        return app_service.validate_user_asset_permission(
            self.client.user.id, self.asset.id, self.system_user.id
        )

    def get_server_conn(self):
        logger.info("Connect to {}:{} ...".format(self.asset.hostname, self.asset.port))
        if self.interactive:
            self.send_connecting_message()
        if not self.validate_permission():
            self.client.send_unicode(warning(_('No permission')))
            server = None
        elif self.system_user.protocol == self.asset.protocol == 'telnet':
            server = self.get_telnet_server_conn()
        elif self.system_user.protocol == self.asset.protocol == 'ssh':
            server = self.get_ssh_server_conn()
        else:
            server = None
        if self.interactive:
            self.client.send(b'\r\n')
        self.connecting = False
        return server

    def get_telnet_server_conn(self):
        telnet = TelnetConnection(self.asset, self.system_user, self.client)
        sock, msg = telnet.get_socket()
        if not sock:
            self.client.send_unicode(warning(wr(msg, before=1, after=0)))
            server = None
        else:
            server = TelnetServer(sock, self.asset, self.system_user)
        return server

    def get_ssh_server_conn(self):
        ssh = SSHConnection()
        transport, sock, msg = ssh.get_transport(self.asset, self.system_user)
        chan = transport.open_session()
        if not chan:
            self.client.send_unicode(warning(wr(msg, before=1, after=0)))
            return

        if self.client.forward_agent:
            AgentRequestHandler(chan, self.client.chan)

        if self.interactive:
            request = self.client.request
            term = request.meta.get('term', 'xterm')
            width = request.meta.get('width', 80)
            height = request.meta.get('height', 24)
            chan.get_pty(term, width, height, 0, 0)
            chan.invoke_shell()

        return Server(chan, sock, self.asset, self.system_user)

    def send_connecting_message(self):
        @ignore_error
        def func():
            delay = 0.0
            msg = _('Connecting to {}@{} {:.1f}').format(
                self.system_user, self.asset, delay
            )
            self.client.send_unicode(msg)
            while self.connecting and delay < config['SSH_TIMEOUT']:
                if 0 <= delay < 10:
                    self.client.send_unicode('\x08\x08\x08{:.1f}'.format(delay))
                else:
                    self.client.send_unicode('\x08\x08\x08\x08{:.1f}'.format(delay))
                time.sleep(0.1)
                delay += 0.1
        thread = threading.Thread(target=func)
        thread.start()
