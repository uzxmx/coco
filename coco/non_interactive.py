#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#

from .proxy import ProxyServer

class NonInteractiveServer:
    def __init__(self, client, asset, su):
        self.client = client
        self.asset = asset
        self.su = su

    def handle(self):
        forwarder = ProxyServer(self.client, False, self.asset, self.su)
        forwarder.proxy()
