from paramiko import SSHException
from paramiko.agent import AgentRemoteProxy

class AgentRequestHandler(object):
    def __init__(self, chanClient, chan):
        self._conn = None
        self.__chanC = chanClient
        chanClient.request_forward_agent(self._forward_agent_handler)
        self._chan = chan
        self.__clientProxys = []

    def _forward_agent_handler(self, chanRemote):
        self.__clientProxys.append(AgentClientProxy(self._chan, chanRemote))

    def __del__(self):
        self.close()

    def close(self):
        for p in self.__clientProxys:
            p.close()

class AgentClientProxy(object):
    def __init__(self, chan, chanRemote):
        self._conn = None
        self._chan = chan
        self.__chanR = chanRemote
        self.thread = AgentRemoteProxy(self, chanRemote)
        self.thread.start()

    def __del__(self):
        self.close()

    def connect(self):
        conn_sock = self._chan.get_transport().open_forward_agent_channel()
        if conn_sock is None:
            raise SSHException("lost ssh-agent")
        conn_sock.set_name("auth-agent")
        self._conn = conn_sock

    def close(self):
        """
        Close the current connection and terminate the agent
        Should be called manually
        """
        if hasattr(self, "thread"):
            self.thread._exit = True
            self.thread.join(1000)
        if self._conn is not None:
            self._conn.close()
