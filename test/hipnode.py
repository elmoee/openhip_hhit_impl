import copy
import re
import uuid
from enum import Enum
from subprocess import PIPE, Popen
from xml.etree import ElementTree

from core.nodes.base import CoreNode


class State(Enum):
    IDLE = 0
    HITGEN = 1
    READY = 2
    RUNNING = 3


class HIPNode(CoreNode):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.state = State.IDLE

    def shutdown(self):
        self.stop()
        super().shutdown()

    def _state_check(self, *states):
        if self.state not in states:
            raise RuntimeError(f"Current state {self.state} is not one of {states}")

    def hitgen(self, ip=None):
        self._state_check(State.IDLE, State.HITGEN, State.READY)

        if not ip:
            ip = self.get_ifaces()[0].get_ip4().ip

        self.cmd(
            " && ".join(
                [
                    "mkdir -p usr.local.etc.hip",
                    "mkdir -p /usr/local/etc/hip",
                    "mount --bind usr.local.etc.hip /usr/local/etc/hip",
                    "cd /usr/local/etc/hip",
                    "hitgen -conf",
                    f"echo '{uuid.uuid4().hex}' | hitgen",
                    "hitgen -publish",
                ]
            ),
            shell=True,
        )
        tree = ElementTree.parse(
            f"{self.nodedir}/usr.local.etc.hip/{self.name}_host_identities.pub.xml"
        )
        root = tree.getroot()
        self.host_identity = copy.deepcopy(root[0])
        self.host_identity.append(ElementTree.fromstring(f"<addr>{ip}</addr>"))
        self.LSI = self.host_identity.find("LSI").text
        self.state = State.HITGEN

    def set_known_hosts(self, nodes):
        self._state_check(State.HITGEN, State.READY)
        khi = ElementTree.Element("known_host_identities")
        for node in nodes:
            khi.append(node.host_identity)

        tree = ElementTree.ElementTree(khi)
        tree.write(
            f"{self.nodedir}/usr.local.etc.hip/known_host_identities.xml",
            encoding="utf-8",
            xml_declaration=True,
        )
        self.state = State.READY

    def command(self, cmd, *args, **kwargs):
        return Popen(
            f"vcmd -c {self.ctrlchnlname} -- {cmd}".split(" "), *args, **kwargs
        )

    def start(self):
        self._state_check(State.READY)

        self.hip = self.command(
            "hip -v",
            stdout=PIPE,
            universal_newlines=True,
        )
        self.state = State.RUNNING
        self.find(r".*?HIP threads initialization completed.*?")

    def find(self, pattern):
        while line := self.hip.stdout.readline():
            if match := re.match(pattern, line):
                return match

    def stop(self):
        if self.state == State.RUNNING:
            self.hip.kill()
            self.hip.wait()
            self.state = State.READY