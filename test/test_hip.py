import unittest
from subprocess import PIPE
from unittest import TestCase

from core.emulator.coreemu import CoreEmu
from core.emulator.data import IpPrefixes
from core.emulator.enumerations import EventTypes
from core.nodes.network import SwitchNode

from hipnode import HIPNode


class TestHIP(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.coreemu = CoreEmu()

    @classmethod
    def tearDownClass(cls):
        """We cannot perform manual cleanup of CoreEmu since it ALWAYS performs
        a cleanup on terminating signals."""
        pass

    def setUp(self):
        self.session = self.coreemu.create_session()
        self.session.set_state(EventTypes.CONFIGURATION_STATE)
        self.ip_prefixes = IpPrefixes(ip4_prefix="10.0.0.0/24")

    def tearDown(self):
        self.coreemu.delete_session(self.session.id)

    def test_basic_connectivity(self):
        """Test that two computers connected by a switch can communicate."""

        switch = self.session.add_node(SwitchNode)
        n1 = self.session.add_node(HIPNode)
        n2 = self.session.add_node(HIPNode)
        iface1 = self.ip_prefixes.create_iface(n1)
        self.session.add_link(n1.id, switch.id, iface1)
        iface2 = self.ip_prefixes.create_iface(n2)
        self.session.add_link(n2.id, switch.id, iface2)
        self.session.instantiate()

        n1.hitgen()
        n2.hitgen()
        n1.set_known_hosts([n1, n2])
        n2.set_known_hosts([n1, n2])
        n1.start()
        n2.start()

        ret = n1.command(f"ping -c 1 {n2.LSI}", stdout=PIPE).wait()
        self.assertIsNotNone(n1.find(r".*?HIP exchange complete.*?"))
        self.assertIsNotNone(n2.find(r".*?HIP exchange complete.*?"))
        self.assertEqual(ret, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2, warnings="ignore")
