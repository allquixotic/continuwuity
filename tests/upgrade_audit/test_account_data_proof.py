import copy
import unittest
from account_data_proof import prove, FAMILIES

class PreservationProof(unittest.TestCase):
    def setUp(self):
        self.server = '@conduit:example.com'
        self.pointer = b'\xff'+self.server.encode()+b'\xffm.push_rules'
        self.before = {FAMILIES[0]: {b'server-old': b'{"type":"m.push_rules","content":{}}',
                                    b'user-old': b'{"content":{"encrypted":"private"}}'},
                       FAMILIES[1]: {self.pointer: b'server-old', b'user-index': b'user-old'}}
        self.after = copy.deepcopy(self.before)
        self.after[FAMILIES[0]][b'server-new'] = self.after[FAMILIES[0]].pop(b'server-old')
        self.after[FAMILIES[1]][self.pointer] = b'server-new'

    def test_server_counter_only(self):
        self.assertTrue(prove(self.before, self.after, self.server)['passed'])

    def test_changed_user_payload_rejected(self):
        self.after[FAMILIES[0]][b'user-old'] = b'{"content":{}}'
        with self.assertRaises(AssertionError): prove(self.before, self.after, self.server)

    def test_changed_server_content_rejected(self):
        self.after[FAMILIES[0]][b'server-new'] = b'{"content":{"rules":"changed"}}'
        with self.assertRaises(AssertionError): prove(self.before, self.after, self.server)

    def test_removed_user_record_rejected(self):
        del self.after[FAMILIES[0]][b'user-old']
        with self.assertRaises(AssertionError): prove(self.before, self.after, self.server)

if __name__ == '__main__': unittest.main()
