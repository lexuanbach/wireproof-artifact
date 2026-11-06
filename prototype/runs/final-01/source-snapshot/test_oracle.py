import struct,unittest
from oracle import selected_groups
def hello(group):
    ext=struct.pack("!HHHH",51,4,group,0)
    msg=b"\x03\x03"+bytes(32)+b"\0"+b"\x13\x01\0"+struct.pack("!H",len(ext))+ext
    return b"\x02"+len(msg).to_bytes(3,"big")+msg
def record(body):
    return b"\x16\x03\x03"+struct.pack("!H",len(body))+body
class ParserTests(unittest.TestCase):
    def test_groups(self):
        self.assertEqual(selected_groups(record(hello(4588))),["X25519MLKEM768"])
        self.assertEqual(selected_groups(record(hello(29))),["X25519"])
    def test_fragmented_handshake(self):
        h=hello(4588)
        self.assertEqual(selected_groups(record(h[:11])+record(h[11:])),["X25519MLKEM768"])
    def test_truncated_record(self):
        with self.assertRaises(ValueError):selected_groups(record(hello(29))[:-1])
    def test_alert_not_handshake(self):
        self.assertEqual(selected_groups(b"\x15\x03\x03\x00\x02\x02\x28"),[])
if __name__=="__main__":unittest.main()
