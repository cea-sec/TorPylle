#! /usr/bin/env python

from scapy.all import *

import socket, ssl
import struct
import urllib2

HASH_FUNC = Crypto.Hash.SHA
HASH_NAME = 'sha1'
HASH_LEN = HASH_FUNC.digest_size
PUBKEY_FUNC = Crypto.PublicKey.RSA
PUBKEY_MODSIZE = 1024
PUBKEY_ENCLEN = 128
PUBKEY_PADLEN = 42
STREAM_FUNC = Crypto.Cipher.AES
STREAM_MODE = Crypto.Cipher.AES.MODE_CTR
STREAM_KEYLEN = 16
DH_LEN = 128
DH_SECLEN = 40
DH_G = 2
DH_P = 179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007L
CELL_LEN = 512
KEY_LEN = 16

torversion = re.compile('^Tor (\d+)\.(\d+)\.(\d+)\.(\d+)(?:-(alpha(?:-dev)?|beta|rc))?$')
torversionorder = [ 'alpha', 'alpha-dev', 'beta', 'rc', None ]
torminversionproto2 = [ 0, 2, 0, 21, None ]
torminversionproto3 = [ 0, 2, 3, 6, 'alpha' ]
torminversionextended2 = [ 0, 2, 4, 8, 'alpha' ]

def str2version(version):
    """
    Converts a string representing a Tor version to a list suitable
    for compare_versions().
    """
    v = torversion.search(version)
    if v is None:
        raise Exception('Unsupported version %s.' % version)
    v = list(v.groups())
    for i in xrange(4):
        v[i] = int(v[i])
    return v

def compare_versions(a, b):
    """
    This function is an equivalent to the built-in cmp() function
    for Tor versions as lists as returned by str2version().
    """
    if a[:4] < b[:4]:
        return -1
    if a[:4] > b[:4]:
        return 1
    return cmp(torversionorder.index(a[4]), torversionorder.index(b[4]))

# tor/src/or/config.c
DEFAULTDIRSERVERS = [
    "moria1 orport=9101 no-v2 "
      "v3ident=D586D18309DED4CD6D57C18FDB97EFA96D330566 "
      "128.31.0.39:9131 9695 DFC3 5FFE B861 329B 9F1A B04C 4639 7020 CE31",
    "tor26 v1 orport=443 v3ident=14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4 "
      "86.59.21.38:80 847B 1F85 0344 D787 6491 A548 92F9 0493 4E4E B85D",
    "dizum orport=443 v3ident=E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58 "
      "194.109.206.212:80 7EA6 EAD6 FD83 083C 538F 4403 8BBF A077 587D D755",
    "Tonga orport=443 bridge no-v2 82.94.251.203:80 "
      "4A0C CD2D DC79 9508 3D73 F5D6 6710 0C8A 5831 F16D",
    "turtles orport=9090 no-v2 "
      "v3ident=27B6B5996C426270A5C95488AA5BCEB6BCC86956 "
      "76.73.17.194:9030 F397 038A DC51 3361 35E7 B80B D99C A384 4360 292B",
    "gabelmoo orport=443 no-v2 "
      "v3ident=ED03BB616EB2F60BEC80151114BB25CEF515B226 "
      "212.112.245.170:80 F204 4413 DAC2 E02E 3D6B CF47 35A1 9BCA 1DE9 7281",
    "dannenberg orport=443 no-v2 "
      "v3ident=585769C78764D58426B8B52B6651A5A71137189A "
      "193.23.244.244:80 7BE6 83E6 5D48 1413 21C5 ED92 F075 C553 64AC 7123",
    "urras orport=80 no-v2 v3ident=80550987E1D626E3EBA5E5E75A458DE0626D088C "
      "208.83.223.34:443 0AD3 FA88 4D18 F89E EA2D 89C0 1937 9E0E 7FD9 4417",
    "maatuska orport=80 no-v2 "
      "v3ident=49015F787433103580E3B66A1707A00E60F2D15B "
      "171.25.193.9:443 BD6A 8292 55CB 08E6 6FBE 7D37 4836 3586 E46B 3810",
    "Faravahar orport=443 no-v2 "
      "v3ident=EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97 "
      "154.35.32.5:80 CF6D 0AAF B385 BE71 B8E1 11FC 5CFF 4B47 9237 33BC",
]

DIRECTORY_SERVERS = []
KNOWN_NODES = {}
CIRCUITS = {}

CELL_COMMANDS = {
    "PADDING": 0,
    "CREATE": 1,
    "CREATED": 2,
    "RELAY": 3,
    "DESTROY": 4,
    "CREATE_FAST": 5,
    "CREATED_FAST": 6,
    "VERSIONS": 7,
    "NETINFO": 8,
    "RELAY_EARLY": 9,
    "VPADDING": 128,
    "CERTS": 129,
    "AUTH_CHALLENGE": 130,
    "AUTHENTICATE": 131,
    "AUTHORIZE": 132
    }

class Cell(Packet):
    # Tor Protocol Specification, section 3
    name = "Tor Cell"
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 0, CELL_COMMANDS),
        StrFixedLenField("Payload", "", CELL_LEN - 3),
        ]
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        """
        This is used to guess which Cell type we have, according to
        the Command field, and for RELAY Cells, according to the
        RelayCommand field.
        This function is called either with _pkt being a string
        representing the packet's bytes, or with (multiple)
        field=value we get in kargs.
        """
        cmd = None
        if _pkt and len(_pkt) >= 3:
            cmd = struct.unpack("B", _pkt[2])[0]
        elif 'Command' in kargs:
            if type(kargs['Command']) is str:
                cmd = CELL_COMMANDS[kargs['Command']]
            elif type(kargs['Command']) is int:
                cmd = kargs['Command']
        if cmd in [3, 9]:
            relcmd = 0
            if _pkt:
                if len(_pkt) >= 6 and (struct.unpack("B", _pkt[3])[0] not in CELL_RELAY_COMMANDS.values()
                                       or _pkt[4:6] != '\x00\x00'):
                    return CellRelayEncrypted
            elif 'Recognized' in kargs:
                if kargs['RelayCommand'] == 0:
                    return CellRelayEncrypted
            if _pkt and len(_pkt) >= 4:
                relcmd = struct.unpack("B", _pkt[3])[0]
            elif 'RelayCommand' in kargs:
                if type(kargs['RelayCommand']) is str:
                    relcmd = CELL_RELAY_COMMANDS[kargs['RelayCommand']]
                elif type(kargs['RelayCommand']) is int:
                    relcmd = kargs['RelayCommand']
            if relcmd == 3:
                return CellRelayEnd
            if relcmd == 9:
                return CellRelayTruncated
            if relcmd == 12:
                return CellRelayResolved
            return CellRelay
        if cmd == 4:
            return CellDestroy
        if cmd == 7:
            return CellVersions
        if cmd == 8:
            return CellNetinfo
        if cmd == 129:
            return CellCerts
        if cmd >= 128:
            return CellVariable
        return Cell

class CellVariable(Cell):
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 0, CELL_COMMANDS),
        FieldLenField("Length", None, "Payload", fmt=">H"),
        StrLenField("Payload", "", length_from=lambda x: x.Length),
        ]

class CellVersions(CellVariable):
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 7, CELL_COMMANDS),
        FieldLenField("Length", None, "Versions", fmt=">H"),
        FieldListField('Versions', [],
                       ShortField("Version", 3),
                       length_from=lambda p: p.Length)
        ]

OR_CERT_TYPES = {
                "Link key": 1,
                "RSA1024 Identity": 2,
                "RSA1024 AUTHENTICATE cell link": 3
                }

class OrCert(Packet):
    name = "Or Certificate"
    fields_desc = [
        ByteEnumField('Type', 0, OR_CERT_TYPES),
        FieldLenField("Length", None, "Certificate", fmt=">H"),
        PacketField('Certificate', None, X509Cert)
        ]

class CellCerts(CellVariable):
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 129, CELL_COMMANDS),
        FieldLenField("Length", None, "Certificates", fmt=">H",
                      adjust=lambda (pkt, x): x+1),
        FieldLenField("NumberOfCerts", None, count_of="Certificates",
                      fmt="B"),
        FieldListField('Certificates', [],
                       PacketField('Cert', None, OrCert),
                       count_from=lambda p: p.NumberOfCerts)
        ]

class OrTimeStampField(IntField):
    def i2repr(self, pkt, val):
        if val is None:
            return "--"
        val = self.i2h(pkt,val)
        return time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime(val))
    def any2i(self, pkt, val):
        if type(val) is str:
            return int(time.mktime(time.strptime(val)))
        return IntField.any2i(self,pkt,val)
    def i2m(self, pkt, val):
        if val is None:
            val = IntField.any2i(self, pkt, time.time())
        return IntField.i2m(self, pkt, val)

OR_ADDRESS_TYPES = {
    'Hostname': 0x00,
    'IPv4': 0x04,
    'IPv6': 0x06,
    'TransientError': 0xf0,
    'NonTransientError': 0xf1,
    }

class OrAddress(Packet):
    name = "Or Address"
    fields_desc = [
        ByteEnumField('Type', 0, OR_ADDRESS_TYPES),
        FieldLenField("Length", None, "Address", fmt="B"),
        StrLenField("Address", "", length_from=lambda x: x.Length),
        ]
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        tpe = None
        if _pkt and len(_pkt) >= 2:
            tpe = struct.unpack("B", _pkt[1])[0]
        elif 'Type' in kargs:
            if type(kargs['Type']) is str:
                tpe = OR_ADDRESS_TYPES[kargs['Type']]
            elif type(kargs['Type']) is int:
                tpe = kargs['Type']
        if tpe == 4:
            return OrAddressIPv4
        return OrAddress

class OrAddressIPv4(OrAddress):
    name = "Or Address"
    fields_desc = [
        ByteEnumField('Type', 0x04, OR_ADDRESS_TYPES),
        FieldLenField("Length", None, "Address", fmt="B"),
        IPField("Address", None)
        ]

class CellNetinfo(Cell):
    name = "Tor Netinfo Cell"
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 8, CELL_COMMANDS),
        OrTimeStampField('Timestamp', None),
        PacketField('OtherOrAddress', None, OrAddress),
        FieldLenField('NumberOfAddresses', None, fmt="B",
                      count_of="ThisOrAddresses"),
        FieldListField('ThisOrAddresses', [],
                       PacketField('ThisOr', None, OrAddress),
                       count_from=lambda p: p.NumberOfAddresses),
        StrFixedLenField("Padding", "", length_from=lambda x: CELL_LEN - 8 - len(x.OtherOrAddress) - sum(map(len, x.ThisOrAddresses)))
        ]

CELL_RELAY_COMMANDS = {
    "RELAY_BEGIN": 1,
    "RELAY_DATA": 2,
    "RELAY_END": 3,
    "RELAY_CONNECTED": 4,
    "RELAY_SENDME": 5,
    "RELAY_EXTEND": 6,
    "RELAY_EXTENDED": 7,
    "RELAY_TRUNCATE": 8,
    "RELAY_TRUNCATED": 9,
    "RELAY_DROP": 10,
    "RELAY_RESOLVE": 11,
    "RELAY_RESOLVED": 12,
    "RELAY_BEGIN_DIR": 13,
    }

class CellRelay(Cell):
    name = "Tor Relay Cell"
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 3, CELL_COMMANDS),
        ByteEnumField('RelayCommand', 1, CELL_RELAY_COMMANDS),
        ShortField('Recognized', 0),
        ShortField('StreamID', 0),
        StrFixedLenField('Digest', '', 4),
        FieldLenField("Length", None, "Data", fmt=">H"),
        StrLenField("Data", "", length_from=lambda x: x.Length),
        StrFixedLenField("Padding", "", length_from=lambda x: CELL_LEN - 14 - len(x.Data))
        ]

class CellRelayEncrypted(CellRelay):
    name = "Tor Relay Cell (encrypted)"
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 3, CELL_COMMANDS),
        StrFixedLenField("EncryptedData", "", length=CELL_LEN - 3)
        ]

class CellRelayResolved(Cell):
    name = "Tor Relay/Resolved Cell"
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 3, CELL_COMMANDS),
        ByteEnumField('RelayCommand', 12, CELL_RELAY_COMMANDS),
        ShortField('Recognized', 0),
        ShortField('StreamID', 0),
        StrFixedLenField('Digest', '', 4),
        FieldLenField("Length", None, "Address", fmt=">H",
                      adjust=lambda pkt, x: x+4),
        PacketField('Address', None, OrAddress),
        IntField("TTL", 0),
        StrFixedLenField("Padding", "", length_from=lambda x: CELL_LEN - 18 - len(x.Address))
        ]

CELL_RELAYEND_REASONS = {
    "REASON_MISC": 1,
    "REASON_RESOLVEFAILED": 2,
    "REASON_CONNECTREFUSED": 3,
    "REASON_EXITPOLICY": 4,
    "REASON_DESTROY": 5,
    "REASON_DONE": 6,
    "REASON_TIMEOUT": 7,
    "REASON_NOROUTE": 8,
    "REASON_HIBERNATING": 9,
    "REASON_INTERNAL": 10,
    "REASON_RESOURCELIMIT": 11,
    "REASON_CONNRESET": 12,
    "REASON_TORPROTOCOL": 13,
    "REASON_NOTDIRECTORY": 14,
    }

class CellRelayEnd(Cell):
    name = "Tor Relay/End Cell"
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 3, CELL_COMMANDS),
        ByteEnumField('RelayCommand', 3, CELL_RELAY_COMMANDS),
        ShortField('Recognized', 0),
        ShortField('StreamID', 0),
        StrFixedLenField('Digest', '', 4),
        ShortField('Length', 1),
        ByteEnumField('Reason', 0, CELL_RELAYEND_REASONS),
        StrFixedLenField("Padding", "", length_from=lambda x: CELL_LEN - 14)
        ]

CELL_DESTROY_CODES = {
    "NONE": 0,
    "PROTOCOL": 1,
    "INTERNAL": 2,
    "REQUESTED": 3,
    "HIBERNATING": 4,
    "RESOURCELIMIT": 5,
    "CONNECTFAILED": 6,
    "OR_IDENTITY": 7,
    "OR_CONN_CLOSED": 8,
    "FINISHED": 9,
    "TIMEOUT": 10,
    "DESTROYED": 11,
    "NOSUCHSERVICE": 12,
    }

class CellRelayTruncated(Cell):
    name = "Tor Relay/End Cell"
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 3, CELL_COMMANDS),
        ByteEnumField('RelayCommand', 9, CELL_RELAY_COMMANDS),
        ShortField('Recognized', 0),
        ShortField('StreamID', 0),
        StrFixedLenField('Digest', '', 4),
        ShortField('Length', 1),
        ByteEnumField('ErrorCode', 0, CELL_DESTROY_CODES),
        StrFixedLenField("Padding", "", length_from=lambda x: CELL_LEN - 14)
        ]

class CellDestroy(Cell):
    name = "Tor Destroy Cell"
    fields_desc = [
        ShortField('CircID', 0),
        ByteEnumField('Command', 4, CELL_COMMANDS),
        ByteEnumField('ErrorCode', 0, CELL_DESTROY_CODES),
        StrFixedLenField('Padding', "", CELL_LEN - 4)
        ]

bind_layers(OrCert, Padding)
bind_layers(X509Cert, Padding)
bind_layers(OrAddress, Padding)
bind_layers(Cell, Padding)

def superpack(val, blen):
    x = hex(val)[2:].rstrip('L')
    if len(x) % 2: x = '0' + x
    x = x.decode('hex')
    if len(x) > blen:
        raise ValueError('Value %d does not fit in %d bytes.' % (val, blen))
    if len(x) < blen:
        x = '\x00' * (blen - len(x)) + x
    return x

def superb64dec(x):
    for i in [ '', '=', '==' ]:
        try:
            return (x+i).decode('base64')
        except:
            pass

class TorNode:
    def __init__(self, name, address, digest=None):
        self.name = name
        self.address = address
        self.digest = digest
        if digest is not None:
            if digest in KNOWN_NODES:
                print "WARNING: node %s already present." % digest.encode('hex')
            KNOWN_NODES[digest] = self
    def __repr__(self):
        return '<Node %s at %s:%d [digest=%s]%s>' % ((self.name,) + self.address + (self.digest.encode('hex'), hasattr(self, 'diraddr') and ' DS' or ''))
    def onionkeyinit(self, onionpubkey):
        self.onionpubkey = cert._EncryptAndVerify()
        self.onionpubkey.key = PUBKEY_FUNC.construct(onionpubkey)
        self.onionpubkey.modulus = onionpubkey[0]
        self.onionpubkey.modulusLen = PUBKEY_MODSIZE
        """
        try:
            self.pubkey = Cert(str(self.certificates[OR_CERT_TYPES['Link key']]))
        except:
            # workaround output mismatch between scapy and openssl
            print "WARNING: your scapy version does not understand the output of openssl"
            self.pubkey = cert._EncryptAndVerify()
            pubkey = [ x.val for x in ASN1_Codecs.BER.dec(self.certificates[OR_CERT_TYPES['Link key']].pubkey.val[1:])[0].val]
            self.pubkey.key = PUBKEY_FUNC.construct(pubkey)
            self.pubkey.modulus = pubkey[0]
            self.pubkey.modulusLen = PUBKEY_MODSIZE
            """
    def onionpubkeyencrypt(self, message):
        return self.onionpubkey.encrypt(message, t='oaep', h=HASH_NAME)
    def streamencrypt(self, message, key):
        # this one is only used with a random key by hybridencrypt()
        self.streamcounter = 0
        def counter():
            self.streamcounter += 1
            return superpack(self.streamcounter - 1, 16)
        r = STREAM_FUNC.new(key, mode=STREAM_MODE,
                            counter=counter
                            ).encrypt(message)
        return r
    def hybridencrypt(self, message):
        if len(message) < PUBKEY_ENCLEN - PUBKEY_PADLEN:
            return self.onionpubkeyencrypt(message)
        key = randstring(STREAM_KEYLEN)
        m1 = message[:PUBKEY_ENCLEN - PUBKEY_PADLEN - STREAM_KEYLEN]
        m2 = message[PUBKEY_ENCLEN - PUBKEY_PADLEN - STREAM_KEYLEN:]
        return self.onionpubkeyencrypt(key+m1) + self.streamencrypt(m2, key)

DIRSERVER_FLAGS = {
    'NO_DIRINFO': 0,
    # Serves/signs v1 directory information: Big lists of routers, and short
    # routerstatus documents.
    'V1_DIRINFO': 1 << 0,
    # Serves/signs v2 directory information: i.e. v2 networkstatus documents
    'V2_DIRINFO': 1 << 1,
    # Serves/signs v3 directory information: votes, consensuses, certs
    'V3_DIRINFO': 1 << 2,
    # Serves hidden service descriptors.
    'HIDSERV_DIRINFO': 1 << 3,
    # Serves bridge descriptors.
    'BRIDGE_DIRINFO': 1 << 4,
    # Serves extrainfo documents.
    'EXTRAINFO_DIRINFO': 1 << 5,
    # Serves microdescriptors.
    'MICRODESC_DIRINFO': 1 << 6
}

class DirectoryServer(TorNode):
    def __init__(self, line):
        self.dirflags = DIRSERVER_FLAGS['V2_DIRINFO']
        self.documents = {}
        line = line.split()
        name = line.pop(0)
        isnothidservauth = False
        isnotv2auth = False
        while line:
            x = line.pop(0)
            if x[0].isdigit():
                line.insert(0, x)
                break
            if x.lower() == 'v1':
                self.dirflags |= DIRSERVER_FLAGS['V1_DIRINFO']
            elif x.lower() == 'hs':
                self.dirflags |= DIRSERVER_FLAGS['HIDSERV_DIRINFO']
            elif x.lower() == 'no-hs':
                isnothidservauth = True
            elif x.lower() == 'bridge':
                self.dirflags |= DIRSERVER_FLAGS['BRIDGE_DIRINFO']
            elif x.lower() == 'no-v2':
                isnotv2auth = True
            elif x.lower().startswith('orport='):
                orport = int(x[7:])
            elif x.lower().startswith('v3ident='):
                self.dirflags |= (DIRSERVER_FLAGS['V3_DIRINFO']|DIRSERVER_FLAGS['EXTRAINFO_DIRINFO']|DIRSERVER_FLAGS['MICRODESC_DIRINFO'])
                self.v3digest = x[8:].decode('hex')
        if not isnothidservauth:
            self.dirflags &= ~DIRSERVER_FLAGS['HIDSERV_DIRINFO']
        if not isnotv2auth:
            self.dirflags &= ~DIRSERVER_FLAGS['V2_DIRINFO']
        (addr, dirport) = line.pop(0).split(':', 1)
        self.diraddr = (addr, int(dirport))
        TorNode.__init__(self, name, (addr, orport),
                         digest=''.join(line).decode('hex'))
    def retrieve_doc(self, doc, refresh=False):
        if not refresh and doc in self.documents:
            return
        host = self.diraddr[0]
        if self.diraddr[1] != 80:
            host += ':%d' % self.diraddr[1]
        req = urllib2.Request('http://%s/tor/%s' % (host, doc),
                              headers={})
        f = urllib2.urlopen(req)
        self.documents[doc] = (f.code, f.msg, f.read())
        return f.code
    def parse_consensus(self, refresh=False):
        self.retrieve_doc('status-vote/current/consensus' , refresh=refresh)
        consensus = self.documents['status-vote/current/consensus'][2]
        consensus = consensus[consensus.index('\nr ')+3:consensus.index('\ndirectory-footer\n')]
        for l in consensus.split('\nr '):
            h, l = l.split('\n', 1)
            nickname, identity, digest, pub1, pub2, address, orport, dirport = h.split(' ')
            identity = superb64dec(identity)
            digest = superb64dec(digest)
            publication = time.strptime(pub1+' '+pub2, '%Y-%m-%d %H:%M:%S')
            diraddr = (address, int(dirport))
            address = (address, int(orport))
            addresses6 = []
            for i in l.split('\n'):
                if i.startswith('s '):
                    flags = i[2:].split(' ')
                elif i.startswith('v '):
                    version = i[2:]
                elif i.startswith('w '):
                    weight = dict([x.split('=', 1) for x in i[2:].split(' ')])
                elif i.startswith('p '):
                    policy = i[2:]
                elif i.startswith('a ['):
                    a6 = i[3:].split(']:', 1)
                    addresses6.append((a6[0], int(a6[1])))
                    del(a6)
                else:
                    print "WARNING: line not recognized [%r], node [%r]" % (i, nickname)
            # FIXME we should initialise w/ DirectoryServer when
            # possible
            if identity not in KNOWN_NODES:
                t = TorNode(nickname, address, digest=identity)
                if dirport != "0":
                    t.diraddr = diraddr
                t.orflags = flags
                t.version = version
                t.weight = weight
                t.policy = policy
            else:
                t = KNOWN_NODES[identity]
                if t.name != nickname:
                    print "WARNING: host %s has changed its name [%r -> %r]" % (identity.encode('hex'), t.name, nickname)
                    t.name = nickname
                if t.address != address:
                    print "WARNING: host %s has changed its address [%s:%d -> %s:%d]" % ((identity.encode('hex'),) + t.address + address)
                    t.address = address
                if dirport != "0":
                    if hasattr(t, "diraddr"):
                        if t.diraddr != diraddr:
                            print "WARNING: host %s has changed its Directory Server port [%s:%d -> %s:%d]" % ((identity.encode('hex'),) + t.diraddr + diraddr)
                            t.diraddr = diraddr
                    else:
                        print "WARNING: host %s now has a Directory Server port [%s:%d]" % ((identity.encode('hex'),) + diraddr)
                        t.diraddr = diraddr
                if addresses6:
                    if hasattr(t, 'addresses6'):
                        if t.addresses6 != addresses6:
                            print "WARNING: host %s has changed its IPv6 address list [%r -> %r]" % (identity.encode('hex'), t.addresses6, addresses6)
                            t.addresses6 = addresses6
                    else:
                        print "WARNING: host %s now has an IPv6 address list [%r]" % (identity.encode('hex'), addresses6)
                        t.addresses6 = addresses6
                elif hasattr(t, 'addresses6'):
                    if t.addresses6:
                        print "WARNING: host %s no longer has an IPv6 address list (was [%r])" % t.addresses6
                    del(t.addresses6)
                if hasattr(t, 'orflags'):
                    if t.orflags != flags:
                        print "WARNING: host %s has changed its OR flags [%s -> %s]" % (identity.encode('hex'), t.orflags, flags)
                        t.orflags = flags
                else:
                    t.orflags = flags
                if hasattr(t, 'version'):
                    if t.version != version:
                        print "WARNING: host %s has changed its version [%s -> %s]" % (identity.encode('hex'), t.version, version)
                        t.version = version
                else:
                    t.version = version
                if hasattr(t, 'weight'):
                    if t.weight != weight:
                        print "NOTICE: host %s has a different weight [%s -> %s]" % (identity.encode('hex'), t.weight, weight)
                        t.weight = weight
                else:
                    t.weight = weight
                if hasattr(t, 'policy'):
                    if t.policy != policy:
                        print "WARNING: host %s has changed its policy [%s -> %s]" % (identity.encode('hex'), t.policy, policy)
                        t.policy = policy
                else:
                    t.policy = policy
    def get_node_info(self, identity, refresh=False):
        self.retrieve_doc('server/fp/' + identity.encode('hex') , refresh=refresh)
        infos = self.documents['server/fp/' + identity.encode('hex')]
        if infos[0] != 200:
            raise Exception("Error when getting node information for %s: HTTP code %d." % (identity.encode('hex'), infos[0]))
        infos = infos[2]
        if identity in KNOWN_NODES:
            node = KNOWN_NODES[identity]
            onionkey = infos[infos.index('\nonion-key\n')+42:]
            onionkey = onionkey[:onionkey.index('\n-----END RSA PUBLIC KEY-----\n')+1]
            onionkey = ASN1_Codecs.BER.dec(onionkey.decode('base64'))[0]
            node.onionkeyinit([x.val for x in onionkey.val])
            node.allinfos = infos

class TorHop:
    """
    This object contains the information (e.g., cryptographic
    material) for one TorNode in a Circuit.
    """
    def __init__(self, node, **kargs):
        self.node = node
        self.init = kargs
        if 'X' in self.init and 'Y' in self.init:
            # CREATE_FAST
            self.K0 = self.init['X'] + self.init['Y']
        elif ('x' in self.init or 'gx' in self.init) and 'gy' in self.init:
            if 'x' in self.init and 'gx' not in self.init:
                self.init['gx'] = pow(DH_G, self.init['x'], DH_P)
            self.K0 = superpack(pow(self.init['gy'], self.init['x'],
                                    DH_P), DH_LEN)
        self.K = ''
        i = 0
        while len(self.K) < 2 * KEY_LEN + 3 * HASH_LEN:
            self.K += HASH_FUNC.new(self.K0 + chr(i)).digest()
            i += 1
        self.KH = self.K[:HASH_LEN]
        self.Df = self.K[HASH_LEN:2*HASH_LEN]
        self.Db = self.K[2*HASH_LEN:3*HASH_LEN]
        self.Kf = self.K[3*HASH_LEN:3*HASH_LEN+KEY_LEN]
        self.Kb = self.K[3*HASH_LEN+KEY_LEN:3*HASH_LEN+2*KEY_LEN]
        if 'KH' in self.init and self.KH != self.init['KH']:
            raise Exception('Computed KH differs from data sent by peer.')
        self.Dffunc = HASH_FUNC.new(self.Df)
        self.Dbfunc = HASH_FUNC.new(self.Db)
        self.Kfctr = 0
        def fctr():
            self.Kfctr += 1
            return superpack(self.Kfctr - 1, 16)
        self.Kffunc = STREAM_FUNC.new(self.Kf, mode=STREAM_MODE, counter=fctr)
        self.Kbctr = 0
        def bctr():
            self.Kbctr += 1
            return superpack(self.Kbctr - 1, 16)
        self.Kbfunc = STREAM_FUNC.new(self.Kb, mode=STREAM_MODE, counter=bctr)

class Circuit:
    """
    This object represents a Circuit in a connection (e.g. a
    TorSocket).

    Its main attributes are circid (an integer used to discriminate
    multiple circuits sharing a connection), hops (an ordered list of
    TorHop objects, the first being the entry node and the last the
    exit node), and socket, the TorSocket used to send and receive the
    packets.
    """
    def __init__(self, circid, socket):
        self.circid = circid
        self.hops = []
        self.socket = socket
        CIRCUITS[circid] = self
    def stream_encrypt(self, message, nodeindex, direction='f'):
        """
        Encrypts a message to the nodeindex-th hop of the circuit
        according to the direction ('f' means 'forward', e.g., from us
        to the hop, and 'b' means 'backward', from the hop to us).

        You should not use this method, but rather see encrypt_cell()
        and decrypt_cell(), which will call this method for each hop
        in the circuit.
        """
        if direction == 'f':
            return self.hops[nodeindex].Kffunc.encrypt(message)
        elif direction == 'b':
            return self.hops[nodeindex].Kbfunc.encrypt(message)
    def encrypt_cell(self, cell, tohop=None, computedigest=True):
        """
        Encrypts a Cell successively for each node in the circuit,
        starting with the exit (or last) node and ending with the
        entry node.

        If computedigest is True, computes the valid Digets field
        according to the last node before encrypting.
        """
        if computedigest and isinstance(cell, CellRelay):
            cell.Digest = '\x00' * 4
            h = self.hops[-1].Dffunc
            h.update(str(cell)[3:])
            cell.Digest = h.digest()[:4]
        cell = str(cell)
        result = cell[3:]
        if tohop is None: tohop = len(self.hops) - 1
        for i in xrange(tohop, -1, -1):
            result = self.stream_encrypt(result, i, direction='f')
        return cell[:3] + result
    def decrypt_cell(self, cell, fromhop=None):
        """
        Decrypts a Cell successively for each node in the circuit,
        starting with the entry node and ending with the exit (or last)
        node.
        """
        cell = str(cell)
        result = cell[3:]
        if fromhop is None: fromhop = len(self.hops) - 1
        for i in xrange(fromhop + 1):
            result = self.stream_encrypt(result, i, direction='b')
        return Cell(cell[:3] + result)
    def extend(self, node, use_relay_early=True):
        """
        This method is similar to TorSocket.create (no "fast" mode
        here), except it extends the circuit (adds a new hop at the
        end of it) instead of creating it.

        If use_relay_early is set to False, a CellRelay with Command
        "RELAY", instead of "RELAY_EARLY", will be used.

        The only use case for a "RELAY" Command instead of
        "RELAY_EARLY" (beside testing) is to create very long
        circuits, because according to tor-spec, section 5.6: "If a
        node ever receives more than 8 RELAY_EARLY cells on a given
        outbound circuit, it SHOULD close the circuit."

        But: "[Starting with Tor 0.2.3.11-alpha, future version of
        Tor, relays should reject any EXTEND cell not received in a
        RELAY_EARLY cell.]"
        """
        streamid = RandShort()._fix()
        local_keymaterial = random.randint(0, 256 ** DH_SECLEN - 1)
        local_DHpubkey = pow(DH_G, local_keymaterial, DH_P)
        command = (use_relay_early and "RELAY_EARLY" or "RELAY")
        self.socket.send(Raw(self.encrypt_cell(
                    # tor-spec 5.6:
                    # [Starting with Tor 0.2.3.11-alpha, future
                    # version of Tor, relays should reject any EXTEND
                    # cell not received in a RELAY_EARLY cell.]
                    CellRelay(Command=command,
                              CircID=self.circid,
                              RelayCommand='RELAY_EXTEND',
                              StreamID=streamid,
                              Data=socket.inet_aton(node.address[0]) + struct.pack('>H', node.address[1]) + node.hybridencrypt(superpack(local_DHpubkey, DH_LEN)) + node.digest))))
        cell = self.socket.recv_cell("RELAY")
        global errorcell
        errorcell = cell.copy()
        if isinstance(cell, CellRelayEncrypted):
            cell = self.decrypt_cell(cell)
        global errorcellclear
        errorcellclear = cell.copy()
        if cell.RelayCommand != 7: # RELAY_EXTENDED
            raise Exception('Expected RELAY_EXTENDED, got %d [%s]' % cell.RelayCommand, cell.sprintf('%RelayCommand%'))
        del(errorcell)
        del(errorcellclear)
        peer_keymaterial = int(cell.Data[:DH_LEN].encode('hex'), 16)
        peer_derivativekeydata = cell.Data[DH_LEN:DH_LEN+HASH_LEN]
        hop = TorHop(node, x=local_keymaterial, gx=local_DHpubkey,
                     gy=peer_keymaterial, KH=peer_derivativekeydata)
        self.hops.append(hop)
    def destroy(self, reason=0):
        """
        Tears down the Circuit.
        """
        self.socket.send(CellDestroy(CircID=self.circid,
                                     ErrorCode=reason))
    def resolve(self, name):
        """
        Resolves a name (that can be a .in-addr.arpa address) through
        the Circuit.
        """
        streamid = RandShort()._fix()
        self.socket.send(Raw(self.encrypt_cell(
                    CellRelay(CircID=self.circid,
                              RelayCommand="RELAY_RESOLVE",
                              StreamID=streamid,
                              Data=name))))
        r = self.decrypt_cell(self.socket.recv_cell("RELAY"))
        return r.Address, r.TTL
    def connect(self, address, streamid=None):
        """
        Connects to an address through the Circuit. If streamid is
        None, a random one will be chosen.
        """
        if streamid is None:
            streamid = RandShort()._fix()
        self.socket.send(Raw(self.encrypt_cell(
                    CellRelay(CircID=self.circid,
                              RelayCommand="RELAY_BEGIN",
                              StreamID=streamid,
                              Data="%s:%d\x00" % (address)))))
        r = self.decrypt_cell(self.socket.recv_cell("RELAY"))
        # TODO: check the answer
        return streamid, r
    def send(self, streamid, data):
        """
        Sends data in the selected stream through the Circuit. This
        will require data to be split into several cells if it's too
        long.
        """
        while data:
            self.socket.send(Raw(self.encrypt_cell(
                        CellRelay(CircID=self.circid,
                                  RelayCommand="RELAY_DATA",
                                  StreamID=streamid,
                                  Data=data[:CELL_LEN - 14]))))
            data = data[CELL_LEN - 14:]
    def recv(self):
        """
        Receives data from the Circuit, and returns a tuple with the
        streamid as first element and the data received as second
        element.
        """
        r = self.decrypt_cell(self.socket.recv_cell("RELAY"))
        if r.RelayCommand == 2: # RELAY_DATA:
            return (r.CircID, r.Data)
        if r.RelayCommand == 3: # RELAY_END
            print r.sprintf("WARNING: circuit %CircID% closed (%Reason%)")
            return (r.CircID, '')
        print r.sprintf("WARNING: circuit %CircID% sent unhandled RelayCommand (%RelayCommand%)")
        return (r.CircID, r)

class TorSocket(StreamSocket):
    """
    A socket used to connect to an entry node.

    The __init__ method will establish the TCP + SSL/TLS connection.
    """
    desc = "Tor Socket"
    def __init__(self, node, version=3, ssl_version=ssl.PROTOCOL_TLSv1):
        self.node = node
        self.version = version
        self.circuits = []
        if version in [ 1, 2 ]:
            raise Exception('Version %d not implemented yet.' % version)
        if version == 3:
            self.__origsocket = socket.socket()
            self.__origsocket.connect(node.address)
            sock = ssl.wrap_socket(self.__origsocket, ssl_version=ssl_version)
            self.peer_sslcertificate = X509Cert(sock.getpeercert(binary_form=True))
        StreamSocket.__init__(self, sock, basecls=Cell)
        self.__beforerecv = ''
    def recv(self, x=4096):
        """
        This is an attempt to provide an equivalent to the
        StreamSocket.recv() method, without using socket.MSG_PEEK flag, which
        is not available on SSL sockets.

        This part is Tor-specific as it makes use of the Length
        attribute of the Cell packet to guess whether or not we have
        read enough data.
        """
        read_enough = False
        if len(self.__beforerecv) >= 5:
            cmd = struct.unpack("B", self.__beforerecv[2])[0]
            if cmd < 128 and cmd != 7:
                cellsize = 512
            else:
                cellsize = 5 + struct.unpack(">H", self.__beforerecv[3:5])[0]
            if len(self.__beforerecv) >= cellsize:
                read_enough = True
        if not read_enough and len(self.__beforerecv) < x:
            pkt = self.__beforerecv + self.ins.recv(x-len(self.__beforerecv))
            self.__beforerecv = ''
        else:
            pkt = self.__beforerecv[:x]
            self.__beforerecv = self.__beforerecv[x:]
        x = len(pkt)
        if x == 0:
            raise socket.error((100,"Underlying stream socket tore down."))
        pkt = self.basecls(pkt)
        if Padding in pkt:
            pad = pkt[Padding]
            if pad is not None and pad.underlayer is not None:
                del(pad.underlayer.payload)
            beforerecv = ''
            while pad is not None and not isinstance(pad, NoPayload):
                beforerecv += str(pad.load)
                pad = pad.payload
            self.__beforerecv = beforerecv + self.__beforerecv
        return pkt
    def recv_cell(self, cmd=None):
        """
        Receives one cell from the socket, ignoring Padding cells.
        """
        cell = self.recv()
        while cell.Command == CELL_COMMANDS['PADDING']:
            cell = self.recv()
        if cmd is not None:
            if type(cmd) is str: cmd = CELL_COMMANDS[cmd]
            if cell.Command != cmd:
                global errorcell
                errorcell = cell
                raise Exception("Peer answer error: expected command %s, got %s." % (Cell(Command=cmd).sprintf('%Command%'), cell.sprintf('%Command%')))
        return cell
    def init_connection(self):
        """
        Sends and receives required cells prior to the creation of a
        circuit.
        """
        # We init the session by negotiating protocol version
        self.send(Cell(Command="VERSIONS", Versions=[self.version]))
        # We get the versions supported by the peer
        self.node.versions = self.recv_cell(cmd="VERSIONS").Versions
        if self.version not in self.node.versions:
            raise Exception("Peer does not seem to support version %d (only supports %s)." % (self.version, ', '.join(self.node.versions)))
        # Then its certificates
        self.node.certificates = dict([(x.Type, x.Certificate) for x in self.recv_cell(cmd="CERTS").Certificates])
        if self.peer_sslcertificate != self.node.certificates[OR_CERT_TYPES['Link key']]:
            raise Exception("Peer's CERTS cell did not include the certificate used for SSL connection.")
        # The authentication challenge
        self.peer_authchallenge = self.recv_cell()
        # And the NETINFO cell...
        cell = self.recv_cell(cmd="NETINFO")
        # ...with our public address...
        self.public_address = cell.OtherOrAddress
        # ... and the peer's addresses
        self.node.addresses = cell.ThisOrAddresses
        if self.node.address[0] not in [ x.Address for x in self.node.addresses ]:
            sys.stderr.write("WARNING: we are connected to %s, which is not listed in its announced addresses [%s].\n" % (self.node.address[0], ', '.join([ x.Address for x in self.node.addresses ])))
        # We send him our NETINFO cell
        self.send(Cell(Command='NETINFO',
                       OtherOrAddress=OrAddress(Type=4,
                                                Address=self.ins.getpeername()[0]),
                       ThisOrAddresses = [self.public_address]))
        # We are ready !
    def create(self, fast=True, circid=None):
        """
        Creates a circuit, using fast mode by default.
        """
        if circid is None:
            while True:
                circid = RandShort()._fix()
                if circid not in CIRCUITS: break
        if fast:
            # This is X (cf. 5.1.1)
            local_keymaterial = randstring(HASH_LEN)
            self.send(Cell(CircID=circid,
                           Command='CREATE_FAST',
                           Payload=local_keymaterial))
            cell = self.recv_cell(cmd='CREATED_FAST')
            # This is Y (cf. 5.1.1)
            peer_keymaterial = cell.Payload[:HASH_LEN]
            peer_derivativekeydata = cell.Payload[HASH_LEN:2*HASH_LEN]
            hop = TorHop(self.node, X=local_keymaterial, Y=peer_keymaterial,
                         KH=peer_derivativekeydata)
        else:
            local_keymaterial = random.randint(0, 256 ** DH_SECLEN - 1)
            local_DHpubkey = pow(DH_G, local_keymaterial, DH_P)
            self.send(Cell(CircID=circid,
                           Command='CREATE',
                           Payload=self.node.hybridencrypt(superpack(local_DHpubkey, DH_LEN))))
            cell = self.recv_cell(cmd='CREATED')
            peer_keymaterial = int(cell.Payload[:DH_LEN].encode('hex'), 16)
            peer_derivativekeydata = cell.Payload[DH_LEN:DH_LEN+HASH_LEN]
            hop = TorHop(self.node, x=local_keymaterial, gx=local_DHpubkey,
                         gy=peer_keymaterial, KH=peer_derivativekeydata)
        circuit = Circuit(circid, self)
        circuit.hops = [ hop ]
        self.circuits.append(circuit)
        return circuit

def add_default_directory_authorities():
    """
    Uses hard-coded information to add the initial directory
    servers.
    """
    for l in DEFAULTDIRSERVERS:
        DIRECTORY_SERVERS.append(DirectoryServer(l))

def search_node(flags=['Fast', 'Exit', 'Running'], minversion=None,
                maxversion=None, ipv6=False):
    """
    Finds nodes matching flags and version requirements.
    """
    r = []
    for n in KNOWN_NODES:
        if hasattr(KNOWN_NODES[n], 'orflags') and all([x in KNOWN_NODES[n].orflags for x in flags]):
            if minversion is not None or maxversion is not None:
                v = str2version(KNOWN_NODES[n].version)
                if v is not None:
                    if minversion is not None and compare_versions(v, minversion) < 1:
                        continue
                    if maxversion is not None and compare_versions(v, maxversion) > 1:
                        continue
            if ipv6 and not KNOWN_NODES[n].addresses6:
                continue
            r.append(n)
    return r
