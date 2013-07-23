#! /usr/bin/env python

import torpylle
import sys
import signal

class AlarmException(Exception):
    pass

def alarmhandler(signum, frame):
    raise AlarmException()

signal.signal(signal.SIGALRM, alarmhandler)

BASE_TIMEOUT = 10

# to run with -i flag on python interpreter
import atexit
import os
import readline
import rlcompleter
historyPath = os.path.expanduser("~/.torpylle_history")

def save_history(historyPath=historyPath):
    import readline
    readline.write_history_file(historyPath)

if os.path.exists(historyPath):
    readline.read_history_file(historyPath)

readline.parse_and_bind('tab: complete')
atexit.register(save_history)
del os, atexit, readline, rlcompleter, save_history, historyPath

# directory manipulation
print "Adding default directory servers...",
torpylle.add_default_directory_authorities()
print "[OK]"

while True:
    try:
        signal.alarm(BASE_TIMEOUT)
        d = torpylle.random.choice(torpylle.DIRECTORY_SERVERS)
        print "Getting consensus from a random server [%s:%d]..." % d.address,
        sys.stdout.flush()
        d.parse_consensus()
        signal.alarm(0)
        print "[DONE]"
        signal.alarm(BASE_TIMEOUT)
        print "Selecting an entry node and getting infos...",
        sys.stdout.flush()
        # our entry node should be a Guard, Fast and Running node with
        # a version compatible with protocol 3.
        n1 = torpylle.random.choice(torpylle.search_node(
                flags=['Fast', 'Running', 'Guard'],
                minversion=torpylle.torminversionproto3))
        d.get_node_info(n1)
        print "[OK]"
        signal.alarm(BASE_TIMEOUT)
        print "Connecting to the entry node [%s:%d]..." % torpylle.KNOWN_NODES[n1].address,
        sys.stdout.flush()
        s = torpylle.TorSocket(torpylle.KNOWN_NODES[n1])
        print "[OK]"
        print "Initiating connection...",
        sys.stdout.flush()
        s.init_connection()
        print "[OK]"
        signal.alarm(0)
        print "Entry node certificates:"
        for c in s.node.certificates:
            print "    ", c, s.node.certificates[c].subject[0].value.val, 'issued by', s.node.certificates[c].issuer[0].value.val
        print
        print "IP Addresses:"
        print "    ", "I am %s" % s.public_address.Address
        print "    ", "Peer is %s" % ', '.join([x.Address for x in s.node.addresses])
        print
        signal.alarm(BASE_TIMEOUT)
        print "Creating circuit...",
        sys.stdout.flush()
        c = s.create(fast=False)
        print "[OK]"
        signal.alarm(BASE_TIMEOUT)
        print "Selecting an exit node and getting infos...",
        sys.stdout.flush()
        # our exit node shoub be an Exit, Fast and Running node.
        n2 = torpylle.random.choice(torpylle.search_node(flags=['Fast', 'Exit', 'Running']))
        d.get_node_info(n2)
        print "[OK]"
        signal.alarm(4 * BASE_TIMEOUT)
        print "Extending circuit [%s:%d]..." % torpylle.KNOWN_NODES[n2].address,
        sys.stdout.flush()
        c.extend(torpylle.KNOWN_NODES[n2])
        print "[OK]"
        signal.alarm(BASE_TIMEOUT)
        print "Resolving www.google.com",
        sys.stdout.flush()
        rslv = c.resolve("www.google.com")
        print "[OK]",
        print rslv[0].Address
        signal.alarm(2 * BASE_TIMEOUT)
        print "Connecting to www.google.com and GETting /",
        sys.stdout.flush()
        strm = c.connect((rslv[0].Address, 80))
        c.send(strm[0], 'GET / HTTP/1.0\r\n\r\n')
        data = ''
        da = c.recv()[1]
        while da:
            data += da
            da = c.recv()[1]
        print "[OK]"
        signal.alarm(0)
        print data[:80]
        if len(data) > 80:
            print '[...]'
        break
    except AlarmException:
        print "[TIMEOUT]"
        print
    except Exception as e:
        print "[ERROR] %s" % e.message
        if hasattr(torpylle, "errorcell"):
            print "Cell:", repr(torpylle.errorcell)
            del(torpylle.errorcell)
        if hasattr(torpylle, "errorcellclear"):
            print "Clear Cell:", repr(torpylle.errorcellclear)
            del(torpylle.errorcellclear)
        print
