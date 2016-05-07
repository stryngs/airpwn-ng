from Queue import Queue, Empty
from threading import Thread
from scapy.all import *
import binascii, fcntl, gzip, socket, struct, sys, time
import sqlite3 as lite

class Database(object):
    """database logs"""

    def __init__(self):
        ## DB the cookies
        self.con = lite.connect('cookies.db')
        self.con.text_factory = str
        self.db = self.con.cursor()
        self.db.execute("CREATE TABLE IF NOT EXISTS ip2mac(ip TEXT, mac TEXT, UNIQUE(ip, mac))")
        self.db.execute("CREATE TABLE IF NOT EXISTS cookies(ip TEXT, dm TEXT, ck TEXT)")

    def sqlite(self, ip, mac, dm, cookie):
        with self.con:
            self.db.execute("INSERT OR IGNORE INTO ip2mac VALUES(?, ?);", (ip, mac))
            self.db.execute("INSERT OR IGNORE INTO cookies VALUES(?, ?, ?);", (ip, dm, cookie))


class Logfile(object):
    """Plaintext logs"""
    
    def __init__(self):
        ## Plaintext log of cookies
        self.cFile = open('cookies.log', 'w')

    def cookies(self, ip, mac, dm, cookie, option):
            self.cFile.write(ip + '\n' + mac + '\n' + dm + '\n' + cookie + '\n\n')
