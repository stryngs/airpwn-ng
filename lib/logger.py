import re, time
import sqlite3 as lite

class Database(object):
    """Database style logs"""

    def __init__(self, dbFile):
        ## DB the cookies
        self.con = lite.connect(dbFile)
        self.con.text_factory = str
        self.db = self.con.cursor()
        self.db.execute("CREATE TABLE IF NOT EXISTS ip2mac(ip TEXT, mac TEXT, UNIQUE(ip, mac))")
        self.db.execute("CREATE TABLE IF NOT EXISTS cookies(mac TEXT, ip TEXT, dm TEXT, ck TEXT, UNIQUE(mac, ip, dm, ck))")

    def sqlite_cookies(self, ip, mac, dm, cookie):
        """Database method for using sqlite to store cookies"""
        with self.con:
            self.db.execute("INSERT OR IGNORE INTO ip2mac VALUES(?, ?);", (ip, mac))
            self.db.execute("INSERT OR IGNORE INTO cookies VALUES(?, ?, ?, ?);", (mac, ip, dm, cookie))

    def extract_cookies(self):
        """Database method for parsing stored cookies
        Requires Cookies Manager+ (v1.7) for import

        Cheats by using regex to subout www. from cookie
        Not 100% reliable, yet...
        See comments in get_request() in packet_handler.py to follow-along
        """
        #dList = []
        #cList = []
        cExp = str(int(time.time()) + 31536000)

        with self.con:
            ## Obtain rows within cookies table
            getRows = self.db.execute("SELECT count(rowid) from cookies;")
            tVal = getRows.fetchone()
            rCount = tVal[0] + 1
            
            ## Loop through rows
            ### Probably can deal without a range, but to make sure order stays correct...
            for row in range(1, rCount):
                with open('cookie-grab_%s.ck' % row, 'w') as oFile:
                    getDM = self.db.execute("SELECT dm FROM cookies WHERE rowid = ?;", (row,))
                    dmVal = getDM.fetchone()
                    #dList.append(dmVal[0])
                    getCK = self.db.execute("SELECT ck FROM cookies WHERE rowid = ?;", (row,))
                    ckVal = getCK.fetchone()
                    #cList.append(ckVal[0])

                    ## Grab top cookie
                    name = ckVal[0].split(';')[0].split(':')[1].strip().split('=')[0]
                    nameLen = len(ckVal[0].split(';')[0].strip().split('=')[0]) + 1
                    oFile.write(re.sub('^www.', '.', dmVal[0]) + '\t' + 'TRUE' + '\t' + '/' + '\t' + 'FALSE' + '\t' + cExp + '\t' + name + '\t' + ckVal[0].split(';')[0].strip()[nameLen:] + '\t' + '1' + '\r\n')

                    ## Grab the rest of the cookies
                    cLen = len(ckVal[0].split(';'))
                    for c in range(1, cLen):
                        name = ckVal[0].split(';')[c].strip().split('=')[0]
                        nameLen = len(ckVal[0].split(';')[c].strip().split('=')[0]) + 1
                        oFile.write(re.sub('^www.', '.', dmVal[0]) + '\t' + 'TRUE' + '\t' + '/' + '\t' + 'FALSE' + '\t' + cExp + '\t' + name + '\t' + ckVal[0].split(';')[c].strip()[nameLen:] + '\t' + '1' + '\r\n')
                print 'cookie-grab_%s.ck created!' % row



class Logfile(object):
    """Plaintext logs"""
    
    def __init__(self):
        ## Plaintext log of cookies
        self.cFile = open('cookies.log', 'w')

    def cookies(self, ip, mac, dm, cookie):
        """Method for storing plaintext cookie sniffs"""
        self.cFile.write(ip + '\n' + mac + '\n' + dm + '\n' + cookie + '\n\n')
