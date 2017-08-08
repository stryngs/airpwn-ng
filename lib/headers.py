import time

class Headers(object):
    """ Headers class

        This class is where the user can add new headers.
        This class might become file based, but for now, module.
        
        Example headers:
        headers = "HTTP/1.1 200 OK\r\n"
        headers += "Date: " + time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()) + "\r\n"
        headers += "Server: Apache\r\n"
        headers += "Cache-Control: public, max-age=99999\r\n"
        headers += "Expires:Sun, 26 Jul 2016 02:37:33 GMT\r\n"
        headers += "Content-Encoding: utf-8\r\n"
        headers += "Content-Length: " + str(len(self.injection)) + "\r\n"
        headers += "Connection: close\r\n"
        headers += "Content-Type: text/html\r\n"
        headers += "Set-Cookie: PHPSESSID = pwneduser\r\n"
        headers += "\r\n"
    """
    
    def default(self, injection):
        """ Create the HTML headers """
        headers = 'HTTP/1.1 200 OK\r\n'
        headers += 'Date: ' + time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime()) + '\r\n'
        headers += 'Server: Apache\r\n'
        headers += 'Content-Length: ' + str(len(injection)) + '\r\n'
        headers += 'Connection: close\r\n'
        headers += 'Content-Type: text/html\r\n'
        headers += '\r\n'
        return headers
