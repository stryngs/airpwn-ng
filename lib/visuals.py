import os

class Bcolors(object):
    """Define the color schema"""

    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'



class Pager(object):
    """Homebrew paging"""
    def __init__(self):
        self.tHeight, self.tWidth = os.popen('stty size', 'r').read().split()

    def scroll(self, txt):
        if len(txt.splitlines()) <= int(self.tHeight):
            print txt
        else:
            oPut = txt.splitlines()
            rMax = int(self.tHeight) - 1
            spacer = str('...').rjust(int(self.tWidth))
            while len(oPut) > 0: 
                for i in range(0, rMax):
                    try:
                        print oPut.pop(0)
                    except:
                        pass
                if len(oPut) != 0:
                    raw_input(spacer)