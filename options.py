import getopt
import pathlib

class Options:
    def __init__(self):
        self.urlLotl = 'https://ec.europa.eu/tools/lotl/eu-lotl.xml'
        self.workingDir = pathlib.Path('/tmp/etsi-plugtests/etl')
        self.force = False
        # self.wdPath = pathlib.Path(self.workingDir)

    def localTListPath(self):
        return self.workingDir / "trustlists"

    def localTrustCertPath(self):
        return self.workingDir / "trustcerts"

    def localUnTrustCertPath(self):
        return self.workingDir / "untrustcerts"

    def localCachePath(self):
        return self.workingDir

    def parseCommandLine(self, argv):
        try:
            opts, args = getopt.getopt(
                argv, "hf", ["workingdir="])
        except getopt.GetoptError:
            self.printHelp()
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                self.printHelp()
                sys.exit()
            elif opt == '-f':
                self.force = True
            elif opt in ("--workingdir"):
                # self.workingDir = arg
                self.workingDir = pathlib.Path(arg)

    def printHelp(self):
        print('''
            -h              print this help and exit.
            -f              force download. Will replace the file if it already exists. Default is False.
            --workingdir    local working directory
            ''')
