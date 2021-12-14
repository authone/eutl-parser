import getopt
import pathlib
import sys

'''
Options class to parse command line parameters:
            -h                      print this help and exit.   
            -v, --version           print application version and exit.
            -f                      force download. Will replace the file if it already exists. Default is False.
            -t                      Trust the file; do not perform validation. Default is false (perform validation)
            -p                      Create a package archive containing all certificates and services list
            --workingdir path       local working directory
            --xsd-directory path    path to xsd schema files location
'''

class Options:
    def __init__(self):
        self.urlLotl = 'https://ec.europa.eu/tools/lotl/eu-lotl.xml'
        self.workingDir = pathlib.Path('/tmp/etsi-plugtests/etl')
        self.xsdDir = pathlib.Path("schemas")
        self.force = False
        self.noValidation = False
        self.printVersionAndExit = False
        self.createPackage = False

    def localTListPath(self):
        return self.workingDir / "trustlists"

    def localTrustCertPath(self):
        return self.workingDir / "trustcerts"

    def localCachePath(self):
        return self.workingDir

    def parseCommandLine(self, argv):
        try:
            opts, args = getopt.getopt(
                argv, "hvftp", ["package", "version", "workingdir=", "xsd-directory="])
        except getopt.GetoptError:
            self.printHelp()
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                self.printHelp()
                sys.exit()
            elif opt == '-f':
                self.force = True
            elif opt == '-t':
                self.noValidation = True
            elif opt in ("-p", "--package"):
                self.createPackage = True
            elif opt in ("--workingdir"):
                self.workingDir = pathlib.Path(arg)
            elif opt in ("-v", "--version"):
                self.printVersionAndExit = True
            elif opt in ("--xsd-directory"):
                self.xsdDir = pathlib.Path(arg)

    def printHelp(self):
        print('''
            -h                      print this help and exit.   
            -v, --version           print application version and exit.
            -f                      force download. Will replace the file if it already exists. Default is False.
            -t                      Trust the file; do not perform validation. Default is false (perform validation)
            -p, --package           Create a package archive containing all certificates and services list
            --workingdir path       local working directory
            --xsd-directory path    path to xsd schema files location
            ''')
