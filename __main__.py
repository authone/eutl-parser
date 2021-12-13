'''
    @author: George Gugulea
    @author_email: george.gugulea@certsign.ro
    @date: 01.11.2019
    @description: Download European Trust Lists and parse it to obtain containing certificates
                    It all starts from the root of the lists: 'https://ec.europa.eu/tools/lotl/eu-lotl.xml'
'''
import sys
import pathlib

from options import Options
from logger import Logger
from eutl import *

eutl_parser_version = "1.0.3"

def check_preconditions(options):
    if not options.workingDir.is_dir():
        os.makedirs(options.workingDir)
    if not options.localTListPath().is_dir():
        os.makedirs(options.localTListPath())
    if not options.localTrustCertPath().is_dir():
        os.makedirs(options.localTrustCertPath())
    if not (options.xsdDir / "ts_119612v020201_201601xsd.xsd").exists():
        Logger.LogError("Could not find schema definition files")
        return False
    return True

def printVersion():
    msg = "eutl_parser v{0}".format(eutl_parser_version)
    print(msg)

def main(argv):

    options = Options()
    options.workingDir = pathlib.Path("./.download")
    options.parseCommandLine(argv)

    eutl_schema_path = options.xsdDir / "ts_119612v020201_201601xsd.xsd"

    if options.printVersionAndExit:
        printVersion()
        sys.exit()

    if not check_preconditions(options):
        Logger.LogError("Preconditions not satisfied, exiting")
        return False

    try:
        EuTL = TrustList( options.urlLotl, MimeType.Xml, "EU", str(eutl_schema_path) )
        EuTL.Update(options.localTListPath(), options.force)
        EuTL.DownloadChildren()
        EuTL.PostProcess(options.localCachePath())
        EuTL.SaveCetificatesOnDisk(options.localTrustCertPath())
        EuTL.PrintStatistics()

        Logger.LogInfo("Found {0} trust service providers and {1} services.".format(
            sum(len(x.TrustServiceProviders) for x in EuTL.ListsOfTrust),
            len(EuTL.AllServices)))

        return True
    except Exception as ex:
        Logger.LogExceptionTrace("main: Got an error", ex)


if __name__ == '__main__':
    main(sys.argv[1:])
