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

def check_preconditions(options):
    if not options.workingDir.is_dir():
        os.makedirs(options.workingDir)
    if not options.localTListPath().is_dir():
        os.makedirs(options.localTListPath())
    if not options.localTrustCertPath().is_dir():
        os.makedirs(options.localTrustCertPath())
    return True

def main(argv):

    options = Options()
    options.workingDir = pathlib.Path("./.download")
    options.parseCommandLine(argv)

    if not check_preconditions(options):
        Logger.LogError("main: preconditions not satisfied, exiting.")
        return False

    try:
        EuTL = TrustList(options.urlLotl, MimeType.Xml, "EU")
        EuTL.Update(options.localTListPath(), options.force)
        EuTL.DownloadChildren()
        EuTL.PostProcess(options.localCachePath())
        EuTL.SaveCetificatesOnDisk(options.localTrustCertPath())
        # EuTL.Print()

        Logger.LogInfo("Found {0} trust service providers and {1} services.".format(
            sum(len(x.TrustServiceProviders) for x in EuTL.ListsOfTrust),
            len(EuTL.AllServices)))

        return True
    except Exception as ex:
        Logger.LogExceptionTrace("main: Got an error", ex)


if __name__ == '__main__':
    main(sys.argv[1:])
