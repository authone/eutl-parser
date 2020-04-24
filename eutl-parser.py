'''
    @author: George Gugulea
    @author_email: george.gugulea@certsign.ro
    @date: 01.11.2019
    @description: Download European Trust Lists and parse it to obtain containing certificates
                    It all starts from the root of the lists: 'https://ec.europa.eu/tools/lotl/eu-lotl.xml'
'''
import sys
import pathlib
import base64
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
# import lxml.etree as LXML

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
    # if not options.localUnTrustCertPath().is_dir():
    #     os.makedirs(options.localUnTrustCertPath())
    return True

def save_certificates_on_disk(services, base_dir):

    table_replace = {
        '(': '_',
        ')': '_',
        ' ': '_',
        '=': '_',
        '/': '_',
        '\\': '_',
        ',': '_',
        '.': '_',
        ';': '_',
        ':': '_',
    }
    trantab = str.maketrans("() =/.,\\", "________")

    for service in services:
        if(not service.Type or not service.Certificate.Value):
            continue
        svc_type_path = base_dir / service.Type.name
        if not svc_type_path.is_dir():
            os.makedirs(svc_type_path)

        if service.Certificate.Value:
            certBytes = base64.b64decode(service.Certificate.Value)
            Cert_x509 = x509.load_der_x509_certificate(
                certBytes, default_backend())

            certFingerprintPrefix = Cert_x509.fingerprint(hashes.SHA1()).hex()[0:10]
            file_name = service.Country + "_" + \
                service.Name.translate(trantab) + "_" + \
                certFingerprintPrefix + ".cer"
            file_path = svc_type_path / file_name

            with open(file_path, "wb") as cert_file:
                cert_file.write(certBytes)

def main(argv):

    options = Options()
    options.workingDir = pathlib.Path("./.download")
    options.parseCommandLine(argv)

    if not check_preconditions(options):
        Logger.LogError("main: preconditions not satisfied, exiting.")
        return

    try:
        EuTL = TrustList(options.urlLotl, MimeType.Xml, "EU")
        EuTL.Update(options.localTListPath(), options.force)
        EuTL.DownloadChildren()
        # EuTL.Print()

        all_services = EuTL.GetAllServices()
        save_certificates_on_disk(all_services, options.localTrustCertPath() )

        Logger.LogInfo("Found {0} trust service providers and {1} services.".format(
            sum(len(x.TSPs) for x in EuTL.ListsOfTrust),
            len(all_services)))

        return True
    except Exception as ex:
        Logger.LogExceptionTrace("main: Got an error", ex)


if __name__ == '__main__':
    main(sys.argv[1:])
