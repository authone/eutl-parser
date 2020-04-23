'''
    @author: George Gugulea
    @author_email: george.gugulea@certsign.ro
    @date: 01.11.2019
    @description: Download European Trust Lists and parse it to obtain containing certificates
                    It all starts from the root of the lists: 'https://ec.europa.eu/tools/lotl/eu-lotl.xml'
'''

import pathlib
import urllib.request
import sys
import getopt
import traceback
import ssl
import os
import xml.etree.ElementTree as ET
import base64
from enum import Enum, unique
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
# import lxml.etree as LXML

NS1 = "{http://uri.etsi.org/02231/v2#}"
NS2 = "{http://www.w3.org/2000/09/xmldsig#}"
NS3 = "{http://uri.etsi.org/01903/v1.3.2#}"
NS4 = "{http://uri.etsi.org/02231/v2/additionaltypes#}"
NS5 = "{http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#}"
NS6 = "{http://uri.etsi.org/01903/v1.4.1#}"
NS_EN = "{en}"
NS_RO = "{ro}"

class StringEnumType(Enum):
    @classmethod
    def get_type_from_string(cls, str_value):
        for name, member in cls.__members__.items():
            if(member.value == str_value):
                return member

@unique
class MimeType(StringEnumType):
    Xml = "application/vnd.etsi.tsl+xml"
    Pdf = "application/pdf"

@unique
class TrustListType(StringEnumType):
    ListOfTheLists = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists"
    Generic = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric"
    ListOfLists = "???" # does this exist?
    Pdf = "== Some Pdf List Type =="

@unique
class TspServiceType(StringEnumType):
    UNSPECIFIED = "http://uri.etsi.org/TrstSvc/Svctype/unspecified"
    IDV = "http://uri.etsi.org/TrstSvc/Svctype/IdV"
    IDV_NOPKI = "http://uri.etsi.org/TrstSvc/Svctype/IdV/nothavingPKIid"
    CA_QC = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC"
    CA_PKC = "http://uri.etsi.org/TrstSvc/Svctype/CA/PKC"
    NATIONALCA_QC = "http://uri.etsi.org/TrstSvc/Svctype/NationalRootCA-QC"
    TSA = "http://uri.etsi.org/TrstSvc/Svctype/TSA"
    TSA_QTST = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST"
    TSA_TSSQC = "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-QC"
    TSA_TSSADESQCQES = "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-AdESQCandQES"
    OCSP = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP"
    OCSP_QC = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC"
    QESVAL_Q = "http://uri.etsi.org/TrstSvc/Svctype/QESValidation/Q"
    ACA = "http://uri.etsi.org/TrstSvc/Svctype/ACA"
    RA = "http://uri.etsi.org/TrstSvc/Svctype/RA"
    EDS_Q = "http://uri.etsi.org/TrstSvc/Svctype/EDS/Q"
    PSES_Q = "http://uri.etsi.org/TrstSvc/Svctype/PSES/Q"

@unique
class TspStatusType(StringEnumType):
    NationalLevelRecognised = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel"
    NationalLevelDeprecated = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedatnationallevel"
    Granted = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
    Withdrawn = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn"

@unique
class ListStatus(Enum):
    Success = 0
    NotDownloaded = 1
    StructureError = 2
    SignatureNotValid = 3

def get_tsp_status_type(strStatus):
    if(strStatus == TspStatusType.NationalLevelRecognised.value):
        return TspStatusType.NationalLevelRecognised

def get_text_or_none(node):
    if( node != None):
        return node.text
    else:
        return None

def url_remote_file_name(url):
    items = url.split('/')
    return items[-1]

def download_file(rPath, lPath, force):
    if(lPath.exists()):
        msg = "File {0} exists; {1}".format(
            lPath, "it will be overwritten" if force else "it will NOT be downloaded again")
        Logger.LogInfo(msg)

        if(force):
            os.remove(lPath)
        else:
            return True

    req = urllib.request.Request(rPath)
    req.add_header(
        'User-Agent', "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.2 Safari/605.1.15")
    # sslcontext = ssl.create_default_context()

    resp = urllib.request.urlopen(req)
    Logger.LogInfo("Downloading file {0} ...".format(rPath) )
    data = resp.read()
    lFile = open(lPath, 'xb')
    lFile.write(data)
    Logger.LogInfo( "File {0} successfully downloaded.".format(lPath) )


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

class Logger:
    @staticmethod
    def LogError(msg):
        print("ERROR: ", msg)

    @staticmethod
    def LogInfo(msg):
        print("INFO: ", msg)

    @staticmethod
    def LogException(msg, ex):
        print("ERROR: {0}: {1}".format(msg, ex))

    @staticmethod
    def LogExceptionTrace(msg, ex):
        print("ERROR: ", msg)
        print('-'*60)
        traceback.print_exc(file=sys.stdout)
        print('-'*60)


class Certificate:
    def __init__(self, subject, value):
        self.Subject = subject
        self.Value = value

class TrustServiceProviderService:
    def __init__(self, svc_name, svc_type, country, svc_status, status_begin):
        self.Name = svc_name
        self.Type = TspServiceType.get_type_from_string(svc_type)
        self.Country = country
        self.StatusType = TspStatusType.get_type_from_string(svc_status)
        self.StatusBegin = status_begin
        self.Certificate = None

class TrustServiceProvider:
    def __init__(self, name, country):
        self.Name = name
        self.Country = country
        self.Services = []

class TrustList:
    xpOperatorTeritory = "{0}SchemeInformation/{0}SchemeTerritory".format(NS1)
    xpNextUpdate = "{0}SchemeInformation/{0}NextUpdate/{0}dateTime".format(NS1)
    xpVersion = "{0}SchemeInformation/{0}TSLVersionIdentifier".format(NS1)
    xpSqNumber = "{0}SchemeInformation/{0}TSLSequenceNumber".format(NS1)
    xpType = "{0}SchemeInformation/{0}TSLType".format(NS1)
    xpOperatorName = "{0}SchemeInformation/{0}SchemeOperatorName/{0}Name".format(NS1)
    xpOtherTL = "{0}SchemeInformation/{0}PointersToOtherTSL/{0}OtherTSLPointer".format(NS1)
    xpTsps = "{0}TrustServiceProviderList/{0}TrustServiceProvider".format(NS1)

    def __init__(self, Url, mime, country):
        self.UrlLocation = Url
        self.LocalPath = None
        self.LocalName = country + "-" + url_remote_file_name(self.UrlLocation) # add country code in front if the name: some lists have the same name
        self.Version = None
        self.SeqNumber = None
        self.OperatorName = None
        self.OperatorTeritory = country
        self.MimeType = mime
        self.TSLType = None
        self.NextUpdate = None
        self.TSPs = []
        self.ListsOfTrust = []
        self.Signature = None
        self.ForceDownload = False
        self.LocalWD = None
        self.ChildrenGenericCount = 0
        self.ChildrenLOTLCount = 0
        self.ChildrenPdfCount = 0
        self.Status = ListStatus.NotDownloaded

    def Update(self, localwd, force):
        self.Download(localwd, force)
        self.Parse()

    def Download(self, localwd, force):
        if(self.UrlLocation == None):
            raise "TrustList.Download failed: Url is empty"
        self.ForceDownload = force
        self.LocalWD = localwd
        self.LocalPath = localwd / self.LocalName
        try:
            download_file(self.UrlLocation, self.LocalPath, force)
            self.Status = ListStatus.Success
        except Exception as ex:
            self.Status = ListStatus.NotDownloaded
            Logger.LogException("Failed to download list {0}".format(self.UrlLocation), ex)

    def Parse(self):
        if( self.Status != ListStatus.Success):
            Logger.LogInfo("Will not parse list {0}: Staus is {1} ".format(self.LocalName, self.Status))
            return False

        if( self.MimeType == MimeType.Pdf):
            self.TSLType = TrustListType.Pdf
            return False

        tree = ET.parse(self.LocalPath)

        node = tree.find(TrustList.xpOperatorTeritory)
        self.OperatorTeritory = node.text

        node = tree.find(TrustList.xpNextUpdate)
        self.NextUpdate = node.text

        node = tree.find(TrustList.xpVersion)
        self.Version = node.text

        node = tree.find(TrustList.xpSqNumber)
        self.SeqNumber = node.text

        node = tree.find(TrustList.xpType)
        self.TSLType = TrustListType.get_type_from_string(node.text)

        node = tree.find(TrustList.xpOperatorName)
        self.OperatorName = node.text

        if(self.TSLType == TrustListType.ListOfTheLists or self.TSLType == TrustListType.ListOfLists):
            self.parse_list_of_lists(tree)
        elif(self.TSLType == TrustListType.Generic):
            self.parse_list_of_generic(tree)

        return True

    def parse_list_of_lists(self, tree):
        otls = tree.findall(TrustList.xpOtherTL)
        # self.ListsOfTrust = []
        for tl in otls:
            url = tl.find("{0}TSLLocation".format(NS1)).text
            mime = tl.find(".//{0}MimeType".format(NS4)).text
            country = tl.find(
                "{0}AdditionalInformation//{0}SchemeTerritory".format(NS1)).text
            trustList = TrustList(url, MimeType.get_type_from_string(mime), country)
            if(self.UrlLocation == url):
                continue
            self.ListsOfTrust.append(trustList)

    def parse_list_of_generic(self, tree):
        nodes = tree.findall(TrustList.xpTsps)
        for node in nodes:
            node2 = node.find(
                "{0}TSPInformation/{0}TSPName/{0}Name".format(NS1))
            name = node2.text

            tsp = TrustServiceProvider(name, self.OperatorTeritory)
            self.TSPs.append(tsp)

            node_services = node.findall(
                "{0}TSPServices/{0}TSPService/{0}ServiceInformation".format(NS1))

            for node_svc in node_services:
                node_svc_name = node_svc.find(
                    "{0}ServiceName/{0}Name".format(NS1))
                node_svc_type = node_svc.find(
                    "{0}ServiceTypeIdentifier".format(NS1))
                node_svc_status = node_svc.find(
                    "{0}ServiceStatus".format(NS1))
                node_svc_status_begin = node_svc.find(
                    "{0}StatusStartingTime".format(NS1))
                node_svc_x509_val = node_svc.find(
                    "{0}ServiceDigitalIdentity/{0}DigitalId/{0}X509Certificate".format(NS1))
                node_svc_x509_subj = node_svc.find(
                    "{0}ServiceDigitalIdentity/{0}DigitalId/{0}X509SubjectName".format(NS1))

                svc_cert = Certificate(
                    get_text_or_none(node_svc_x509_subj),
                    get_text_or_none(node_svc_x509_val)
                )
                svc = TrustServiceProviderService(
                    get_text_or_none(node_svc_name),
                    get_text_or_none(node_svc_type),
                    tsp.Country,
                    get_text_or_none(node_svc_status),
                    get_text_or_none(node_svc_status_begin)
                )
                svc.Certificate = svc_cert
                tsp.Services.append(svc)

    def DownloadChildren(self):
        self.ChildrenGenericCount = 0
        self.ChildrenLOTLCount = 0
        if(self.TSLType == TrustListType.ListOfTheLists or self.TSLType == TrustListType.ListOfLists):
            for lot in self.ListsOfTrust:
                if( lot.MimeType != MimeType.Xml):
                    continue
                lot.Download(self.LocalWD, self.ForceDownload)
                lot.Parse()
                if(lot.TSLType == TrustListType.ListOfTheLists or lot.TSLType == TrustListType.ListOfLists):
                    self.ChildrenLOTLCount += 1
                elif(lot.TSLType == TrustListType.Generic):
                    self.ChildrenGenericCount += 1
                elif(lot.MimeType == MimeType.Pdf):
                    self.ChildrenPdfCount += 1

    def Print(self):
        print("\n{0}: {1}\n\tFile: {2}\n\tUrl: {3}\n\tVersion: {4}\n\tSeqNumber: {5}\n\tNextUpdate: {6}\n\tListType: {7}\
                \n\tMimeType: {8}".format(
            self.OperatorTeritory,
            self.OperatorName,
            self.LocalName,
            self.UrlLocation,
            self.Version,
            self.SeqNumber,
            self.NextUpdate,
            self.TSLType,
            self.MimeType,
        ))
        if(self.TSLType == TrustListType.ListOfTheLists):
            print("\tChildren: {0} LofT; {1} Generic; {2} Pdf".format(
                self.ChildrenLOTLCount,
                self.ChildrenGenericCount,
                self.ChildrenPdfCount
            ))
        elif(self.TSLType == TrustListType.Generic):
            print("\tChildren: {0} TSPs".format(
                len(self.TSPs)))

        if(self.TSLType == TrustListType.ListOfTheLists):
            for tslist in self.ListsOfTrust:
                tslist.Print()

    def GetAllServices(self):
        all_services = []
        for tlist in self.ListsOfTrust:
            for svc_prov in tlist.TSPs:
                for service in svc_prov.Services:
                    all_services.append(service)
        return all_services



        
options = Options()
options.workingDir = pathlib.Path("./.download")

def check_preconditions():
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
    options.parseCommandLine(argv)
    if not check_preconditions():
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
