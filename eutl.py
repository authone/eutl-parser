'''
    eutl module contains definitions of datastructures that map on EUTL data types definition
        as it is specified bu ETSI TS 119 612 V2.1.1 (2015-07)

    TrustList class contains methods that are able to download the list of trustlists
        that should be 'https://ec.europa.eu/tools/lotl/eu-lotl.xml', parse it and download
        the referenced trust lists that corresponds to each member state

    @author: George Gugulea
    @author_email: george.gugulea@certsign.ro
    @date: 01.11.2019
    @description: Download European Trust Lists and parse it to obtain containing certificates
                    It all starts from the root of the lists: 'https://ec.europa.eu/tools/lotl/eu-lotl.xml'
'''
from enum import Enum, unique
import xml.etree.ElementTree as ET
from xml.dom import minidom
import urllib.request
import os
import io
import ssl
import base64
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from logger import Logger
import glob


def get_text_or_empty(node):
    return node.text if node is not None else ""


def url_remote_file_name(url):
    items = url.split('/')
    return items[-1]


def make_dir(base_path, dir_name):
    full_path = base_path / dir_name
    if not full_path.is_dir():
        os.makedirs(full_path)

def delete_all_files(folder_path, pattern):

    if(folder_path is None or not folder_path.exists()):
        Logger.LogError("Folder does not exist: {0}". folder_path)
        return

    Logger.LogInfo(
        "Deleting existing certificate files in directory {0}".format(folder_path))


    cert_files = list(folder_path.glob(pattern))
    #cert_files = glob.glob(, recursive=False)
    for cert_file in cert_files:
        os.remove(cert_file)

    Logger.LogInfo("Deleted {0} {1} files".format(len(cert_files), pattern))



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
    sslcontext = ssl.SSLContext(ssl.PROTOCOL_TLS)

    resp = urllib.request.urlopen(url=req, context=sslcontext)
    data = resp.read()
    lFile = open(lPath, 'xb')
    lFile.write(data)


def save_xml_to_file(elem_root, lPath):
    reprsed = minidom.parseString(ET.tostring(elem_root, 'utf-8'))
    xml_str_pretty = reprsed.toprettyxml(indent="  ")

    with io.open(lPath, "w", encoding="utf-8") as xmlfile:
        xmlfile.write(xml_str_pretty)


class StringEnumType(Enum):
    @classmethod
    def get_type_from_string(cls, str_value):
        for name, member in cls.__members__.items():
            if(member.value == str_value):
                return member


@unique
class EutlNS(StringEnumType):
    NS1 = "{http://uri.etsi.org/02231/v2#}"
    NS2 = "{http://www.w3.org/2000/09/xmldsig#}"
    NS3 = "{http://uri.etsi.org/01903/v1.3.2#}"
    NS4 = "{http://uri.etsi.org/02231/v2/additionaltypes#}"
    NS5 = "{http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#}"
    NS6 = "{http://uri.etsi.org/01903/v1.4.1#}"
    NS_EN = "{en}"
    NS_RO = "{ro}"


@unique
class MimeType(StringEnumType):
    Xml = "application/vnd.etsi.tsl+xml"
    Pdf = "application/pdf"


@unique
class TrustListType(StringEnumType):
    ListOfTheLists = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists"
    Generic = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric"
    GenericNonEU = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/CClist"
    Pdf = "== Some Pdf List Type =="


@unique
class TspServiceType(StringEnumType):
    ''' Follows qualified service providers'''
    QC_CA = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC"
    QC_OCSP = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC"
    QC_CRL = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/CRL/QC"
    Q_TST = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST"
    Q_EDS = "http://uri.etsi.org/TrstSvc/Svctype/EDS/Q"
    Q_REM = "http://uri.etsi.org/TrstSvc/Svctype/EDS/REM/Q"
    Q_PSES = "http://uri.etsi.org/TrstSvc/Svctype/PSES/Q"
    Q_QESVAL = "http://uri.etsi.org/TrstSvc/Svctype/QESValidation/Q"
    ''' Follows not qualified service providers'''
    NQC_CA = "http://uri.etsi.org/TrstSvc/Svctype/CA/PKC"
    NQC_OCSP = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP"
    NQC_CRL = "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/CRL"
    NQ_TST = "http://uri.etsi.org/TrstSvc/Svctype/TSA"
    NQ_TSSQC = "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-QC"
    NQ_TSSADESQCQES = "http://uri.etsi.org/TrstSvc/Svctype/TSA/TSS-AdESQCandQES"
    NQ_EDS = "http://uri.etsi.org/TrstSvc/Svctype/EDS"
    NQ_REMDS = "http://uri.etsi.org/TrstSvc/Svctype/EDS/REM"
    NQ_PSES = "http://uri.etsi.org/TrstSvc/Svctype/PSES"
    NQ_ADESV = "http://uri.etsi.org/TrstSvc/Svctype/AdESValidation"
    NQ_ADESG = "http://uri.etsi.org/TrstSvc/Svctype/AdESGeneration"
    ''' Follows not qualified, national level service providers'''
    NAT_RA = "http://uri.etsi.org/TrstSvc/Svctype/RA"
    NAT_RANOPKI = "http://uri.etsi.org/TrstSvc/Svctype/RA/nothavingPKIid"
    NAT_ACA = "http://uri.etsi.org/TrstSvc/Svctype/ACA"
    NAT_SPA = "http://uri.etsi.org/TrstSvc/Svctype/SignaturePolicyAuthority"
    NAT_ARCH = "http://uri.etsi.org/TrstSvc/Svctype/Archiv"
    NAT_ARCHNOPKI = "http://uri.etsi.org/TrstSvc/Svctype/Archiv/nothavingPKIid"
    NAT_IDV = "http://uri.etsi.org/TrstSvc/Svctype/IdV"
    NAT_IDVNOPKI = "http://uri.etsi.org/TrstSvc/Svctype/IdV/nothavingPKIid"
    NAT_QESC = "http://uri.etsi.org/TrstSvc/Svctype/KEscrow"
    NAT_QESCNOPKI = "http://uri.etsi.org/TrstSvc/Svctype/KEscrow/nothavingPKIid"
    NAT_PP = "http://uri.etsi.org/TrstSvc/Svctype/PPwd"
    NAT_PPNOPKI = "http://uri.etsi.org/TrstSvc/Svctype/PPwd/nothavingPKIid"
    NAT_TLISS = "http://uri.etsi.org/TrstSvd/Svctype/TLIssuer"
    NAT_ROOTCA_QC = "http://uri.etsi.org/TrstSvc/Svctype/NationalRootCA-QC"

    UNSPECIFIED = "http://uri.etsi.org/TrstSvc/Svctype/unspecified"


@unique
class TspServiceStatusType(StringEnumType):
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


__q_services = {
    "http://uri.etsi.org/TrstSvc/Svctype/CA/QC": True,
    "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC": True,
    "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/CRL/QC": True,
    "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST": True,
    "http://uri.etsi.org/TrstSvc/Svctype/EDS/Q": True,
    "http://uri.etsi.org/TrstSvc/Svctype/EDS/REM/Q": True,
    "http://uri.etsi.org/TrstSvc/Svctype/PSES/Q": True,
    "http://uri.etsi.org/TrstSvc/Svctype/QESValidation/Q": True
}
def IsQualifiedService(str_service_type):
    return "true" if __q_services.get(str_service_type) else "false"


class Certificate:
    def __init__(self, value, subject=None):
        self.Subject = subject
        self.Value = value
        self.Bytes = None
        self.FingerprintSHA1 = None
        if( self.Value is None):
            raise Exception("This certificate has no value {0}".format(self.Subject))

        self.Bytes = base64.b64decode(self.Value)
        Cert_x509 = x509.load_der_x509_certificate(self.Bytes, default_backend())
        self.FingerprintSHA1 = Cert_x509.fingerprint(hashes.SHA1()).hex()
        subj_attrs = Cert_x509.subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME)
        if(not subj_attrs):
            subj_attrs = Cert_x509.subject.get_attributes_for_oid(
                x509.NameOID.ORGANIZATION_NAME)
        self.Subject = subj_attrs[0].value



class TrustServiceProviderService:
    def __init__(self, cc, tsp_name, tsp_tradename, svc_name, svc_type_id, svc_status, status_start_time):
        self.CC = cc
        self.TrustServiceProviderName = tsp_name
        self.TrustServiceProviderTradeName = tsp_tradename
        self.ServiceName = svc_name
        self.ServiceTypeId = TspServiceType.get_type_from_string(svc_type_id)
        self.ServiceCurrentStatusId = TspServiceStatusType.get_type_from_string(
            svc_status)
        self.ServiceCurrentStatusStartTime = status_start_time
        # self.Certificate = None
        self.Certificates = []


class TrustServiceProvider:
    def __init__(self, cc, name, tradename):
        self.CC = cc
        self.TrustServiceProviderName = name
        self.TrustServiceProviderTradeName = tradename
        self.Services = []


class TrustList:
    xpOperatorTeritory = "{0}SchemeInformation/{0}SchemeTerritory".format(
        EutlNS.NS1.value)
    xpNextUpdate = "{0}SchemeInformation/{0}NextUpdate/{0}dateTime".format(
        EutlNS.NS1.value)
    xpVersion = "{0}SchemeInformation/{0}TSLVersionIdentifier".format(
        EutlNS.NS1.value)
    xpSqNumber = "{0}SchemeInformation/{0}TSLSequenceNumber".format(
        EutlNS.NS1.value)
    xpType = "{0}SchemeInformation/{0}TSLType".format(EutlNS.NS1.value)
    xpOperatorName = "{0}SchemeInformation/{0}SchemeOperatorName/{0}Name".format(
        EutlNS.NS1.value)
    xpOtherTL = "{0}SchemeInformation/{0}PointersToOtherTSL/{0}OtherTSLPointer".format(
        EutlNS.NS1.value)
    xpTsps = "{0}TrustServiceProviderList/{0}TrustServiceProvider".format(
        EutlNS.NS1.value)

    def __init__(self, Url, mime, cc):
        self.UrlLocation = Url
        self.LocalPath = None
        # add country code in front if the name: some lists have the same name
        self.LocalName = cc + "-" + url_remote_file_name(self.UrlLocation)
        self.TypeVersion = None
        self.SeqNumber = None
        self.OperatorName = None
        self.OperatorTeritory = cc
        self.MimeType = mime
        self.TSLType = None
        self.NextUpdate = None
        self.Signature = None
        self.ForceDownload = False
        self.LocalWD = None
        self.ChildrenGenericCount = 0
        self.ChildrenLOTLCount = 0
        self.ChildrenPdfCount = 0
        self.Status = ListStatus.NotDownloaded
        self.ListsOfTrust = []
        self.TrustServiceProviders = []
        self.AllServices = []

    def Update(self, localwd, force):
        self.Download(localwd, force)
        self.Parse()

    def Download(self, localwd, force):
        if(self.UrlLocation is None):
            raise "TrustList.Download failed: Url is empty"
        self.ForceDownload = force
        self.LocalWD = localwd
        self.LocalPath = localwd / self.LocalName
        try:
            Logger.LogInfo("Downloading file {0} ...".format(self.UrlLocation))
            download_file(self.UrlLocation, self.LocalPath, force)
            self.Status = ListStatus.Success
        except urllib.error.URLError as ex:
            self.Status = ListStatus.NotDownloaded
            Logger.LogException(
                "Failed to download list {0}".format(self.UrlLocation), ex)
    
    def ValidateWithSchema(self):
        if(self.Status != ListStatus.Success):
            Logger.LogInfo("Will not validate list {0}: Staus is {1} ".format(
                            self.LocalName, self.Status))
            return False

        return True

    def Parse(self):
        if(self.Status != ListStatus.Success):
            Logger.LogInfo("Will not parse list {0}: Staus is {1} ".format(
                self.LocalName, self.Status))
            return False

        if(self.MimeType == MimeType.Pdf):
            self.TSLType = TrustListType.Pdf
            Logger.LogInfo("Ignoring file {0}".format(self.LocalName))
            return False

        try:
            tree = ET.parse(self.LocalPath)

            node = tree.find(TrustList.xpOperatorTeritory)
            self.OperatorTeritory = node.text

            node = tree.find(TrustList.xpVersion)
            self.TypeVersion = node.text

            if(self.TypeVersion != "5"):
                Logger.logError("Will not parse list {0}. it has an unknown type version {1}".format(
                    self.LocalName, self.TypeVersion))
                self.Status = ListStatus.StructureError
                return False

            node = tree.find(TrustList.xpSqNumber)
            self.SeqNumber = node.text

            # After Brexit, UK lists have an empty NextUpdate
            node = tree.find(TrustList.xpNextUpdate)
            self.NextUpdate = node.text if node is not None else ""

            node = tree.find(TrustList.xpType)
            self.TSLType = TrustListType.get_type_from_string(node.text)

            node = tree.find(TrustList.xpOperatorName)
            self.OperatorName = node.text

        except AttributeError as ex:
            Logger.LogException(
                "Failed to parse list {0}".format(self.LocalName), ex)
            self.Status = ListStatus.StructureError
            return False


        if(self.TSLType == TrustListType.ListOfTheLists):
            self.__parse_list_of_lists(tree)
        elif(self.TSLType == TrustListType.Generic):
            self.__parse_list_of_generic(tree)

        return True

    def DownloadChildren(self):
        self.ChildrenGenericCount = 0
        self.ChildrenLOTLCount = 0
        if(self.TSLType == TrustListType.ListOfTheLists ):
            for lot in self.ListsOfTrust:
                if(lot.MimeType != MimeType.Xml):
                    continue

                lot.Download(self.LocalWD, self.ForceDownload)
                lot.Parse()

                if(lot.TSLType == TrustListType.ListOfTheLists):
                    self.ChildrenLOTLCount += 1
                elif(lot.TSLType == TrustListType.Generic):
                    self.ChildrenGenericCount += 1
                elif(lot.MimeType == MimeType.Pdf):
                    self.ChildrenPdfCount += 1

    def PostProcess(self, path):
        if(self.TSLType != TrustListType.ListOfTheLists):
            return False
        self.AllServices = self.__get_all_services()
        self.__save_xml_list_cache(path)
        self.__save_xml_certificates_cache(path)

    def SaveCetificatesOnDisk(self, base_dir):
        if(not self.AllServices):
            return False

        delete_all_files(base_dir, "*.cer")

        trantab = str.maketrans("() =/\\.,;:&%?*", "______________")

        for service in self.AllServices:
            if(not service.ServiceTypeId):
                raise("This service has no type")

            if (service.Certificates):
                for certificate in service.Certificates:
                    subject = certificate.Subject.encode('ascii', 'replace').decode(
                        'ascii', 'replce').translate(trantab)
                    file_name = service.CC + "_" + subject + "_" + \
                        service.ServiceTypeId.name + "_" + \
                        certificate.FingerprintSHA1[0:10] + ".cer"
                    file_path = base_dir / file_name

                    with open(file_path, "wb") as cert_file:
                        cert_file.write(certificate.Bytes)


    def Print(self):
        print("\n{0}: {1}\n\tFile: {2}\n\tUrl: {3}\n\tType Version: {4}\n\tSeqNumber: {5}\n\tNextUpdate: {6}\n\tListType: {7}\
                \n\tMimeType: {8}".format(
            self.OperatorTeritory,
            self.OperatorName,
            self.LocalName,
            self.UrlLocation,
            self.TypeVersion,
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
                len(self.TrustServiceProviders)))

        if(self.TSLType == TrustListType.ListOfTheLists):
            for tslist in self.ListsOfTrust:
                tslist.Print()

    def __parse_list_of_lists(self, tree):
        otls = tree.findall(TrustList.xpOtherTL)

        for tl in otls:
            url = tl.find("{0}TSLLocation".format(EutlNS.NS1.value)).text
            mime = tl.find(".//{0}MimeType".format(EutlNS.NS4.value)).text
            cc = tl.find(
                "{0}AdditionalInformation//{0}SchemeTerritory".format(EutlNS.NS1.value)).text

            if(self.UrlLocation == url):
                continue

            if(MimeType.get_type_from_string(mime) == MimeType.Pdf):
                continue

            trustList = TrustList(
                url, MimeType.get_type_from_string(mime), cc)

            self.ListsOfTrust.append(trustList)

    def __parse_list_of_generic(self, tree):
        nodes = tree.findall(TrustList.xpTsps)
        for node in nodes:
            node_name = node.find(
                "{0}TSPInformation/{0}TSPName/{0}Name".format(EutlNS.NS1.value))
            name = node_name.text
            node_tradename = node.find(
                "{0}TSPInformation/{0}TSPTradeName/{0}Name".format(EutlNS.NS1.value))
            tradename = get_text_or_empty(node_tradename)

            tsp = TrustServiceProvider(self.OperatorTeritory, name, tradename)
            self.TrustServiceProviders.append(tsp)

            node_services = node.findall(
                "{0}TSPServices/{0}TSPService/{0}ServiceInformation".format(EutlNS.NS1.value))

            for node_svc in node_services:
                node_svc_name = node_svc.find(
                    "{0}ServiceName/{0}Name".format(EutlNS.NS1.value))
                node_svc_type = node_svc.find(
                    "{0}ServiceTypeIdentifier".format(EutlNS.NS1.value))
                node_svc_status = node_svc.find(
                    "{0}ServiceStatus".format(EutlNS.NS1.value))
                node_svc_status_begin = node_svc.find(
                    "{0}StatusStartingTime".format(EutlNS.NS1.value))
                node_svc_x509_vals = node_svc.findall(
                    "{0}ServiceDigitalIdentity/{0}DigitalId/{0}X509Certificate".format(EutlNS.NS1.value))
                # node_svc_x509_subj = node_svc.find(
                #     "{0}ServiceDigitalIdentity/{0}DigitalId/{0}X509SubjectName".format(EutlNS.NS1.value))

                svc = TrustServiceProviderService(
                    tsp.CC,
                    tsp.TrustServiceProviderName,
                    tsp.TrustServiceProviderTradeName,
                    get_text_or_empty(node_svc_name),
                    get_text_or_empty(node_svc_type),
                    get_text_or_empty(node_svc_status),
                    get_text_or_empty(node_svc_status_begin)
                )

                # TODO: should we validate list structure here?
                 
                if(node_svc_x509_vals is not None):
                    for value in node_svc_x509_vals:      
                        svc.Certificates.append( Certificate(value.text) )
                tsp.Services.append(svc)
    
    def __get_all_services(self):
        all_services = []
        for tlist in self.ListsOfTrust:
            if(self.Status is not ListStatus.Success):
                continue

            for svc_prov in tlist.TrustServiceProviders:
                for service in svc_prov.Services:
                    all_services.append(service)
        return all_services

    def __save_xml_list_cache(self, path):
        if( self.ListsOfTrust is None):
            return False

        elem_root = ET.Element('trustlists')
        elem_root.set('version', self.TypeVersion)
        elem_root.set('sequence', self.SeqNumber)
        
        for tl in self.ListsOfTrust:

            if( tl.Status is not ListStatus.Success):
                continue

            if(not tl.OperatorTeritory or not tl.OperatorName or not tl.LocalName or not tl.UrlLocation or not tl.NextUpdate or not tl.TypeVersion or not tl.SeqNumber):
                Logger.LogInfo("Some informations are missing in list " + tl.LocalName)

            tl_attrs = {
                "cc": tl.OperatorTeritory,
                "operator": tl.OperatorName,
                "name": tl.LocalName,
                "uri": tl.UrlLocation,
                "nextupdate": tl.NextUpdate if tl.NextUpdate is not None else "",
                "type": tl.TypeVersion, 
                "version": tl.SeqNumber
            }
            elem_tl = ET.SubElement(elem_root, 'list', tl_attrs)

        save_xml_to_file (elem_root, path / "trust_lists.xml")
        
    def __save_xml_certificates_cache(self, path):
        if( self.AllServices is None or len(self.AllServices) == 0):
            return False

        elem_root = ET.Element('trustservicesdigitalids', {"nextupdate": self.NextUpdate})

        for svc in self.AllServices:
            if( not svc.Certificates ):
                Logger.LogInfo("This service {0} '{1}' of type {2} has no certificate".format(svc.CC, svc.ServiceName, svc.ServiceTypeId.name))
                continue
            for certificate in svc.Certificates:
                svc_attrs = {
                    "cc": svc.CC,
                    "tspname": svc.TrustServiceProviderName,
                    "tsptradename": svc.TrustServiceProviderTradeName,
                    "servicename": svc.ServiceName,
                    "type": svc.ServiceTypeId.value,
                    "isqualified": IsQualifiedService(svc.ServiceTypeId.value),
                    "status": svc.ServiceCurrentStatusId.value,
                    "begin": svc.ServiceCurrentStatusStartTime,
                    "x509fingerprintsha1": certificate.FingerprintSHA1,
                    # "x509valueb64": svc.Certificates[0].Value if svc.Certificates else ""
                }
                elem_svc = ET.SubElement(elem_root, 'digitalid', svc_attrs)

        save_xml_to_file(elem_root, path / "trust_services.xml")
