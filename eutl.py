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
import binascii
# import glob
import xml.etree.ElementTree as ET
import xmlschema
# from xml.dom import minidom

from logger import Logger
from eutl_io import *
from eutl_types import *
from eutl_trust_service import *

def get_text_or_empty(node) -> str:
    return node.text if node is not None else ""

def compute_certificate_file_name(certificate, countryCode, typeId, translations):
    subject = certificate.Subject.encode('ascii', 'replace').decode(
                'ascii', 'replce').translate(translations)
    file_name = countryCode + "_" + subject + "_" + \
                typeId + "_" + \
                certificate.FingerprintSHA1[0:10] + \
                ".cer"
    return file_name


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

    def __init__(self, Url, mime, cc, xsdPath):
        self.FileCache_TrustServices = "trust_services.xml"
        self.FileCache_TrustLists = "trust_lists.xml"

        self.UrlLocation = Url
        self.LocalPath = None
        self.xsdPath = xsdPath
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
        self.NoValidation = False
        self.LocalWD = None
        self.ChildrenGenericCount = 0
        self.ChildrenLOTLCount = 0
        self.ChildrenPdfCount = 0
        self.Status = ListStatus.NotDownloaded
        self.ListsOfTrust = []
        self.TrustServiceProviders = []
        self.AllServices = []

        self.eutlschema = xmlschema.XMLSchema(self.xsdPath, )

    def Update(self, localwd, force, noValidation):
        self.NoValidation = noValidation
        self.Download(localwd, force)
        self.ValidateWithSchema()
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
        if(self.Status != ListStatus.Success or self.NoValidation):
            Logger.LogInfo("Will not validate list {0}: Staus is {1} ".format(
                            self.LocalName, self.Status))
            return False

        valid = self.eutlschema.is_valid( str(self.LocalPath) )

        self.Status = ListStatus.Success if self.eutlschema.is_valid( str(self.LocalPath)) else ListStatus.SchemaError
        Logger.LogInfo("Validation result for list {0} with etsi schema is {1}".format(self.LocalName, self.Status))
        
        return self.Status is ListStatus.Success 

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
                lot.ValidateWithSchema()
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

                    file_name = compute_certificate_file_name(certificate, service.CC, service.ServiceTypeId.name, trantab)
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

    def PrintStatistics(self):
        if(self.TSLType != TrustListType.ListOfTheLists):
            print("This is not the root list")
            return False
        
        if(not self.AllServices):
            print("This is not the root list")
            return False

        QC_CA_n = 0
        QC_OCSP_n = 0
        QC_CRL_n = 0
        Q_TST_n = 0
        Q_EDS_n = 0
        Q_REM_n = 0
        Q_PSES_n = 0
        Q_QESVAL_n = 0

        granted_QC_CA_n = 0
        national_QC_CA_n = 0
        granted_QC_OCSP_n = 0
        national_QC_OCSP_n = 0

        for service in self.AllServices:
            if(service.ServiceTypeId == TspServiceType.QC_CA):
                QC_CA_n += 1
                if(service.ServiceStatusId == TspServiceStatusType.Granted):
                    granted_QC_CA_n += 1
                if(service.ServiceStatusId == TspServiceStatusType.NationalLevelRecognised):
                    national_QC_CA_n += 1
            elif(service.ServiceTypeId == TspServiceType.QC_OCSP):
                QC_OCSP_n += 1
                if(service.ServiceStatusId == TspServiceStatusType.Granted):
                    granted_QC_OCSP_n += 1
                if(service.ServiceStatusId == TspServiceStatusType.NationalLevelRecognised):
                    national_QC_OCSP_n += 1
            elif(service.ServiceTypeId == TspServiceType.QC_CRL):
                QC_CRL_n += 1
            elif(service.ServiceTypeId == TspServiceType.Q_TST):
                Q_TST_n += 1
            elif(service.ServiceTypeId == TspServiceType.Q_EDS):
                Q_EDS_n += 1
            elif(service.ServiceTypeId == TspServiceType.Q_REM):
                Q_REM_n += 1
            elif(service.ServiceTypeId == TspServiceType.Q_PSES):
                Q_PSES_n += 1
            elif(service.ServiceTypeId == TspServiceType.Q_QESVAL):
                Q_QESVAL_n += 1

        print("Found QC_CA_n={0} [g={1}, n={2}], QC_OCSP_n={3} [g={4}, n={5}], QC_CRL_n={6}, Q_TST_n={7}, Q_EDS_n={8}, Q_REM_n={9}, Q_PSES_n={10}, Q_QESVAL_n={11}".format(
                QC_CA_n, granted_QC_CA_n, national_QC_CA_n,
                QC_OCSP_n, granted_QC_OCSP_n, national_QC_OCSP_n,
                QC_CRL_n, Q_TST_n, Q_EDS_n, Q_REM_n, Q_PSES_n, Q_QESVAL_n))

        return (QC_CA_n, QC_OCSP_n, QC_CRL_n, Q_TST_n, Q_EDS_n, Q_REM_n, Q_PSES_n, Q_QESVAL_n)

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
                url, MimeType.get_type_from_string(mime), cc, self.xsdPath)

            self.ListsOfTrust.append(trustList)

    def __get_sie_from_node(self, tree):
        if( tree is None ):
            return ""
        node_sie_b64 = ""
        node_sie = tree.find(
            "{0}ServiceInformationExtensions".format(EutlNS.NS1.value))
        if (node_sie is not None):
            xmlstr = ET.tostring(node_sie, encoding='utf8', method='xml')
            node_sie_b64 = binascii.b2a_base64(xmlstr).decode()
        return node_sie_b64

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
                "{0}TSPServices/{0}TSPService".format(EutlNS.NS1.value))

            for node_svc in node_services:
                node_svc_name = node_svc.find(
                    "{0}ServiceInformation/{0}ServiceName/{0}Name".format(EutlNS.NS1.value))
                node_svc_type = node_svc.find(
                    "{0}ServiceInformation/{0}ServiceTypeIdentifier".format(EutlNS.NS1.value))
                node_svc_status = node_svc.find(
                    "{0}ServiceInformation/{0}ServiceStatus".format(EutlNS.NS1.value))
                node_svc_status_begin = node_svc.find(
                    "{0}ServiceInformation/{0}StatusStartingTime".format(EutlNS.NS1.value))
                node_svc_x509_vals = node_svc.findall(
                    "{0}ServiceInformation/{0}ServiceDigitalIdentity/{0}DigitalId/{0}X509Certificate".format(EutlNS.NS1.value))
                # node_svc_x509_subj = node_svc.find(
                #     "{0}ServiceDigitalIdentity/{0}DigitalId/{0}X509SubjectName".format(EutlNS.NS1.value))


                # extract ServiceInformationExtenstions in xml format (transform it into b64) and store it in the trust_services xml
                # the consumer application will get this xml info, parse it and use it accordingly
                node_sie_b64 = self.__get_sie_from_node(node_svc)


                svc = TrustServiceProviderService(
                    tsp.CC,
                    tsp.TrustServiceProviderName,
                    tsp.TrustServiceProviderTradeName,
                    get_text_or_empty(node_svc_name),
                    get_text_or_empty(node_svc_type),
                    get_text_or_empty(node_svc_status),
                    get_text_or_empty(node_svc_status_begin),
                    node_sie_b64
                )

                # Do service history
                self.__parse_service_history(node_svc, svc)

                ## TODO: should we validate list structure here?
                ## TODO: we should check this: as of ts_119612, sec. 5.5.4, ServiceCurrentStatus shall be:
                ##  i. The identifier of the status of the services of a type specified in clause 5.5.1.1 shall be 
                #       either "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted" or 
                #       "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn" as defined in clause D.5.
                ## ii. The identifier of the status of the services of a type specified in clause 5.5.1.2 or in clause 5.5.1.3 shall be 
                #       either "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel" or 
                #       "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedatnationallevel" as defined in clause D.5.
                 
                if(node_svc_x509_vals is not None):
                    for value in node_svc_x509_vals:
                        try:      
                            svc.Certificates.append( Certificate(value.text) )
                        except ValueError as ex:
                            Logger.LogException("Unable to parse certificate: country={0} service={1}".
                                                        format(svc.CC, svc.ServiceName),
                                                ex )
                tsp.Services.append(svc)
    
    def __parse_service_history(self, node_svc, svc):
        nodes_history = node_svc.findall(
            "{0}ServiceHistory/{0}ServiceHistoryInstance".format(EutlNS.NS1.value))
        for node_history in nodes_history:
            node_svc_history_type = node_history.find("{0}ServiceTypeIdentifier".format(EutlNS.NS1.value))
            node_svc_history_name = node_history.find("{0}ServiceName/{0}Name".format(EutlNS.NS1.value))
            node_svc_history_status = node_history.find("{0}ServiceStatus".format(EutlNS.NS1.value))
            node_svc_history_status_begin = node_history.find("{0}StatusStartingTime".format(EutlNS.NS1.value))
            svc_history_sie_b64 = self.__get_sie_from_node(node_history)

            svc_history = BaseTrustServiceProviderService(
                get_text_or_empty(node_svc_history_name),
                get_text_or_empty(node_svc_history_type),
                get_text_or_empty(node_svc_history_status),
                get_text_or_empty(node_svc_history_status_begin),
                svc_history_sie_b64
                )

            self.__parse_service_digital_identity(node_history, svc_history, svc)

            svc.History.append(svc_history)

    def __parse_service_digital_identity(self, node_svc_history, svc_history, svc):
        nodes_sdi = node_svc_history.findall("{0}ServiceDigitalIdentity/{0}DigitalId".format(EutlNS.NS1.value))
        for node_sdi in nodes_sdi:
            node_x509Certificate = node_sdi.find("{0}X509Certificate".format(EutlNS.NS1.value))
            node_x509SubjectName = node_sdi.find("{0}X509SubjectName".format(EutlNS.NS1.value))
            node_x509SKI = node_sdi.find("{0}X509SKI".format(EutlNS.NS1.value))
            node_KeyValue = node_sdi.find("{0}KeyValue".format(EutlNS.NS1.value))
            
            sdi = None
            if( node_x509Certificate is not None):
                sdi = ServiceDigitalIdentity(SdiType.SDI_X509Certificate, get_text_or_empty(node_x509Certificate))
            if( node_x509SubjectName is not None):
                sdi = ServiceDigitalIdentity(SdiType.SDI_X509SubjectName, get_text_or_empty(node_x509SubjectName))
            if( node_x509SKI is not None):
                sdi = ServiceDigitalIdentity(SdiType.SDI_X509SKI, get_text_or_empty(node_x509SKI))
            if( node_KeyValue is not None):
                sdi = ServiceDigitalIdentity(SdiType.SDI_KeyValue, get_text_or_empty(node_KeyValue))

            if( sdi is None):
                return
            # TODO: do the same for service current SDIs: that is replace the field Certificates[] with ServiceDigitalIdentity[] and populate it
            svc_history.ServiceDigitalIdentity.append(sdi)
            if(sdi.SdiType == SdiType.SDI_X509Certificate):
                try:
                    svc.Certificates.append( Certificate(sdi.Value) )
                except ValueError as ex:
                    Logger.LogException("Unable to parse certificate", ex)

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

        save_xml_to_file (elem_root, path / self.FileCache_TrustLists)
        
    def __save_xml_certificates_cache(self, path):
        if( self.AllServices is None or len(self.AllServices) == 0):
            return False

        root_attrs = {
            "nextupdate": self.NextUpdate,
            "version": self.TypeVersion,
            "seq": self.SeqNumber
        }
        elem_root = ET.Element('trustservicesdigitalids', root_attrs)

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
                    "status": svc.ServiceStatusId.value,
                    "begin": svc.ServiceStatusStartTime,
                    "x509fingerprintsha1": certificate.FingerprintSHA1,
                    "sie": svc.sie,
                    # "x509valueb64": svc.Certificates[0].Value if svc.Certificates else ""
                }
                elem_svc = ET.SubElement(elem_root, 'digitalid', svc_attrs)

                for svc_history in svc.History:
                    svc_history_attrs = {
                        "servicename": svc_history.ServiceName,
                        "type": svc_history.ServiceTypeId.value,
                        "isqualified": IsQualifiedService(svc.ServiceTypeId.value),
                        "status": svc_history.ServiceStatusId.value,
                        "begin": svc_history.ServiceStatusStartTime,
                        "sie": svc_history.sie,
                    }
                    elem_svc_history = ET.SubElement(elem_svc, "svc_history", svc_history_attrs)

                    for sdi in svc_history.ServiceDigitalIdentity:
                        svc_sdi_attrs = {
                            "sdi_type": str(sdi.SdiType),
                            "value": sdi.Value
                        }
                        elem_svc_sdi = ET.SubElement(elem_svc_history, "sdi", svc_sdi_attrs)

        save_xml_to_file(elem_root, path / self.FileCache_TrustServices)
