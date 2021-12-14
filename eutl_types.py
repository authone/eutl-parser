from enum import Enum, unique


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
    UnderSupervision = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision"
    SupervisionInCessation = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionincessation"
    SupervisionCeased = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionceased"
    SupervisionRevoked = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionrevoked"
    Accredited = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited"
    AccreditationCeased = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationceased"
    AccreditationRevoked = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationrevoked"
    SetByNationalLaw = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/setbynationallaw"
    DeprecatedByNationalLaw = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedbynationallaw"

@unique
class ListStatus(Enum):
    Success = 0
    NotDownloaded = 1
    SchemaError = 2
    StructureError = 3
    SignatureNotValid = 4

@unique
class SdiType(Enum):
    SDI_X509Certificate = 0
    SDI_X509SubjectName = 1
    SDI_X509SKI = 2
    SDI_KeyValue = 3
    def __str__(self):
        return self._name_

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
def IsQualifiedService(str_service_type) -> str:
    return "true" if __q_services.get(str_service_type) else "false"

