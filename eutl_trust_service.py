import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography import x509

from eutl_types import *

class ServiceDigitalIdentity:
    def __init__(self, sdi_type, value) -> None:
        self.SdiType = sdi_type
        self.Value = value

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

class BaseTrustServiceProviderService:
    def __init__(self, svc_name, svc_type_id, svc_status, status_start_time, sie):
        self.ServiceName = svc_name
        self.ServiceTypeId = TspServiceType.get_type_from_string(svc_type_id)
        self.ServiceStatusId = TspServiceStatusType.get_type_from_string(
            svc_status)
        self.ServiceStatusStartTime = status_start_time
        self.sie = sie if sie is not None else ""
        self.ServiceDigitalIdentity = []

class TrustServiceProviderService (BaseTrustServiceProviderService):
    def __init__(self, cc, tsp_name, tsp_tradename, svc_name, svc_type_id, svc_status, status_start_time, sie):
        super(TrustServiceProviderService, self).__init__(svc_name, svc_type_id, svc_status, status_start_time, sie)
        self.CC = cc
        self.TrustServiceProviderName = tsp_name
        self.TrustServiceProviderTradeName = tsp_tradename
        self.Certificates = []
        self.History = []

class TrustServiceProvider:
    def __init__(self, cc, name, tradename):
        self.CC = cc
        self.TrustServiceProviderName = name
        self.TrustServiceProviderTradeName = tradename
        self.Services = []

