import os
from zipfile import ZipFile

def CreatePackage(name, eutl, options) -> None:
    with ZipFile(name, 'w') as myzip:
        for cert_file in options.localTrustCertPath().glob("*.cer"):
            filename = os.path.join(cert_file.parent.name, cert_file.name)
            myzip.write(cert_file, arcname=filename )
        myzip.write(options.localCachePath() / eutl.FileCache_TrustServices, arcname=eutl.FileCache_TrustServices)
