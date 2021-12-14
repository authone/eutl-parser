
from logger import Logger
import os
import io
import ssl
from xml.dom import minidom
import urllib.request
import xml.etree.ElementTree as ET


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
    reparsed = minidom.parseString(ET.tostring(elem_root, 'utf-8'))
    xml_str_pretty = reparsed.toprettyxml(indent="  ")

    with io.open(lPath, "w", encoding="utf-8") as xmlfile:
        xmlfile.write(xml_str_pretty)
