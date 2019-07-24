import sys
import gzip
import base64
import subprocess
from subprocess import CalledProcessError

from xml.dom import minidom
from cStringIO import StringIO

def is_wcf_header(header):
  return 'msbin' in header

def get_headers_containing(findValue, headers):
  if findValue is not None and headers is not None and len(headers) > 0:
    return [s for s in headers if findValue in s.lower()]
  return None

def prettyxml(xmldata):
  try:
    return minidom.parseString(xmldata).toprettyxml(encoding="utf-8")
  except:
    return xmldata

def decompress(stringContent, extender):
  try:
    buf = StringIO(stringContent)
    s = gzip.GzipFile(mode="r", fileobj=buf)
    content = s.read()
    
    return content
  except Exception as e:
    extender.stdout.println("error({0}): {1}".format(type(e), str(e)))
  return None

def compress(content, extender):
  stringContent = extender.helpers.bytesToString(content)
  try:
    buf = StringIO()
    s = gzip.GzipFile(mode="wb", fileobj=buf)
    s.write(stringContent)
    s.close()
    gzipContent = buf.getvalue()
    return gzipContent
  except Exception as e:
    extender.stdout.println("error({0}): {1}".format(type(e), str(e)))
  return None


def wcfdecode(binary_str, extender, do_zip=False):
  if do_zip:
    binary_str = decompress(binary_str, extender)

  b64_wcfbinary_string = base64.b64encode(binary_str)
  try:
    # NBFS.exe must be in the same directory as Burp
    proc = subprocess.Popen(['NBFS.exe', 'decode'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    data = proc.communicate(input=b64_wcfbinary_string)
    b64_out_string = data[0]
    extender.stdout.println(b64_out_string)
    extender.stdout.println(data[1])
    output = base64.b64decode(b64_out_string)
    return output

  except CalledProcessError, e:
    extender.stdout.println("error({0}): {1}".format(e.errno, e.strerror))
  except:
    extender.stdout.println("Unexpected error: %s: %s\n%s" % (sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2]))
  return None

def wcfencode(body, extender, do_zip=False):
  xmlStringContent = extender.helpers.bytesToString(body)
  base64EncodedXML = base64.b64encode(xmlStringContent.replace("\n", '').replace("\t", ''))
  try:
    # NBFS.exe must be in the same directory as Burp
    proc = subprocess.Popen(['NBFS.exe', 'encode'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    output = proc.communicate(input=base64EncodedXML)[0]
    extender.stdout.println(output)
    extender.stdout.println(proc.stderr.read())
    data = extender.helpers.stringToBytes(base64.b64decode(output))

    if do_zip:
      data = compress(data, extender)
    
    return data

  except CalledProcessError, e:
    extender.stdout.println("error({0}): {1}".format(e.errno, e.strerror))
  except:
    extender.stdout.println("Unexpected error: %s: %s\n%s" % (sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2]))
  return None
