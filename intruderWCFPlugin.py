from burp import IBurpExtender, IContextMenuFactory, IHttpListener
from java.io import PrintWriter
from javax.swing import JMenuItem
from java.awt.event import MouseAdapter

from wcfutils import is_wcf_header, wcfdecode, wcfencode, get_headers_containing, prettyxml

class BurpExtender(IBurpExtender):
  def registerExtenderCallbacks(self, callbacks):
    self.callbacks = callbacks
    self.stdout = PrintWriter(callbacks.getStdout(), True)
    self.stderr = PrintWriter(callbacks.getStderr(), True)
    self.helpers = callbacks.getHelpers()

    callbacks.setExtensionName("Intruder WCF")
    callbacks.registerHttpListener(WCFIntruderListener(self))
    callbacks.registerContextMenuFactory(WCFIntruderCtxMenu(self))

    return


class WCFIntruderListener(IHttpListener):
  def __init__(self, extender):
    self.extender = extender

  def processHttpMessage(self, tool, is_request, msg_info):
    if tool != self.extender.callbacks.TOOL_INTRUDER or not is_request:
      return
    
    request = msg_info.getRequest()
    req_info = self.extender.helpers.analyzeRequest(request)
    headers = req_info.getHeaders()

    gzip = reduce(lambda acc, x: acc or 'gzip' in x, get_headers_containing('content-type', headers), False)
    body = wcfencode(self.extender.helpers.bytesToString(request[req_info.getBodyOffset():]), self.extender, gzip)

    msg_info.setRequest(self.extender.helpers.buildHttpMessage(headers, body))


class WCFIntruderCtxMenu(IContextMenuFactory):
  def __init__(self, extender):
    self.extender = extender

  def createMenuItems(self, invoc):
    menu = JMenuItem('Send WCF to Intruder')
    menu.addMouseListener(CtxMenuMouseListener(self.extender, invoc))

    enabled = True
    for msg in invoc.getSelectedMessages():
      headers = self.extender.helpers.analyzeRequest(msg.getRequest()).getHeaders()

      enabled = reduce(lambda acc, val: acc or is_wcf_header(val), get_headers_containing('content-type', headers), False)
      if not enabled:
        break
    
    menu.setEnabled(enabled)
    return [menu]

class CtxMenuMouseListener(MouseAdapter):
  def __init__(self, extender, invoc):
    self.extender = extender
    self.invoc = invoc

  def mousePressed(self, arg0):
    for reqres in self.invoc.getSelectedMessages():
      http_service = reqres.getHttpService()

      message = reqres.getRequest()
      req_info = self.extender.helpers.analyzeRequest(message)
      headers = req_info.getHeaders()

      gzip = reduce(lambda acc, x: acc or 'gzip' in x, get_headers_containing('content-type', headers), False)
      body = wcfdecode(self.extender.helpers.bytesToString(message[req_info.getBodyOffset():]), self.extender, gzip)

      self.extender.callbacks.sendToIntruder(http_service.getHost(), http_service.getPort(),
        http_service.getProtocol() == 'https', self.extender.helpers.buildHttpMessage(headers, prettyxml(body)))




      
