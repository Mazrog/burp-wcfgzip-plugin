# -*- coding: utf-8 -*-
"""
"""

from wcfutils import prettyxml, wcfdecode, wcfencode

from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from java.io import PrintWriter


class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("WCF viewer")
        callbacks.registerMessageEditorTabFactory(self)
        return

    def createNewInstance(self, controller, editable):
        return GzipHelperTab(self, controller, editable)


class GzipHelperTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self.extender = extender
        self.editable = editable
        self.controller = controller

        self.txtInput = extender.callbacks.createTextEditor()
        self.txtInput.setEditable(editable)

        self.httpHeaders = None
        self.body = None
        self.content = None

        self.gzip = False
        return

    def getTabCaption(self):
        return "Gzip Helper"

    def getUiComponent(self):
        return self.txtInput.getComponent()

    def isModified(self):
        return self.txtInput.isTextModified()

    def getSelectedData(self):
        return self.txtInput.getSelectedText()

    def getHeadersContaining(self, findValue, headers):
        if findValue is not None and headers is not None and len(headers) > 0:
            return [s for s in headers if findValue in s.lower()]
        return None

    def isEnabled(self, content, isRequest):
        self.content = content
        request_or_response_info = None
        if isRequest:
            request_or_response_info = self.extender.helpers.analyzeRequest(content)
        else:
            request_or_response_info = self.extender.helpers.analyzeResponse(content)
        if request_or_response_info is not None:
            headers = request_or_response_info.getHeaders()
            if headers is not None and len(headers) > 0:
                self.httpHeaders = headers
                self.body = self.extender.helpers.bytesToString(content[request_or_response_info.getBodyOffset():])
                matched_headers = self.getHeadersContaining('content-type', headers)
                if matched_headers is not None:
                    for matched_header in matched_headers:
                        self.gzip = 'gzip' in matched_header
                        if 'msbin' in matched_header:
                            return True

                    return self.gzip
        return False

    def setMessage(self, content, isRequest):
        output = wcfdecode(self.body, self.extender, self.gzip)
        self.extender.stdout.println(output)
        self.txtInput.setText(prettyxml(output))
        return

    def getMessage(self):
        if self.txtInput.isTextModified():
            encoded_txt = wcfencode(self.txtInput.getText(), self.extender, self.gzip)
            return self.extender.helpers.buildHttpMessage(self.httpHeaders, encoded_txt)
        else:
            return self.content
