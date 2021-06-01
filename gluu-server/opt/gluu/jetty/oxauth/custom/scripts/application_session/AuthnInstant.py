# Script to synchronize the local Gluu authentication timestamp
# With that of a GCCF SAML IDP
#
# Author: Doug Harris
#

from org.gluu.model.custom.script.type.session import ApplicationSessionType

from java.util import Date
from java.time import Instant

import uuid

class ApplicationSession(ApplicationSessionType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, configurationAttributes):
        return True

    def destroy(self, configurationAttributes):
        return True

    def getApiVersion(self):
        return 2

    def startSession(self, httpRequest, sessionId, configurationAttributes):
        authnInstant = sessionId.getSessionAttributes().get("authnInstant")
        if authnInstant:
            sessionId.setAuthenticationTime(Date.from(Instant.parse(authnInstant)))
        return True

    def onEvent(self, event):
        return

    def endSession(self, httpRequest, sessionId, configurationAttributes):
        return True