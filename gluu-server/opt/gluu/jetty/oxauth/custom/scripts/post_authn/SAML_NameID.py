# Author: Doug Harris
#

from org.gluu.model.custom.script.type.postauthn import PostAuthnType
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.service import UserService

import sys
sys.path.append("/opt/gluu/jetty/oxauth/custom/scripts/person_authentication")
from sic import account

class PostAuthn(PostAuthnType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, customScript, configurationAttributes):
        self.name = customScript.getName()
        print ("%s: Initializing" % self.name)
        self.account = account.Account()
        return True

    def destroy(self, configurationAttributes):
        print ("%s: Destroyed" % self.name)
        return True

    def getApiVersion(self):
        return 11

    # For SAML clients, check for persistent nameID, create if needed
    def forceReAuthentication(self, context):
        userService = CdiUtil.bean(UserService)

        httpRequest = context.getHttpRequest()
        session = context.getSession()

        entityId = httpRequest.getParameter("entityId")
        spNameQualifier = httpRequest.getParameter("spNameQualifier") or entityId

        user = userService.getUser(session.getUser().getUserId(), "inum", "uid", "persistentId")

        if self.account.getSamlSubject(user, spNameQualifier) is None:
            user = self.account.addSamlSubject(user, spNameQualifier)
            userService.updateUser(user)

        return False

    def forceAuthorization(self, context):
        return False