# Module for out-of-band 
#
# Author: Doug Harris

from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.util import ServerUtil
from org.gluu.jsf2.message import FacesMessages
from org.gluu.oxauth.i18n import LanguageBean
from org.gluu.util import StringHelper
from org.gluu.oxauth.service import UserService, AuthenticationService, AuthenticationProtectionService

from javax.faces.application import FacesMessage

from java.security import SecureRandom

import sys
import java

sys.path.append("/opt/gluu/jetty/oxauth/custom/scripts/person_authentication")

from sic import notify

class OOBError(Exception):
    """Base class for exceptions in this module."""
    pass

class OutOfBand:

    def __init__(self):
        return None
    
    def init(self, configurationAttributes, scriptName):

        self.scriptName = scriptName
        print ("OutOfBand. init called from " + self.scriptName)

        self.userService=CdiUtil.bean(UserService)

        self.notify = notify.Notify()
        self.notify.init(configurationAttributes, self.scriptName)

        self.random = SecureRandom.getInstanceStrong()
        print ("OutOfBand. Secure random seeded for  " + self.scriptName)

    def SendOneTimeCode(self, userId=None, mail=None, mobile=None):
        identity = CdiUtil.bean(Identity)

        if mobile is None and mail is None:
            user = self.userService.getUser(userId, "mobile", "mail")
            mobile = user.getAttribute("mobile")
            mail = user.getAttribute("mail")
            if mobile is None and mail is None:
                raise OOBError("OutOfBand. No mobile or mail on the account")

        code = str(100000 + self.random.nextInt(100000))
        print ("oob code: %s" % code)

        notifySucessful = self.notify.sendOobSMS(mobile, code) if mobile is not None else self.notify.sendOobEmail(mail, code)
        if notifySucessful:
            identity.setWorkingParameter("oobCode", code)

        return notifySucessful


    def AuthenticateOutOfBand(self, requestParameters):
        identity = CdiUtil.bean(Identity)
        facesMessages = CdiUtil.bean(FacesMessages)
        languageBean = CdiUtil.bean(LanguageBean)
        authenticationService = CdiUtil.bean(AuthenticationService)
        authenticationProtectionService = CdiUtil.bean(AuthenticationProtectionService)

        #facesMessages.setKeepMessages()
        enteredCode = ServerUtil.getFirstValue(requestParameters, "oob:code")

        if enteredCode == identity.getWorkingParameter("oobCode"):
            return authenticationService.authenticate(identity.getWorkingParameter("userId"))
        else:
            if (authenticationProtectionService.isEnabled()):
                authenticationProtectionService.storeAttempt(identity.getWorkingParameter("userId"), False)
            facesMessages.add(FacesMessage.SEVERITY_ERROR, languageBean.getMessage("sic.invalidCode"))
            return False


    def RegisterOutOfBand(self, requestParameters):
        identity = CdiUtil.bean(Identity)
        facesMessages = CdiUtil.bean(FacesMessages)
        languageBean = CdiUtil.bean(LanguageBean)

        #facesMessages.setKeepMessages()
        mobile = ServerUtil.getFirstValue(requestParameters, "register_oob:mobile")
        mail = ServerUtil.getFirstValue(requestParameters, "register_oob:mail")

        if StringHelper.isEmpty(mobile) and StringHelper.isEmpty(mail):
            facesMessages.add(FacesMessage.SEVERITY_ERROR, languageBean.getMessage("sic.pleaseEnter"))
            return False

        if not self.SendOneTimeCode(None, mail, mobile):
            print ("mail: %s" % mail)
            print ("mobile: %s" % mobile)
            facesMessages.add(FacesMessage.SEVERITY_ERROR, languageBean.getMessage("sic.badEmail" if StringHelper.isNotEmpty(mail) else "sic.badPhone"))
            return False
        else:
            user = self.userService.getUser(identity.getWorkingParameter("userId"), "uid")
            if mobile is not None:
                self.userService.addUserAttribute(user, "mobile", mobile)
            if mail is not None:
                self.userService.addUserAttribute(user, "mail", mail)
            self.userService.updateUser(user)
            return True
