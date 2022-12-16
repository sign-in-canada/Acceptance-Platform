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
from java.time import Instant

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
            identity.setWorkingParameter("oobExpires", str(Instant.now().getEpochSecond() + 600)) # 10 minutes

        return notifySucessful

    def AuthenticateOutOfBand(self, requestParameters):
        identity = CdiUtil.bean(Identity)
        facesMessages = CdiUtil.bean(FacesMessages)
        languageBean = CdiUtil.bean(LanguageBean)
        authenticationService = CdiUtil.bean(AuthenticationService)
        authenticationProtectionService = CdiUtil.bean(AuthenticationProtectionService)

        if requestParameters.containsKey("oob:cancel"):
            return False

        expires = int(identity.getWorkingParameter("oobExpires"))
        print ("Expires: " + str(expires))
        print ("Now: " + str(Instant.now().getEpochSecond()))
        if expires < Instant.now().getEpochSecond():
            print ("OOB Expired for %s" % identity.getWorkingParameter("userId"))
            facesMessages.add("oob:code", FacesMessage.SEVERITY_ERROR, languageBean.getMessage("sic.expiredCode"))
            return False

        enteredCode = ServerUtil.getFirstValue(requestParameters, "oob:code")
        print ("Comparing [%s] to [%s]" % (enteredCode, identity.getWorkingParameter("oobCode")))

        if enteredCode == identity.getWorkingParameter("oobCode"):
            facesMessages.clear()
            print ("OOB Success for %s" % identity.getWorkingParameter("userId"))
            contact = identity.getWorkingParameter("oobContact")
            if contact is not None: # Registration
                mfaMethod = identity.getWorkingParameter("mfaMethod")
                user = self.userService.getUser(identity.getWorkingParameter("userId"), "uid")
                if mfaMethod == "sms":
                    self.userService.addUserAttribute(user, "mobile", contact)
                elif mfaMethod == "email":
                    self.userService.addUserAttribute(user, "mail", contact)
                self.userService.updateUser(user)

            return authenticationService.authenticate(identity.getWorkingParameter("userId"))
        else:
            print ("OOB Wrong for %s" % identity.getWorkingParameter("userId"))
            if (authenticationProtectionService.isEnabled()):
                authenticationProtectionService.storeAttempt(identity.getWorkingParameter("userId"), False)
            facesMessages.add("oob:code", FacesMessage.SEVERITY_ERROR, languageBean.getMessage("sic.invalidCode"))
            return False

    def RegisterOutOfBand(self, requestParameters):
        identity = CdiUtil.bean(Identity)
        facesMessages = CdiUtil.bean(FacesMessages)
        languageBean = CdiUtil.bean(LanguageBean)

        mobile = ServerUtil.getFirstValue(requestParameters, "register_oob:mobile")
        mail = ServerUtil.getFirstValue(requestParameters, "register_oob:email")

        if StringHelper.isEmpty(mobile) and StringHelper.isEmpty(mail):
            facesMessages.add(FacesMessage.SEVERITY_ERROR, languageBean.getMessage("sic.pleaseEnter"))
            return False

        if not self.SendOneTimeCode(None, mail, mobile):
            if StringHelper.isNotEmpty(mobile):
                facesMessages.add("register_oob:mobile", FacesMessage.SEVERITY_ERROR, languageBean.getMessage("sic.badPhone"))
            else:
                facesMessages.add("register_oob:email", FacesMessage.SEVERITY_ERROR, languageBean.getMessage("sic.badEmail"))
            return False
        else:
            facesMessages.clear()
            user = self.userService.getUser(identity.getWorkingParameter("userId"), "uid")
            if mobile is not None:
                identity.setWorkingParameter("oobContact", mobile)
            if mail is not None:
                identity.setWorkingParameter("oobContact", mail)
            return True
