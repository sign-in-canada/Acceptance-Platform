# Module for out-of-band 
#
# Author: Doug Harris

from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.util import ServerUtil
from org.gluu.jsf2.service import FacesResources
from org.gluu.jsf2.message import FacesMessages
from org.gluu.oxauth.i18n import LanguageBean
from org.gluu.util import StringHelper
from org.gluu.oxauth.service import UserService, AuthenticationService, AuthenticationProtectionService
from org.gluu.model import GluuStatus
from org.gluu.oxauth.model.authorize import AuthorizeRequestParam

from javax.faces.application import FacesMessage

from java.security import SecureRandom
from java.time import Instant

from com.microsoft.applicationinsights import TelemetryClient

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

        self.codeLifetime = 600
        if configurationAttributes.containsKey("oob_code_lifetime"):
            self.codeLifetime = StringHelper.toInteger(configurationAttributes.get("oob_code_lifetime").getValue2())
        print ("OutOfBand. Code lifetime for %s is %s seconds." % (self.scriptName, self.codeLifetime))

        self.lockoutThreshold = 100
        if configurationAttributes.containsKey("lockout_threshold"):
            self.lockoutThreshold = StringHelper.toInteger(configurationAttributes.get("lockout_threshold").getValue2())
        print ("OutOfBand. Lockout threshold fir %s is %s failed attempts." % (self.scriptName, self.lockoutThreshold))

        self.telemetryClient = TelemetryClient()

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
            identity.setWorkingParameter("oobExpires", str(Instant.now().getEpochSecond() + self.codeLifetime))

        return notifySucessful

    def AuthenticateOutOfBand(self, requestParameters):
        identity = CdiUtil.bean(Identity)
        facesMessages = CdiUtil.bean(FacesMessages)
        authenticationService = CdiUtil.bean(AuthenticationService)
        authenticationProtectionService = CdiUtil.bean(AuthenticationProtectionService)

        if requestParameters.containsKey("oob:cancel"):
            return False

        userId = identity.getWorkingParameter("userId")
        contact = identity.getWorkingParameter("oobContact")

        if (authenticationProtectionService.isEnabled()):
            authenticationProtectionService.doDelayIfNeeded(userId)

        if requestParameters.containsKey("oob:resend"):
            if contact is not None: # Registration
                oobChannel = identity.getWorkingParameter("oobChannel")
                print ("OOB type: %s" % oobChannel)
                if oobChannel == "sms":
                    self.SendOneTimeCode(None, None, contact)
                elif oobChannel == "email":
                    self.SendOneTimeCode(None, contact, None)
            else:
                self.SendOneTimeCode(userId)
            addMessage("oob:resend", FacesMessage.SEVERITY_INFO, "sic.newCode")
            return False

        expires = int(identity.getWorkingParameter("oobExpires"))
        if expires < Instant.now().getEpochSecond():
            print ("OOB Expired for %s" % identity.getWorkingParameter("userId"))
            addMessage("oob:code", FacesMessage.SEVERITY_ERROR, "sic.expiredCode")
            addMessage("oob:resend", FacesMessage.SEVERITY_INFO, "sic.newCode")
            return False

        enteredCode = ServerUtil.getFirstValue(requestParameters, "oob:code")
        user = self.userService.getUser(userId, "uid", "gluuStatus", "oxCountInvalidLogin", "locale")

        if StringHelper.equals(user.getAttribute("gluuStatus"), GluuStatus.INACTIVE.getValue()):
             addMessage("oob:code", FacesMessage.SEVERITY_ERROR, "sic.lockedOut")
             return False

        if enteredCode == identity.getWorkingParameter("oobCode"):
            print ("OOB Success for %s" % identity.getWorkingParameter("userId"))
            facesMessages.clear()
            updateNeeded = False

            if contact is not None: # Registration
                oobChannel = identity.getWorkingParameter("oobChannel")
                if oobChannel == "sms":
                    self.userService.addUserAttribute(user, "mobile", contact)
                elif oobChannel == "email":
                    self.userService.addUserAttribute(user, "mail", contact)
                updateNeeded = True

            if user.getAttribute("oxCountInvalidLogin") is not None:
                user.setAttribute("oxCountInvalidLogin", "0")
                updateNeeded = True

            sessionAttributes = identity.getSessionId().getSessionAttributes()
            locale = sessionAttributes.get(AuthorizeRequestParam.UI_LOCALES)
            if locale != user.getAttribute("locale", True, False):
                user.setAttribute("locale", locale, False)
                updateNeeded = True

            if updateNeeded:
                self.userService.updateUser(user)

            return authenticationService.authenticate(userId)
        else:
            print ("OOB Wrong for %s" % userId)
            if (authenticationProtectionService.isEnabled()):
                authenticationProtectionService.storeAttempt(userId, False)
            attempts = StringHelper.toInteger(user.getAttribute("oxCountInvalidLogin"), 0)
            attempts += 1
            user.setAttribute("oxCountInvalidLogin", StringHelper.toString(attempts))
            if attempts >= self.lockoutThreshold:
                self.telemetryClient.trackEvent("Account Locked",
                                                    {"cause": "Too many failed OOB attempts",
                                                     "user": userId}, None)
                user.setAttribute("gluuStatus", GluuStatus.INACTIVE.getValue())
                addMessage("oob:code", FacesMessage.SEVERITY_ERROR, "sic.lockedOut")
            else:
                addMessage("oob:code", FacesMessage.SEVERITY_ERROR, "sic.invalidCode")
            self.userService.updateUser(user)

            return False

    def RegisterOutOfBand(self, requestParameters):
        identity = CdiUtil.bean(Identity)
        facesMessages = CdiUtil.bean(FacesMessages)

        mobile = ServerUtil.getFirstValue(requestParameters, "register_oob:mobile")
        mail = ServerUtil.getFirstValue(requestParameters, "register_oob:email")

        if StringHelper.isEmpty(mobile) and StringHelper.isEmpty(mail):
            addMessage("register_oob:mobile", FacesMessage.SEVERITY_ERROR, "sic.pleaseEnter")
            addMessage("register_oob:email", FacesMessage.SEVERITY_ERROR, "sic.pleaseEnter")
            return False

        if not self.SendOneTimeCode(None, mail, mobile):
            if StringHelper.isNotEmpty(mobile):
                addMessage("register_oob:mobile", FacesMessage.SEVERITY_ERROR, "sic.badPhone")
            else:
                addMessage("register_oob:email", FacesMessage.SEVERITY_ERROR, "sic.badEmail")
            return False
        else:
            facesMessages.clear()
            user = self.userService.getUser(identity.getWorkingParameter("userId"), "uid")
            if mobile is not None:
                identity.setWorkingParameter("oobContact", mobile)
            if mail is not None:
                identity.setWorkingParameter("oobContact", mail)
            return True

def addMessage(uiControl, severity, msgId):
    languageBean = CdiUtil.bean(LanguageBean)
    facesResources = CdiUtil.bean(FacesResources)
    facesContext = facesResources.getFacesContext()
    externalContext = facesResources.getExternalContext()
    msgText = languageBean.getMessage(msgId)
    message = FacesMessage(severity, msgText, msgText)
    facesContext.addMessage(uiControl, message)
    externalContext.getFlash().setKeepMessages(True)
