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
from java.util import Date

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
        print ("OutOfBand. Lockout threshold for %s is %s failed attempts." % (self.scriptName, self.lockoutThreshold))

        self.telemetryClient = TelemetryClient()

        self.userService=CdiUtil.bean(UserService)

        self.notify = notify.Notify()
        self.notify.init(configurationAttributes, self.scriptName)

        self.random = SecureRandom.getInstanceStrong()
        print ("OutOfBand. Secure random seeded for  " + self.scriptName)

    def SendOneTimeCode(self, userId=None, channel=None, contact=None):
        identity = CdiUtil.bean(Identity)

        if contact is not None: # Registrastion
            if channel == "sms":
                mobile = contact
            elif channel == "email":
                mail = contact
            else:
                raise OOBError("OutOfBand. Invalid channel: %s" % channel)
        else: # Authentication
            user = self.userService.getUser(userId, "mobile", "mail")
            mobile = user.getAttribute("mobile")
            mail = user.getAttribute("mail")
            if mobile is not None:
                channel = "sms"
            elif mail is not None:
                channel = "email"
            else:
                raise OOBError("OutOfBand. No mobile or mail on the account")

        code = str(100000 + self.random.nextInt(100000))

        notifySucessful = self.notify.sendOobSMS(mobile, code) if channel == "sms" else self.notify.sendOobEmail(mail, code)
        if notifySucessful:
            identity.setWorkingParameter("oobCode", code)
            identity.setWorkingParameter("oobExpiry", str(Instant.now().getEpochSecond() + self.codeLifetime))

        return notifySucessful

    def AuthenticateOutOfBand(self, requestParameters):
        identity = CdiUtil.bean(Identity)
        facesMessages = CdiUtil.bean(FacesMessages)
        authenticationService = CdiUtil.bean(AuthenticationService)
        authenticationProtectionService = CdiUtil.bean(AuthenticationProtectionService)

        session = identity.getSessionId()
        userId = identity.getWorkingParameter("userId")
        contact = identity.getWorkingParameter("oobContact")

        telemetry = {"sid" : session.getOutsideSid()}
        duration = float((Date().getTime() - session.getLastUsedAt().getTime()) / 1000)

        if (authenticationProtectionService.isEnabled()):
            authenticationProtectionService.doDelayIfNeeded(userId)

        codeExpiry = int(identity.getWorkingParameter("oobExpiry"))
        codeExpired = codeExpiry < Instant.now().getEpochSecond()

        if codeExpired:
            addMessage("oob:code", FacesMessage.SEVERITY_ERROR, "sic.expiredCode")
            addMessage("oob:resend", FacesMessage.SEVERITY_INFO, "sic.newCode")

        if codeExpired or requestParameters.containsKey("oob:resend"):
            telemetry["result"] = "failed"
            telemetry["reason"] = "code expired" if codeExpired else "new code requested"
            self.telemetryClient.trackEvent("OOB Authentication", telemetry, {"durationInSeconds": duration})

            if (authenticationProtectionService.isEnabled()):
                authenticationProtectionService.storeAttempt(userId, False)
            identity.setWorkingParameter("oobCode", None) # Start over
            addMessage("oob:resend", FacesMessage.SEVERITY_INFO, "sic.newCode")
            return False

        enteredCode = ServerUtil.getFirstValue(requestParameters, "oob:code")
        user = self.userService.getUser(userId, "uid", "gluuStatus", "oxCountInvalidLogin", "locale")

        if StringHelper.equals(user.getAttribute("gluuStatus"), GluuStatus.INACTIVE.getValue()):
             addMessage("oob:code", FacesMessage.SEVERITY_ERROR, "sic.lockedOut")
             return False

        if enteredCode == identity.getWorkingParameter("oobCode"):
            facesMessages.clear()
            updateNeeded = False
            telemetry["result"] = "success"

            if contact is not None: # Registration
                telemetry["step"] = "code verification"
                self.telemetryClient.trackEvent("OOB Registration", telemetry, {"durationInSeconds": duration})
                channel = identity.getWorkingParameter("oobChannel")
                if channel == "sms":
                    self.userService.addUserAttribute(user, "mobile", contact)
                elif channel == "email":
                    self.userService.addUserAttribute(user, "mail", contact)
                updateNeeded = True
            else:
                self.telemetryClient.trackEvent("OOB Authentication", telemetry, {"durationInSeconds": duration})

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
            telemetry["result"] = "failed"
            telemetry["reason"] = "invalid code"
            if contact is not None:
                telemetry["step"] = "code verification"
                self.telemetryClient.trackEvent("OOB Registration", telemetry, {"durationInSeconds": duration})
            else:
                self.telemetryClient.trackEvent("OOB Authentication", telemetry, {"durationInSeconds": duration})

            if (authenticationProtectionService.isEnabled()):
                authenticationProtectionService.storeAttempt(userId, False)
            attempts = StringHelper.toInteger(user.getAttribute("oxCountInvalidLogin"), 0)
            attempts += 1
            user.setAttribute("oxCountInvalidLogin", StringHelper.toString(attempts))
            if attempts >= self.lockoutThreshold:
                self.telemetryClient.trackEvent("Account Locked",
                                                    {"reason": "Too many failed OOB attempts",
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
        authenticationProtectionService = CdiUtil.bean(AuthenticationProtectionService)

        session = identity.getSessionId()
        userId = identity.getWorkingParameter("userId")
        mobile = ServerUtil.getFirstValue(requestParameters, "register_oob:mobile")
        mail = ServerUtil.getFirstValue(requestParameters, "register_oob:email")

        telemetry = {"sid" : session.getOutsideSid(),
                     "step": "contact entry"}
        duration = float((Date().getTime() - session.getLastUsedAt().getTime()) / 1000)

        if StringHelper.isEmpty(mobile) and StringHelper.isEmpty(mail):
            addMessage("register_oob:mobile", FacesMessage.SEVERITY_ERROR, "sic.pleaseEnter")
            addMessage("register_oob:email", FacesMessage.SEVERITY_ERROR, "sic.pleaseEnter")
            telemetry["result"] = "failed"
            telemetry["reason"] = "Nothing entered"
            self.telemetryClient.trackEvent("OOB Registration", telemetry, {"durationInSeconds": duration})
            return False
        elif StringHelper.isNotEmpty(mobile):
            channel = "sms"
            contact = mobile
        else:
            channel = "email"
            contact = mail
        telemetry["channel"] = channel

        if identity.getWorkingParameter("oobCode") is not None:
            # This means the user previously tried to register but then backed up
            # and changed the email address or mobile number. Possible DoS
            if authenticationProtectionService.isEnabled():
                authenticationProtectionService.storeAttempt(userId, False)
                authenticationProtectionService.doDelayIfNeeded(userId)

        if not self.SendOneTimeCode(None, channel, contact):
            telemetry["result"] = "failed"
            if channel == "sms":
                addMessage("register_oob:mobile", FacesMessage.SEVERITY_ERROR, "sic.badPhone")
                telemetry["reason"] = "Invalid mobile number"
            else:
                addMessage("register_oob:email", FacesMessage.SEVERITY_ERROR, "sic.badEmail")
                telemetry["reason"] = "Invalid email address"
            self.telemetryClient.trackEvent("OOB Registration", telemetry, {"durationInSeconds": duration})
            return False
        else:
            facesMessages.clear()
            telemetry["result"] = "success"
            self.telemetryClient.trackEvent("OOB Registration", telemetry, {"durationInSeconds": duration})
            identity.setWorkingParameter("oobContact", contact)
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
