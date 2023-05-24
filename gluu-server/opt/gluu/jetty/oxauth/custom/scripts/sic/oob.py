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
from org.gluu.oxauth.service import UserService, AuthenticationService, AuthenticationProtectionService, SessionIdService
from org.gluu.model import GluuStatus
from org.gluu.oxauth.model.configuration import AppConfiguration
from org.gluu.oxauth.model.authorize import AuthorizeRequestParam

from javax.faces.application import FacesMessage

from java.security import SecureRandom
from java.time import Instant
from java.util import ArrayList, Date
from java.lang import Thread

from com.microsoft.applicationinsights import TelemetryClient
from com.google.i18n.phonenumbers import PhoneNumberUtil, NumberParseException
from org.apache.commons.validator.routines import EmailValidator

import sys
import re
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
        print ("OutOfBand. Secure random seeded for " + self.scriptName)

        self.phoneUtil = PhoneNumberUtil.getInstance()
        self.emailValidator = EmailValidator.getInstance()

    def SendOneTimeCode(self, userId=None, channel=None, contact=None):
        identity = CdiUtil.bean(Identity)
        facesResources = CdiUtil.bean(FacesResources)
        facesContext = facesResources.getFacesContext()
        externalContext = facesResources.getExternalContext()
        facesFlash = externalContext.getFlash()

        if contact is not None: # Registrastion
            if channel == "sms":
                mobile = contact
            elif channel == "email":
                mail = contact
            else:
                raise OOBError("OutOfBand. Invalid channel: %s" % channel)
        else: # Authentication
            user = self.userService.getUser(userId, "mobile", "mail")
            mobile = user.getAttributeValues("mobile")
            mail = user.getAttributeValues("mail")
            if mobile is not None:
                channel = "sms"
                if mobile.size() < 2:
                    facesFlash.put("backupNeeded", True)
                mobile = mobile.get(0)
            elif mail is not None:
                channel = "email"
                if mail.size() < 2:
                    facesFlash.put("backupNeeded", True)
                mail = mail.get(0)
            else:
                raise OOBError("OutOfBand. No mobile or mail on the account")

        code = str(100000 + self.random.nextInt(900000))

        notifySucessful = self.notify.sendOobSMS(mobile, code) if channel == "sms" else self.notify.sendOobEmail(mail, code)
        if notifySucessful:
            identity.setWorkingParameter("oobCode", code)
            identity.setWorkingParameter("oobExpiry", str(Instant.now().getEpochSecond() + self.codeLifetime))
            if userId is None:
                identity.setWorkingParameter("oobDisplay", mobile if channel == "sms" else mail)
            else:
                identity.setWorkingParameter("oobDisplay", maskPhone(mobile) if channel == "sms" else mail)

        return notifySucessful

    def AuthenticateOutOfBand(self, requestParameters):
        identity = CdiUtil.bean(Identity)
        facesResources = CdiUtil.bean(FacesResources)
        facesContext = facesResources.getFacesContext()
        externalContext = facesResources.getExternalContext()
        facesFlash = externalContext.getFlash()
        facesMessages = CdiUtil.bean(FacesMessages)
        authenticationService = CdiUtil.bean(AuthenticationService)
        authenticationProtectionService = CdiUtil.bean(AuthenticationProtectionService)

        session = identity.getSessionId()
        userId = identity.getWorkingParameter("userId")
        contact = identity.getWorkingParameter("oobContact")

        telemetry = {"sid" : session.getOutsideSid()}
        duration = float((Date().getTime() - session.getLastUsedAt().getTime()) / 1000)

        codeExpiry = int(identity.getWorkingParameter("oobExpiry"))
        codeExpired = codeExpiry < Instant.now().getEpochSecond()

        if codeExpired:
            addMessage("oob:code", FacesMessage.SEVERITY_ERROR, "sic.expiredCode")
            addMessage("oob:resend", FacesMessage.SEVERITY_INFO, "sic.newCode")

        if codeExpired or requestParameters.containsKey("oob:resend"):
            telemetry["result"] = "failed"
            telemetry["reason"] = "code expired" if codeExpired else "new code requested"
            self.telemetryClient.trackEvent("OOB Authentication", telemetry, {"durationInSeconds": duration})
            throttle(authenticationProtectionService, session, userId)
            identity.setWorkingParameter("oobCode", None) # Start over
            addMessage("oob:resend", FacesMessage.SEVERITY_INFO, "sic.newCode")
            return False

        enteredCode = ServerUtil.getFirstValue(requestParameters, "oob:code")
        if StringHelper.isEmpty(enteredCode):
            addMessage("oob:code", FacesMessage.SEVERITY_ERROR, "sic.enterCode")
            return False
        elif len(enteredCode) < 6:
            addMessage("oob:code", FacesMessage.SEVERITY_ERROR, "sic.codeSmall")
            return False
        elif len(enteredCode) > 6:
            addMessage("oob:code", FacesMessage.SEVERITY_ERROR, "sic.codeBig")
            return False

        user = self.userService.getUser(userId, "uid", "gluuStatus", "oxCountInvalidLogin", "mobile", "mail", "locale")

        if StringHelper.equals(user.getAttribute("gluuStatus"), GluuStatus.INACTIVE.getValue()):
             addMessage("oob:code", FacesMessage.SEVERITY_ERROR, "sic.lockedOut")
             throttle(authenticationProtectionService, session, userId)
             return False

        if enteredCode == identity.getWorkingParameter("oobCode"):
            facesMessages.clear()
            identity.setWorkingParameter("oobCode", None)

            updateNeeded = False
            telemetry["result"] = "success"

            if contact is not None: # Registration
                if identity.getWorkingParameter("mfaMethod") and checkInvalidSession():
                    return False
                
                telemetry["step"] = "code verification"
                self.telemetryClient.trackEvent("OOB Registration", telemetry, {"durationInSeconds": duration})
                channel = identity.getWorkingParameter("oobChannel")
                attribute = "mobile" if channel == "sms" else "mail"
                existing = user.getAttributeValues(attribute)
                if not existing or contact not in existing:
                    if identity.getWorkingParameter("manageTask") == "oobReplace":
                        user.setAttribute(attribute, contact, True)
                        addMessage(None, FacesMessage.SEVERITY_INFO, "sic.phoneReplaced", contact)
                    else:
                        self.userService.addUserAttribute(user, attribute, contact, True)
                        if not existing or len(existing) == 0:
                            addMessage(None, FacesMessage.SEVERITY_INFO, "sic.phoneVerified")
                        else:
                            addMessage(None, FacesMessage.SEVERITY_INFO, "sic.backupPhoneVerified")
                    updateNeeded = True
                identity.setWorkingParameter("mfaMethod", channel)
                
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
        else: # Invalid code
            telemetry["result"] = "failed"
            telemetry["reason"] = "invalid code"
            if contact is not None:
                telemetry["step"] = "code verification"
                self.telemetryClient.trackEvent("OOB Registration", telemetry, {"durationInSeconds": duration})
            else:
                self.telemetryClient.trackEvent("OOB Authentication", telemetry, {"durationInSeconds": duration})

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
            throttle(authenticationProtectionService, session, userId)

            return False

    def RegisterOutOfBand(self, requestParameters):
        identity = CdiUtil.bean(Identity)
        facesMessages = CdiUtil.bean(FacesMessages)
        authenticationProtectionService = CdiUtil.bean(AuthenticationProtectionService)

        session = identity.getSessionId()
        userId = identity.getWorkingParameter("userId")
        channel = identity.getWorkingParameter("oobChannel")
        paramName = "register_oob:%s" % ("mobile" if channel == "sms" else "email")
        contact = ServerUtil.getFirstValue(requestParameters, paramName)

        telemetry = {"sid" : session.getOutsideSid(),
                     "step": "contact entry",
                     "channel": channel}
        duration = float((Date().getTime() - session.getLastUsedAt().getTime()) / 1000)

        if StringHelper.isEmpty(contact):
            addMessage(paramName, FacesMessage.SEVERITY_ERROR, "sic.enterPhone" if channel == "sms" else "sic.enterEmail")
            telemetry["result"] = "failed"
            telemetry["reason"] = "Nothing entered"
            self.telemetryClient.trackEvent("OOB Registration", telemetry, {"durationInSeconds": duration})
            return False

        # Load existing contacts for duplicate checks
        attribute = "mobile" if channel == "sms" else "mail"
        user = self.userService.getUser(userId, attribute)
        existingContacts = user.getAttributeValues(attribute)

        if channel == "sms": 
            # Validate the phone number
            try:
                phoneNumber = self.phoneUtil.parse(contact, "CA")
                if not self.phoneUtil.isValidNumber(phoneNumber):
                    raise OOBError("Invalid phone number")
                contact = self.phoneUtil.format(phoneNumber, PhoneNumberUtil.PhoneNumberFormat.NATIONAL)
            except (NumberParseException, OOBError):
                print ("Error: " + str(sys.exc_info()[1]))
                addMessage(paramName, FacesMessage.SEVERITY_ERROR, "sic.invalidPhone")
                telemetry["result"] = "failed"
                telemetry["reason"] = "Invalid phone mumber"
                self.telemetryClient.trackEvent("OOB Registration", telemetry, {"durationInSeconds": duration})
                return False

            # Check for excessive use by multiple accounts
            if len(self.userService.getUsersByAttribute("mobile", contact, True, 16)) > 15:
                addMessage(paramName, FacesMessage.SEVERITY_ERROR, "sic.phoneTooMany")
                return False

            if existingContacts is not None and len(existingContacts) > 0:
                # Check for duplicate
                for existingContact in existingContacts:
                    existingPhone = self.phoneUtil.parse(existingContact, "CA")
                    if self.phoneUtil.isNumberMatch(phoneNumber, existingPhone) != PhoneNumberUtil.MatchType.NO_MATCH:
                        addMessage(paramName, FacesMessage.SEVERITY_ERROR, "sic.duplicatePhone")
                        telemetry["result"] = "failed"
                        telemetry["reason"] = "Duplicate phone number"
                        self.telemetryClient.trackEvent("OOB Registration", telemetry, {"durationInSeconds": duration})
                        return False
        else:
            # Validate the email address
            contact = contact.lower()
            if not self.emailValidator.isValid(contact):
                addMessage(paramName, FacesMessage.SEVERITY_ERROR, "sic.invalidEmail")
                telemetry["result"] = "failed"
                telemetry["reason"] = "Invalid email address"
                self.telemetryClient.trackEvent("OOB Registration", telemetry, {"durationInSeconds": duration})
                return False
            
            # Check for duplicate
            if existingContacts is not None and contact in existingContacts:
                addMessage(paramName, FacesMessage.SEVERITY_ERROR, "sic.duplicateEmail")
                telemetry["result"] = "failed"
                telemetry["reason"] = "Duplicate email address"
                self.telemetryClient.trackEvent("OOB Registration", telemetry, {"durationInSeconds": duration})
                return False

        if identity.getWorkingParameter("oobCode") is not None:
            # This means the user previously tried to register but then backed up
            # and changed the email address or mobile number. Possible DoS
            throttle(authenticationProtectionService, session, userId)

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

    def makeDefault(self, requestParameters):
        if checkInvalidSession():
            return False

        index = ServerUtil.getFirstValue(requestParameters, "i")
        if index.isdigit():
            return self.changeDefaultContact("sms", int(index))
        else:
            print ("%s OufOfBand makeDefault: Invalid contact index: %s" % (self.scriptName, index))
            return False

    def changeDefaultContact(self, channel, index):
        identity = CdiUtil.bean(Identity)

        if checkInvalidSession():
            return False

        userId = identity.getWorkingParameter("userId")
        attribute = "mobile" if channel == "sms" else "mail"
        user = self.userService.getUser(userId, "uid", attribute)
        existingContacts = user.getAttributeObjectValues(attribute)

        if index < 0 or index >= len(existingContacts):
            print ("%s OufOfBand changeDefaultContact: Contact index out of range: %s" % (self.scriptName, index))
            return False

        existingContacts[0], existingContacts[index] = existingContacts[index], existingContacts[0]
        self.userService.updateUser(user)
        identity.setWorkingParameter("manageTask", "oobMakeDefault")
        addMessage(None, FacesMessage.SEVERITY_INFO, "sic.phoneNewDefault", maskPhone(existingContacts[index]))
        return True

    def changeContact(self, requestParameters):
        identity = CdiUtil.bean(Identity)

        if checkInvalidSession():
            return False

        userId = identity.getWorkingParameter("userId")

        index = ServerUtil.getFirstValue(requestParameters, "i")
        if not index.isdigit():
            print ("%s OufOfBand delete: Invalid contact index: %s" % (self.scriptName, index))
            return False
        else:
            index = int(index)

        mobile = ServerUtil.getFirstValue(requestParameters, "change_oob:mobile")
        # Validate the phone number
        if StringHelper.isEmpty(mobile):
            addMessage("change_oob:mobile", FacesMessage.SEVERITY_ERROR, "sic.enterPhone")
            return False
        try:
            phoneNumber = self.phoneUtil.parse(mobile, "CA")
            if not self.phoneUtil.isValidNumber(phoneNumber):
                raise OOBError("Invalid phone number")
        except (NumberParseException, OOBError):
            addMessage("change_oob:mobile", FacesMessage.SEVERITY_ERROR, "sic.invalidPhone")
            return False
        
        user = self.userService.getUser(userId, "uid", "mobile")
        existingContacts = user.getAttributeObjectValues("mobile")

        if existingContacts is None or len(existingContacts) == 0:
            print ("%s OufOfBand deleteContact: No contacts to delete!" % self.scriptName)

        existingPhone = self.phoneUtil.parse(existingContacts[index], "CA")
        if self.phoneUtil.isNumberMatch(phoneNumber, existingPhone) == PhoneNumberUtil.MatchType.NO_MATCH:
            addMessage("change_oob:mobile", FacesMessage.SEVERITY_ERROR, "sic.wrongPhone")
            return False

        if len(existingContacts) > 1: # Delete
            newContacts = ArrayList(existingContacts)
            newContacts.remove(index)
            user.setAttribute("mobile", newContacts, True)
            self.userService.updateUser(user)
            identity.setWorkingParameter("manageTask", "oobDelete")
            addMessage(None, FacesMessage.SEVERITY_INFO, "sic.phoneDeleted", existingContacts[index])
            return True
        else: # Replace
            identity.setWorkingParameter("oobContact", self.phoneUtil.format(phoneNumber, PhoneNumberUtil.PhoneNumberFormat.NATIONAL))
            identity.setWorkingParameter("manageTask", "oobReplace")

def checkInvalidSession():
    identity = CdiUtil.bean(Identity)
    authenticationService = CdiUtil.bean(AuthenticationService)
    session = identity.getSessionId()

    if authenticationService.getAuthenticatedUser() is None:
        # Not signed in
        return True
    elif Date().getTime() - session.getAuthenticationTime().getTime() > 1200000:
        # Signed in too long ago
        return True
    else:
        return False

def maskPhone (phoneNumber):
    return re.sub('\d', '*', phoneNumber, sum(map(unicode.isdigit, phoneNumber)) - 4)

def addMessage(uiControl, severity, msgId, *extras):
    languageBean = CdiUtil.bean(LanguageBean)
    facesResources = CdiUtil.bean(FacesResources)
    facesContext = facesResources.getFacesContext()
    externalContext = facesResources.getExternalContext()
    msgText = languageBean.getMessage(msgId) % extras
    message = FacesMessage(severity, msgText, msgText)
    facesContext.addMessage(uiControl, message)
    externalContext.getFlash().setKeepMessages(True)

def throttle(authenticationProtectionService, session, userId):
    if authenticationProtectionService.isEnabled():
        authenticationProtectionService.storeAttempt(userId, False)
        attempts = authenticationProtectionService.getNonExpiredAttempts(userId)
        attemptCount = 0
        if attempts is not None:
            attemptCount = attempts.getAuthenticationAttempts().size()
            if attemptCount < 5:
                return
            elif attemptCount < 10:
                # Progressive rate limiting
                Thread.sleep((2**(attemptCount - 4) * 1000))
            else: # boot-em
                CdiUtil.bean(SessionIdService).remove(session)
