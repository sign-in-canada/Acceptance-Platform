# Module for managing user accounts
#
# Author: Doug Harris

from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.model.common import User
from org.gluu.oxauth.model.configuration import AppConfiguration
from org.oxauth.persistence.model import PairwiseIdentifier
from org.gluu.jsf2.message import FacesMessages
from org.gluu.oxauth.util import ServerUtil
from org.gluu.oxauth.service import UserService, PairwiseIdentifierService
from org.gluu.oxauth.i18n import LanguageBean
from org.gluu.persist import PersistenceEntryManager
from org.gluu.persist.model.base import CustomEntry
from org.gluu.search.filter import Filter
from org.gluu.util import StringHelper
from org.gluu.model import GluuStatus

from java.net import URI
from javax.faces.context import FacesContext
from javax.faces.application import FacesMessage

from com.microsoft.applicationinsights import TelemetryClient

import uuid, re

class AccountError(Exception):
    """Base class for exceptions in this module."""
    pass

class Account:

    def __init__(self):
        self.userService = CdiUtil.bean(UserService)
        self.pairwiseIdentifierService = CdiUtil.bean(PairwiseIdentifierService)
        self.entryManager = CdiUtil.bean(PersistenceEntryManager)
        self.languageBean = CdiUtil.bean(LanguageBean)
        self.facesMessages = CdiUtil.bean(FacesMessages) 
        self.telemetryClient = TelemetryClient()

    # Creation via external CSP
    def create(self, externalProfile):
        externalUid = externalProfile.get("externalUid")
        if externalUid is not None:
            user = User()
            user.setUserId(uuid.uuid4().hex)
            user.setAttribute("oxExternalUid", externalUid, True)
            return user
        else:
            raise AccountError("Account. Create. External Account is missing externalUid")

    # Creation via registration form
    def register (self, requestParameters):
        uid = ServerUtil.getFirstValue(requestParameters, "registration:username")
        self.facesMessages.setKeepMessages()
        if re.search('\s', uid):
            self.facesMessages.add(FacesMessage.SEVERITY_ERROR, self.languageBean.getMessage("sic.uidnospace"))
            return None

        # Check for available username
        if self.userService.getUser(uid):
            self.facesMessages.add(FacesMessage.SEVERITY_ERROR, self.languageBean.getMessage("sic.uidtaken"))
            return None

        user = User()
        user.setUserId(uid)
        user = self.userService.addUser(user, False)

        # Check for duplicate
        users = self.userService.getUsersByAttribute("uid", uid, False, 2)
        if users.size() > 1:
            message = "Duplicate userid detected"
            self.telemetryClient.trackEvent("SecurityEvent", {"cause": message}, None)
            print ("SECURITY: %s" % message)
            self.entryManager.removeRecursively(user.getDn(), User)
            return None

        return user

    def delete (self, username):
        user = self.userService.getUser(username, "gluuStatus")
        if user.getAttribute("gluuStatus") == GluuStatus.REGISTER.getValue(): # Never delete active accounts
            self.entryManager.removeRecursively(user.getDn(), User)

    # Lookup via external CSP PAI
    def find(self, externalProfile):
        externalUid = externalProfile.get("externalUid")
        if externalUid is not None:
            user = self.userService.getUserByAttribute("oxExternalUid", externalUid, True)
        else:
            raise AccountError("Account. Create. External profile is missing externalUid")

        return user

    # Account Linking
    def getExternalUid(self, user, provider):
        externalUids = user.getAttributeValues("oxExternalUid")
        if externalUids is None:
            return None

        externalPrefix = "passport-" + provider
        for externalUid in externalUids:
           extProvider, extSub = tuple(externalUid.split(":", 1))
           if extProvider == externalPrefix:
               return extSub
        
        return None

    def addExternalUid(self, user, provider, sub=None):
        if sub is None:
            sub = uuid.uuid4().hex
        newExternalId = "passport-%s:%s" %( provider, sub)
        self.userService.addUserAttribute(user, "oxExternalUid", newExternalId, True)
        return sub

    def removeExternalUid(self, user, provider, sub):
        externalUidAttribute = self.userService.getCustomAttribute(user, "oxExternalUid")
        if externalUidAttribute is None:
            return None
        
        externalUids = externalUidAttribute.getValues()

        uidToDelete = "passport-" + provider + ":" + sub
        newExternalUids = []
        for externalUid in externalUids:
            if externalUid != uidToDelete:
                newExternalUids.append(externalUid)

        externalUidAttribute.setValues(newExternalUids)
        externalUidAttribute.setMultiValued(True)
        return user

    def replaceExternalUid(self, user, provider, sub): # For future use (switch credential)
         return NotImplemented

    # SAML RP Subject Management
    def addSamlSubject(self, user, spNameQualifier, nameQualifier = None, nameId = None):
        """Add a new RP SAML Subject to an account."""

        if nameQualifier is None:
            appConfiguration = CdiUtil.bean(AppConfiguration)
            nameQualifier = appConfiguration.getIssuer()

        if nameId is None:
            nameId = "sic" + uuid.uuid4().hex

        newSamlSubject = '%s|%s|%s' % (spNameQualifier, nameQualifier, nameId)

        self.userService.addUserAttribute(user, "persistentId", newSamlSubject, True)

        return user

    def getSamlSubject(self, user, spNameQualifier):
        persistentIds = user.getAttributeValues("persistentId")
        if persistentIds is None:
            return None

        for persistentId in persistentIds:
            samlSubject = persistentId.split("|")
            if samlSubject[0] == spNameQualifier:
                return samlSubject[1], samlSubject[2]
        
        return None

# OpenID RP subject management

    def addOpenIdSubject(self, user, client, sub):

        sectorIdentifier = self.getSectorId(client)

        userInum = user.getAttribute("inum")
        pairwiseSubject = PairwiseIdentifier(sectorIdentifier, client.getClientId(), userInum)
        pairwiseSubject.setId(sub)
        pairwiseSubject.setDn(self.pairwiseIdentifierService.getDnForPairwiseIdentifier(pairwiseSubject.getId(), userInum))
        self.pairwiseIdentifierService.addPairwiseIdentifier(userInum, pairwiseSubject)

    def getOpenIdSubject(self, user, client):
        sectorIdentifier = self.getSectorId(client)
        userInum = user.getAttribute("inum")
        pairwiseSubject = self.pairwiseIdentifierService.findPairWiseIdentifier(userInum, sectorIdentifier, client.getClientId())
        if pairwiseSubject is not None:
            return pairwiseSubject.getId()
        else:
            return None

    def getSectorId(self, client):
        sectorIdentifierUri = client.getSectorIdentifierUri()
        if not sectorIdentifierUri:
            redirectUris = client.getRedirectUris()
            if redirectUris and len(redirectUris) > 0:
                sectorIdentifierUri = redirectUris[0]

        if sectorIdentifierUri is None:
            raise AccountError("account. addOpenIdSubject unable to find client sector identifier Uri")

        return URI.create(sectorIdentifierUri).getHost()

# MFA Management
    def getMfaMethod(self, user):
        if self.userService.countFido2RegisteredDevices(user.getUserId()) > 0:
            return "fido"
        elif self.getExternalUid(user, "mfa") is not None:
            return "totp"
        elif user.getAttribute("mobile") is not None:
            return "sms"
        elif user.getAttribute("mail") is not None:
            return "email"
        else:
            return None

    def backupNeeded(self, userId):
        user = self.userService.getUser(userId, "mobile", "secretAnswer")
        mobile = user.getAttributeValues("mobile")
        backupCodes = user.getAttributeValues("secretAnswer")
        if self.userService.countFido2RegisteredDevices(user.getUserId()) > 1:
            return False
        elif self.getExternalUid(user, "mfa") is not None:
            return False
        elif mobile is not None and len(mobile) > 1:
            return False
        elif backupCodes is not None:
            return False
        else:
            return True

# FIDO2 authenticator management

    def removeFido2Registrations(self, user):
        userInum = user.getAttribute("inum")
        baseDn = self.userService.getBaseDnForFido2RegistrationEntries(userInum)
        userInumFilter = Filter.createEqualityFilter("personInum", userInum)
        registeredFilter = Filter.createEqualityFilter("oxStatus", "registered")
        filter = Filter.createANDFilter(userInumFilter, registeredFilter)

        self.entryManager.remove(baseDn, CustomEntry, filter, 100)

# Identity claim ingestion

    def mergeAttributes(self, user, externalProfile):
                
        for attr in externalProfile:
            # "provider" and "externalUid" are disregarded if part of mapping
            if attr not in ["provider", "externalUid"]:
                values = externalProfile[attr]
                user.setAttribute(attr, values)
