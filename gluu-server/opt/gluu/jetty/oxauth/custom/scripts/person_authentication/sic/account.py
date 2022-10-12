# Module for managing user accounts
#
# Author: Doug Harris

from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.model.common import User
from org.oxauth.persistence.model import PairwiseIdentifier
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.service import UserService, ClientService, PairwiseIdentifierService
from org.gluu.persist import PersistenceEntryManager
from org.gluu.persist.model.base import CustomEntry
from org.gluu.search.filter import Filter

from java.net import URI
from javax.faces.context import FacesContext

import sys
import uuid

class AccountError(Exception):
    """Base class for exceptions in this module."""
    pass

class Account:

    def __init__(self):
        self.userService = CdiUtil.bean(UserService)
        self.clientService = CdiUtil.bean(ClientService)
        self.pairwiseIdentifierService = CdiUtil.bean(PairwiseIdentifierService)
        self.entryManager = CdiUtil.bean(PersistenceEntryManager)

    # Creation
    def create(self, externalProfile):

        externalUid = externalProfile.get("externalUid")
        if externalUid is not None:
            user = User()
            user.setUserId(uuid.uuid4().hex)
            user.setAttribute("oxExternalUid", externalUid, True)
            return user
        else:
            raise AccountError("Account. Create. External Account is missing externalUid")

    # Lookup
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

    def replaceExternalUid(self, user, externalProfile): # For future use (switch credential)
         return NotImplemented

    # SAML RP Subject Management
    def addSamlSubject(self, user, spNameQualifier, nameQualifier = None, nameId = None):
        """Add a new RP SAML Subject to an account."""

        if nameQualifier is None:
            facesContext = CdiUtil.bean(FacesContext)
            serverName = facesContext.getExternalContext().getRequest().getServerName()
            nameQualifier = "https://%s" % serverName

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

    # MFA replacement management
    def replace2FA(self, user):
        try:
            # Disable the Subject Identifier of the old 2nd authenticator from the user account
            externalUids = user.getAttributeValues("oxExternalUid")
            externalUidsToUpdate = False

            if externalUids is None:
                return False
            else:
                for index, externalUid in enumerate(externalUids):
                    if externalUid.startswith('passport-mfa'):
                        externalUids[index] = externalUid.replace("passport-mfa", "passport-disabled-mfa")
                        externalUidsToUpdate = True

                if externalUidsToUpdate:
                    user.setAttribute("oxExternalUid", externalUids, True)
                    self.userService.updateUser(user)

            # Disable the pairwise subjects issued to RPs that use the old 2nd authenticator
            userInum = user.getAttribute("inum")
            credHwmAttribute = self.userService.getCustomAttribute(user, "credHighWaterMark")
            if credHwmAttribute is not None:
                credHwms = credHwmAttribute.getValues()
                for i in range(len(credHwms)):
                    cid, level = tuple(credHwms[i].split("|"))
                    if int(level) == 100: 
                        client = self.clientService.getClient(cid) 
                        if client is not None:
                            clientSectorId = self.getSectorId(client)
                            pairWiseIdentifier = self.pairwiseIdentifierService.findPairWiseIdentifier(userInum, clientSectorId, cid)

                            if pairWiseIdentifier is not None:
                                pwiSectorIdentifier = pairWiseIdentifier.getSectorIdentifier()
                                if pwiSectorIdentifier is not None and not pwiSectorIdentifier.startswith('disabled.'):
                                    pairWiseIdentifier.setSectorIdentifier("disabled." + pwiSectorIdentifier)
                                    self.entryManager.persist(pairWiseIdentifier)
        
        except:
            print ("Exception: ", sys.exc_info()[1])
            return False

        return True