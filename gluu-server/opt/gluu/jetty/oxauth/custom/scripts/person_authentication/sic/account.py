# Module for managing user accounts
#
# Author: Doug Harris

from org.gluu.oxauth.model.common import User
from org.oxauth.persistence.model import PairwiseIdentifier
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.service import UserService, PairwiseIdentifierService

from java.util import ArrayList
from javax.faces.context import FacesContext

import uuid

class AccountError(Exception):
    """Base class for exceptions in this module."""
    pass

class Account:

    def __init__(self):
        self.userService = CdiUtil.bean(UserService)
        self.pairwiseIdentifierService = CdiUtil.bean(PairwiseIdentifierService)

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
            user = self.userService.getUserByAttribute("oxExternalUid", externalUid)
        else:
            raise AccountError("Account. Create. External profile is missing externalUid")

        return user

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

        persistentIds = user.getAttributeValues("persistentId")
        if persistentIds is None:
            persistentIds = ArrayList()
        
        persistentIds.add(newSamlSubject)

        user.setAttribute("persistentId", persistentIds, True)

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

    def addOpenIdSubject(self, user, clientId, sectorId, sub):

        userInum = user.getAttribute("inum")
        pairwiseSubject = PairwiseIdentifier(sectorId, clientId, userInum)
        pairwiseSubject.setId(sub)
        pairwiseSubject.setDn(self.pairwiseIdentifierService.getDnForPairwiseIdentifier(pairwiseSubject.getId(), userInum))
        self.pairwiseIdentifierService.addPairwiseIdentifier(userInum, pairwiseSubject)

    def getOpenIdSubject(self, user, clientId, sectorId):

        userInum = user.getAttribute("inum")
        pairwiseSubject = self.pairwiseIdentifierService.findPairwiseIdentifier(userInum, sectorId, clientId)
        if pairwiseSubject is not None:
            return pairwiseSubject.getId()
        else:
            return None

# Identity claim ingestion

    def mergeAttributes(self, user, externalProfile):
                
        for attr in externalProfile:
            # "provider" and "externalUid" are disregarded if part of mapping
            if attr not in ["provider", "externalUid"]:
                values = externalProfile[attr]
                user.setAttribute(attr, values)
