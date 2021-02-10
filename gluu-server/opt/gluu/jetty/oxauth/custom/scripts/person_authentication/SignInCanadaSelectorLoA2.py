# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2016, Gluu
#
# Author: Pawel Pietrzynski
#

from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.security import Identity
from org.gluu.util import StringHelper
from org.gluu.oxauth.util import ServerUtil
from org.gluu.oxauth.service import AuthenticationService, UserService, ClientService, SessionIdService
from org.gluu.oxauth.i18n import LanguageBean
from org.gluu.jsf2.service import FacesResources
from java.util import ArrayList, Arrays

import sys
import java
import json

REMOTE_DEBUG = False

if REMOTE_DEBUG:
    try:
        import sys
        sys.path.append("/opt/libs/pydevd")
        import pydevd
    except ImportError as ex:
        print "Failed to import pydevd: %s" % ex
        raise
    
class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, configurationAttributes):
        print "IDP Chooser. init called"

        print "IDP Chooser. init - Load RP customization file."
        if not configurationAttributes.containsKey("selector_page_content_file"):
            print "IDP Chooser. Initialization Failed, RP customization file parameter 'selector_page_content_file' missing."
            return False

        content_file = configurationAttributes.get("selector_page_content_file").getValue2()

        # Load customization content from file
        f = open(content_file, 'r')
        try:
            self.selectorPageContent = json.loads(f.read())
        except:
            print "IDP Chooser. Initialization. Failed to load RP customization content from file: %s" % content_file
            return False
        finally:
            f.close()
            
        success = self.processMfaEntityIDsProperty(configurationAttributes)

        print "IDP Chooser. Initialized successfully"
        return True   

    def destroy(self, configurationAttributes):
        print "IDP Chooser. destroy called"
        print "IDP Chooser. Destroyed successfully"
        return True

    def getApiVersion(self):
        return 2

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)
            
        print "IDP Chooser. isValidAuthenticationMethod called"

        identity = CdiUtil.bean(Identity)
        new_acr_value = identity.getWorkingParameter("new_acr_value")
        print "IDP Chooser. isValidAuthenticationMethod: new_acr_value retrieved = '%s'" % new_acr_value

        if (new_acr_value != None):
            return False
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        print "IDP Chooser. getAlternativeAuthenticationMethod called"
        identity = CdiUtil.bean(Identity)
        new_acr_value = identity.getWorkingParameter("new_acr_value")
        print "IDP Chooser. getAlternativeAuthenticationMethod: new_acr_value retrieved = '%s'" % new_acr_value
        return new_acr_value

    def authenticate(self, configurationAttributes, requestParameters, step):
        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        print "IDP Chooser. authenticate called for step '%s'" % step

        identity = CdiUtil.bean(Identity)
        sessionId = identity.getSessionId()
        sessionAttributes = sessionId.getSessionAttributes()

        if (not requestParameters.containsKey("loginForm")):
            # Unexpected navigation. Redirect back to the RP or error page
            facesResources = CdiUtil.bean(FacesResources)
            facesContext = facesResources.getFacesContext()
            externalContext = facesContext.getCurrentInstance().getExternalContext()
            print ("IDP Chooser. authenticate called from the wrong page: " + externalContext.getRequestServletPath())
            clientId = sessionAttributes.get("client_id")
            clientService = CdiUtil.bean(ClientService)
            client = clientService.getClient(clientId)
            clientUri = client.getClientUri()
            if (clientUri is not None):
                externalContext.redirect(clientUri)
            else:
                externalContext.redirect("error.htm")
            return False

        # SWITCH - if the switch credential is in 3_DO_SWITCH state, then do the switch
        if ( sessionAttributes.get("switchFlowStatus") == "3_DO_SWITCH" ):
            # first get the target user
            userService = CdiUtil.bean(UserService)
            sourceUser = userService.getUser( sessionAttributes.get("switchSourceAuthenticatedUser") )
            targetUser = userService.getUser( sessionAttributes.get("switchTargetAuthenticatedUser") )

            if ( targetUser == None):
                print "IDP Chooser. authenticate: Failed to fetch target user '%s'" % sessionAttributes.get("switchTargetAuthenticatedUser")
                sessionAttributes.remove( "switchFlowStatus" )
                ## SESSION_SAFE - update
                CdiUtil.bean(SessionIdService).updateSessionId(sessionId)
                return False
            elif (sourceUser == None ):
                print "IDP Chooser. authenticate: Failed to fetch source user '%s'" % sessionAttributes.get("switchSourceAuthenticatedUser")
                sessionAttributes.remove( "switchFlowStatus" )
                ## SESSION_SAFE - update
                CdiUtil.bean(SessionIdService).updateSessionId(sessionId)
                return False
            else:
                switchPersistentId = sessionAttributes.get( "switchPersistentId" )
                # FIRST set the persistentId for the entitySpNameQualifier in the target user
                tergetPersistentIds = targetUser.getAttributeValues("persistentId")
                tmpList = ArrayList(tergetPersistentIds) if tergetPersistentIds != None else ArrayList()
                tmpList.add( switchPersistentId )
                targetUser.setAttribute( "persistentId", tmpList )
                userService.updateUser(targetUser)

                # SECOND remove the persistentId for the entitySpNameQualifier in the source user
                sourcePersistentIds = sourceUser.getAttributeValues("persistentId")
                tmpList = ArrayList()
                # build a new list of persistentIds without the switched ID
                for sourcePersistentId in sourcePersistentIds:
                    if ( sourcePersistentId != switchPersistentId ):
                        tmpList.add( sessionAttributes.get( "switchPersistentId" ) )
                sourceUser.setAttribute( "persistentId", tmpList )
                try:
                    userService.updateUser(sourceUser)
                except:
                    # THIRD if failed to update the source then reset the source user
                    print "IDP Chooser. authenticate: Failed to update source user, '%s', reverting target user " % sessionAttributes.get("switchSourceAuthenticatedUser")
                    print "Exception: ", sys.exc_info()[1]
                    tergetPersistentIds = targetUser.getAttributeValues("persistentId")
                    tmpList = ArrayList(tergetPersistentIds) if tergetPersistentIds != None else ArrayList()
                    tmpList.add( sessionAttributes.get( "switchPersistentId" ) )
                    targetUser.setAttribute( "persistentId", tmpList )
                    userService.updateUser(targetUser)
                    return False

                # finish the switch flow
                sessionAttributes.put( "switchFlowStatus", "4_FINISHED" )
                ## SESSION_SAFE - update
                return CdiUtil.bean(AuthenticationService).authenticate( targetUser.getUserId() )
        else:
            # process the ACR selection
            new_acr_provider_value = self.getAcrValueFromAuth(requestParameters)
            print "IDP Chooser. authenticate: saving new acr provider = '%s'" % new_acr_provider_value
            new_acr_provider_elements = StringHelper.split(new_acr_provider_value, ":")
            new_acr_value = new_acr_provider_elements[0]
            new_acr_provider = new_acr_provider_elements[1]
            print "IDP Chooser. authenticate: setting new_acr_value = '%s'" % new_acr_value
            print "IDP Chooser. authenticate: setting new_acr_provider = '%s'" % new_acr_provider
            
            # Validate the ACR is allowed for the current entityId/client
            allowedCredentials = sessionAttributes.get("pageContent")["credentials"]
            allowSetNewAcr = False
            for cred in StringHelper.split(allowedCredentials,','):
                if (new_acr_provider_value.find(cred) == -1):
                    allowSetNewAcr = True
                    
            if ( allowSetNewAcr ):
                identity.setWorkingParameter("new_acr_value", new_acr_value)
                sessionAttributes.put("selectedProvider", new_acr_provider)
            else:
                print "IDP Chooser. authenticate: provider '%s' not allowed for this client" % new_acr_provider
                return False

            # SWITCH - Reading switch credential checkbox
            switchFlowStatus = sessionAttributes.get("switchFlowStatus")
            if (switchFlowStatus == None):
                switchSelected = self.getSwitchValueFromAuth(requestParameters)
                if (switchSelected == True):
                    print "IDP Chooser. authenticate SWITCH FLOW: setting 1_GET_SOURCE"
                    sessionAttributes.put("switchFlowStatus", "1_GET_SOURCE")

        ## SESSION_SAFE - update
        CdiUtil.bean(SessionIdService).updateSessionId(sessionId)

        if step == 1:
            return True
        else:
            return False

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        print "IDP Chooser. prepareForStep called for step '%s'" % step

        identity = CdiUtil.bean(Identity)
        sessionId = identity.getSessionId()
        sessionAttributes = sessionId.getSessionAttributes()
        entityId = sessionAttributes.get("entityId")
        entitySpNameQualifier = sessionAttributes.get("spNameQualifier")

        # entityId is used for UI branding. Handle getting entityId if it's an OIDC client
        if ( entityId == None ):
            # First get the client_id (should be deterministic ... ?????)
            currentClientId = sessionAttributes.get("client_id")
            # Call the ClientService and get all clients
            clientService = CdiUtil.bean(ClientService)
            oidcClient = clientService.getClient( currentClientId )
            if ( oidcClient != None ):
                entityId = "oidc:%s" % oidcClient.getClientName()
                sessionAttributes.put("entityId", entityId)

            # SpNameQualifier is used for persistenId generation. Handle getting entitySpNameQualifier if it's an OIDC client
            if ( entitySpNameQualifier == None ):
                # Look for value saved in the PolicyURL field in the client configurationAttributes
                clientPolicyUri = oidcClient.getPolicyUri()
                if ( StringHelper.isNotEmpty(clientPolicyUri) ):
                    # Set it to the clientPolicyUri if absent
                    entitySpNameQualifier = clientPolicyUri
                    sessionAttributes.put("spNameQualifier", clientPolicyUri)
        # FIXME - For now as an error scenario if it's not found put a default
        if ( entityId == None ):
            entityId = "_default"

        # CUSTOMIZATION - Select which page body elements will be rendered
        if (sessionAttributes.get("pageContent") == None):
            # CUSTOMIZATION - FIRST try direct match
            pageContent = self.selectorPageContent.get(entityId)

            # CUSTOMIZATION - SECOND try prefix match
            if ( pageContent == None ):
                for contentKey in self.selectorPageContent.keys():
                    if ( entityId.find(contentKey) == 0 ):
                        pageContent = self.selectorPageContent.get(contentKey)

            # CUSTOMIZATION - LASTLY go to default content
            if ( pageContent == None ):
                pageContent = self.selectorPageContent.get( "_default" )

            # CUSTOMIZATION - save the page content in session for reference in xhtml pages
            if ( pageContent != None ):
                sessionAttributes.put( "pageContent", pageContent )
            else:
                # We have an error - log it and fail
                print "IDP Chooser. prepareForStep ERROR: '_default' and '%s' page content missing in file " % (entityId, configurationAttributes.get("selector_page_content_file").getValue2() )
                return False
            
            # CUSTOMIZATION - Select which credential buttons will show up
            showCredentials = sessionAttributes.get("pageContent")["credentials"]
            allCredentials = self.selectorPageContent["_default"]["credentials"]
            for cred in StringHelper.split(allCredentials,','):
                if (showCredentials.find(cred) == -1):
                    sessionAttributes.put("hide_cred_"+cred, False)

        # SWITCH - update switch flow step if coming back with a user
        if ( sessionAttributes.get("switchFlowStatus") == "1_GET_SOURCE" and sessionAttributes.get("auth_user") != None ):
            # first get the source user and validate the persistentId exists for the entitySpNameQualifier
            userService = CdiUtil.bean(UserService)
            sourceUser = userService.getUser( sessionAttributes.get("switchSourceAuthenticatedUser") )
            # then find the persistenId for the entitySpNameQualifier in the source user
            sourcePersistentIds = sourceUser.getAttributeValues("persistentId")
            if ( sourcePersistentIds != None ):
                # go through source user persistentIds
                for userPersistentId in sourcePersistentIds:
                    existingMappedRp = StringHelper.split(userPersistentId,'|')[0]
                    # if the current RP matches, save the persistenId for the target
                    if ( userPersistentId.find(entitySpNameQualifier) > -1 ):
                        sessionAttributes.put( "switchPersistentId", userPersistentId )

            print "IDP Chooser. prepareForStep SWITCH FLOW: setting 2_GET_TARGET"
            sessionAttributes.put("switchFlowStatus",  "2_GET_TARGET" )

        # SWITCH - move to switch screen if the target has been authenticated
        elif ( sessionAttributes.get("switchFlowStatus") == "2_GET_TARGET" and sessionAttributes.get("auth_user") != None ):
            # first get the target user
            userService = CdiUtil.bean(UserService)
            targetUser = userService.getUser( sessionAttributes.get("switchTargetAuthenticatedUser") )
            # then find the persistenId for the entitySpNameQualifier in the target user
            targetPersistentIds = targetUser.getAttributeValues("persistentId")
            switchCurrentState = "AVAILABLE"
            if ( targetPersistentIds != None ):
                # go through source user persistentIds
                for userPersistentId in targetPersistentIds:
                    existingMappedRp = StringHelper.split(userPersistentId,'|')[0]
                    # if the current RP already has a persistentId then mark it
                    if ( entitySpNameQualifier != None and userPersistentId.find(entitySpNameQualifier) > -1 ):
                        switchCurrentState = "NOT AVAILABLE - Persistent ID already exists for this RP in the target"

            if ( switchCurrentState == "AVAILABLE" ):
                print "IDP Chooser. prepareForStep SWITCH FLOW: setting 3_DO_SWITCH"
                sessionAttributes.put("switchFlowStatus", "3_DO_SWITCH" )
            else:
                print "IDP Chooser. prepareForStep SWITCH FLOW: FAILED - target contains mapping for %s" % entitySpNameQualifier
                sessionAttributes.put("switchFlowStatus", "4_FINISHED" )

            sessionAttributes.put( "switchCurrentState", switchCurrentState )

        # MFA - update mfa flow status - check if the entityId is on the list of MFA applications
        mfaFlowStatus = sessionAttributes.get("mfaFlowStatus")
        print "IDP Chooser. prepareForStep Fetched mfaFlowStatus = '%s'" % mfaFlowStatus
        for mfaEntityId in StringHelper.split(self.entityids_with_mfa,','):
            if (mfaEntityId == entityId):
                # if the status is blank then we set it to MFA_1_REQUIRED. This also means first pass so no MFA forwarding
                if ( mfaFlowStatus == None ):
                    mfaFlowStatus = "MFA_1_REQUIRED"
                    print "IDP Chooser. prepareForStep Setting  mfaFlowStatus = '%s'" % mfaFlowStatus
                    sessionAttributes.put("mfaFlowStatus", mfaFlowStatus)

                # we check that we have an authenticated user, which is a signal to trigger MFA
                elif ( sessionAttributes.get("auth_user") != None ):
                    print "IDP Chooser. prepareForStep For mfaFlowStatus found authenticated user = '%s'" % sessionAttributes.get("auth_user")
                    # SWITCH - we check that we are not in a switch flow, or switch flow has finished
                    switchFlowStatus = sessionAttributes.get("switchSourceAuthenticatedUser")
                    if ( switchFlowStatus == None or switchFlowStatus == "4_FINISHED" ):
                        mfaFlowStatus = "MFA_2_IN_PROGRESS"
                        print "IDP Chooser. prepareForStep Setting  mfaFlowStatus = '%s' and [new_acr_value to 'passport_social'] and [selectedProvider to 'mfa']" % mfaFlowStatus
                        sessionAttributes.put("mfaFlowStatus", mfaFlowStatus)
                        print "IDP Chooser. prepareForStep Setting  [new_acr_value = 'passport_social'] and [selectedProvider = 'mfa']"
                        identity.setWorkingParameter("new_acr_value", "passport_social")
                        sessionAttributes.put("selectedProvider", "mfa")

        ## SESSION_SAFE - update
        CdiUtil.bean(SessionIdService).updateSessionId(sessionId)

        print "IDP Chooser. prepareForStep. got session '%s'"  % identity.getSessionId().toString()

        if (step == 1 or step == 2):
            return True
        else:
            return False

    def getNextStep(self, configurationAttributes, requestParameters, step):
        print "IDP Chooser. getNextStep called for step '%s' (returns -1)" % step
        return -1

    def getExtraParametersForStep(self, configurationAttributes, step):
        print "IDP Chooser. getExtraParametersForStep called for step '%s'" % step
        return Arrays.asList("new_acr_value")

    def getCountAuthenticationSteps(self, configurationAttributes):
        print "IDP Chooser. getCountAuthenticationSteps called"
        # SWITCH - if we did perform a switch then end the flow with the authenticated user
        if ( CdiUtil.bean(Identity).getSessionId() != None ):
            switchFlowStatus = CdiUtil.bean(Identity).getSessionId().getSessionAttributes().get("switchFlowStatus")
            mfaFlowStatus    = CdiUtil.bean(Identity).getSessionId().getSessionAttributes().get("mfaFlowStatus")
            print "IDP Chooser. getCountAuthenticationSteps session found, switchFlowStatus = '%s'" % switchFlowStatus
            print "IDP Chooser. getCountAuthenticationSteps session found, mfaFlowStatus    = '%s'" % mfaFlowStatus
            # check that we are not in a SWITCH flow
            if ( mfaFlowStatus != None and switchFlowStatus == "4_FINISHED" ):
                print "IDP Chooser. getCountAuthenticationSteps (SWITCH COMPLETE) returning 1"
                return 1
            #elif ( mfaFlowStatus == "MFA_3_COMPLETE" ):
            #    print "IDP Chooser. getCountAuthenticationSteps (MFA COMPLETE) returning 1"
            #    return 1

        return 2


    def getPageForStep(self, configurationAttributes, step):
        if REMOTE_DEBUG:
            pydevd.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)

        print "IDP Chooser. getPageForStep called for step '%s'" % step

        facesResources = CdiUtil.bean(FacesResources)
        languageBean = CdiUtil.bean(LanguageBean)

        # Get the locale/language
        locale = languageBean.getLocale().getLanguage()
        print "IDP Chooser. getPageForStep called for step '%s' and locale '%s'" % (step, locale)
        # Make sure it matches "en" or "fr"
        if (locale != "en" and locale != "fr"):
            locale = "en"

        if ( CdiUtil.bean(Identity).getSessionId() != None ):
            switchFlowStatus = CdiUtil.bean(Identity).getSessionId().getSessionAttributes().get("switchFlowStatus")
            print "IDP Chooser. getPageForStep session found, switchFlowStatus = '%s'" % switchFlowStatus
            if ( switchFlowStatus != None and switchFlowStatus == "1_GET_SOURCE" ):
                return "/select2.xhtml"
            if ( switchFlowStatus != None and switchFlowStatus == "2_GET_TARGET" ):
                return "/switch.xhtml"

        # determine what page to display
        if locale == "en":
            return "/en/select.xhtml"
        if locale == "fr":
            return "/fr/choisir.xhtml"


    def logout(self, configurationAttributes, requestParameters):
        print "IDP Chooser. logout called"
        return True


    def getAcrValueFromAuth(self, requestParameters):
        print "IDP Chooser. getAcrValueFromAuth called"
        try:
            toBeFeatched = "loginForm:acrname"
            print "IDP Chooser. getAcrValueFromAuth: fetching '%s'" % toBeFeatched
            new_acr_provider_value = ServerUtil.getFirstValue(requestParameters, toBeFeatched)

            print "IDP Chooser. getAcrValueFromAuth: fetched new_acr_provider_value '%s'" % new_acr_provider_value
            if StringHelper.isNotEmpty(new_acr_provider_value):
                return new_acr_provider_value
            return None
        except Exception, err:
            print("IDP Chooser. getAcrValueFromAuth Exception: " + str(err))


    def getSwitchValueFromAuth(self, requestParameters):
        print "IDP Chooser. getSwitchValueFromAuth called"
        try:
            switchCredential = "loginForm:switchCredentialBox"
            print "IDP Chooser. getSwitchValueFromAuth: fetching '%s'" % switchCredential
            switch_credential_selected = ServerUtil.getFirstValue(requestParameters, switchCredential)

            print "IDP Chooser. getSwitchValueFromAuth: fetched switch_credential_selected = '%s'" % switch_credential_selected
            if switch_credential_selected == "on":
                return True
            return False
        except Exception, err:
            print("IDP Chooser. getSwitchValueFromAuth Exception: " + str(err))


    def processMfaEntityIDsProperty(self, attrs):
        param = attrs.get("entityids_with_mfa")

        if param != None:
            entityids_with_mfa = param.getValue2()
            
            # TODO: validate string is a csv

            self.entityids_with_mfa = entityids_with_mfa
            return True

        print "Passport. processMfaEntityIDsProperty. Property entityids_with_mfa found as invalid CSV"
        return False
