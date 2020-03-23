# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2019, Gluu
#
# Author: Jose Gonzalez
# Author: Yuriy Movchan
#
from org.gluu.jsf2.service import FacesService
from org.gluu.jsf2.message import FacesMessages

from org.gluu.oxauth.model.common import User, WebKeyStorage, SessionIdState
from org.gluu.oxauth.model.configuration import AppConfiguration
from org.gluu.oxauth.model.crypto import CryptoProviderFactory
from org.gluu.oxauth.model.jwt import Jwt, JwtClaimName
from org.gluu.oxauth.model.util import Base64Util
from org.gluu.oxauth.service import AppInitializer, AuthenticationService, UserService, SessionIdService
from org.gluu.oxauth.service.net import HttpService
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.util import ServerUtil
from org.gluu.config.oxtrust import LdapOxPassportConfiguration
from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.util import StringHelper
from java.util import ArrayList, Arrays, Collections
from javax.faces.application import FacesMessage
from javax.faces.context import FacesContext

from java.security import Key
from javax.crypto import Cipher
from javax.crypto.spec import SecretKeySpec, IvParameterSpec
from org.bouncycastle.jce.provider import BouncyCastleProvider


import json
import sys
import uuid
import time
import base64
import random
import string

class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, configurationAttributes):
        print "Passport-social. init called"

        self.extensionModule = self.loadExternalModule(configurationAttributes.get("extension_module"))
        extensionResult = self.extensionInit(configurationAttributes)
        if extensionResult != None:
            return extensionResult

        # Load customization content from file
        login_hint_key_file = configurationAttributes.get("login_hint_key").getValue2()
        print "Passport-social. init. Initialization success"
        f = open( login_hint_key_file, 'r' )
        try:
            key = f.read()
            self.aesKey = key[:16]
        except:
            print "Passport-social. Initialization. Failed reading login_hint AES key file: %s" % login_hint_key_file
            return False
        finally:
            f.close()

        print "Passport-social. init. Behaviour is social"
        success = self.processKeyStoreProperties(configurationAttributes)

        if success:
            self.providerKey = "provider"
            self.customAuthzParameter = self.getCustomAuthzParameter(configurationAttributes.get("authz_req_param_provider"))
            self.passportDN = self.getPassportConfigDN()
            print "Passport-social. init. Initialization success"
        else:
            print "Passport-social. init. Initialization failed"
        return success


    def destroy(self, configurationAttributes):
        print "Passport-social. destroy called"
        return True


    def getApiVersion(self):
        return 2


    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        print "Passport-social. isValidAuthenticationMethod called"

        identity = CdiUtil.bean(Identity)
        sessionAttributes = identity.getSessionId().getSessionAttributes()
        print "Passport-social. isValidAuthenticationMethod. got session '%s'"  % identity.getSessionId().toString()

        # the authentication did not happen or failed, return to the chooser page
        selectedProvider = sessionAttributes.get("selectedProvider")
        userState = identity.getSessionId().getState()
        print "Passport-social. isValidAuthenticationMethod. Found selectedProvider = %s" % selectedProvider
        print "Passport-social. isValidAuthenticationMethod. Found state = %s" % userState
        # selectedProvider will be None after first passport script execution because it will be removed
        if ( userState == SessionIdState.UNAUTHENTICATED and selectedProvider == None ):
            print "Passport-social. isValidAuthenticationMethod. Found unauthenticated sessions after step 1, meaning cancel/failure."
            return False

        # SWITCH - invalidate this authentication only if the switchFlow is ON
        if ( sessionAttributes.get("switchFlowStatus") == "1_GET_SOURCE" and sessionAttributes.get("switchSourceAuthenticatedProvider") != None ):
            print "Passport DEBUG. isValidAuthenticationMethod SWITCH FLOW set to 1_GET_SOURCE, auth complete, returning False"
            return False
        elif ( sessionAttributes.get("switchFlowStatus") == "2_GET_TARGET" and sessionAttributes.get("switchTargetAuthenticatedProvider") != None ):
            print "Passport DEBUG. isValidAuthenticationMethod SWITCH FLOW set to 2_GET_TARGET, auth complete, returning False"
            return False

        # TOFO: For now take this out since we are not going back to SELECT_LOA2 but staying in PASSPORT_SOCIAL to do MFA. Uncomment when refactoring
        # elif ( sessionAttributes.get("mfaFlowStatus") == "MFA_1_REQUIRED" ):
        #     print "Passport DEBUG. isValidAuthenticationMethod MFA FLOW set to MFA_1_REQUIRED, auth complete, returning False"
        #     return False

        return True


    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        print "Passport-social. getAlternativeAuthenticationMethod called"
        return "select_loa2"


    def authenticate(self, configurationAttributes, requestParameters, step):

        extensionResult = self.extensionAuthenticate(configurationAttributes, requestParameters, step)
        if extensionResult != None:
            return extensionResult

        print "Passport-social. authenticate for step %s called" % str(step)
        identity = CdiUtil.bean(Identity)

        if step == 1:
            # Get JWT token
            jwt_param = ServerUtil.getFirstValue(requestParameters, "user")
            if jwt_param != None:
                print "Passport-social. authenticate for step 1. JWT user profile token found"

                # Parse JWT and validate
                jwt = Jwt.parse(jwt_param)
                if not self.validSignature(jwt):
                    return False

                if self.jwtHasExpired(jwt):
                    return False

                (user_profile, jsonp) = self.getUserProfile(jwt)
                if user_profile == None:
                    return False

                return self.attemptAuthentication(identity, user_profile, jsonp)

            #See passportlogin.xhtml
            provider = ServerUtil.getFirstValue(requestParameters, "loginForm:provider")
            if StringHelper.isEmpty(provider):

                #it's username + passw auth
                print "Passport-social. authenticate for step 1. Basic authentication detected"
                logged_in = False

                credentials = identity.getCredentials()
                user_name = credentials.getUsername()
                user_password = credentials.getPassword()

                if StringHelper.isNotEmptyString(user_name) and StringHelper.isNotEmptyString(user_password):
                    authenticationService = CdiUtil.bean(AuthenticationService)
                    logged_in = authenticationService.authenticate(user_name, user_password)

                print "Passport-social. authenticate for step 1. Basic authentication returned: %s" % logged_in
                return logged_in

            elif provider in self.registeredProviders:
                #it's a recognized external IDP
                identity.setWorkingParameter("selectedProvider", provider)
                print "Passport-social. authenticate for step 1. Retrying step 1"
                #see prepareForStep (step = 1)
                return True

        if step == 2:
            mail = ServerUtil.getFirstValue(requestParameters, "loginForm:email")
            jsonp = identity.getWorkingParameter("passport_user_profile")

            if mail == None:
                self.setMessageError(FacesMessage.SEVERITY_ERROR, "Email was missing in user profile")
            elif jsonp != None:
                # Completion of profile takes place
                user_profile = json.loads(jsonp)
                user_profile["mail"] = mail

                return self.attemptAuthentication(identity, user_profile, jsonp)

            print "Passport-social. authenticate for step 2. Failed: expected mail value in HTTP request and json profile in session"
            return False


    def prepareForStep(self, configurationAttributes, requestParameters, step):

        extensionResult = self.extensionPrepareForStep(configurationAttributes, requestParameters, step)
        if extensionResult != None:
            return extensionResult

        print "Passport-social. prepareForStep called for step %s" % str(step)
        identity = CdiUtil.bean(Identity)
        sessionAttributes = identity.getSessionId().getSessionAttributes()
        sessionId = identity.getSessionId()

        if step == 1:
            #re-read the strategies config (for instance to know which strategies have enabled the email account linking)
            self.parseProviderConfigs()
            identity.setWorkingParameter("externalProviders", json.dumps(self.registeredProviders))

            providerParam = self.customAuthzParameter
            providerFromSession = None
            url = None

            print "Passport-social. prepareForStep. got session '%s'" % identity.getSessionId().toString()

            sessionAttributes = identity.getSessionId().getSessionAttributes()
            self.skipProfileUpdate = StringHelper.equalsIgnoreCase(sessionAttributes.get("skipPassportProfileUpdate"), "true")
            
            # MFAgetCountAuthenticationSteps
            # 1. Check if there has been an authenticated user
            # 2. Check that mfa flow status is MFA_2_IN_PROGRESS
            # 3. Set the selected provider to "mfa"
            # 4. Get the MFA PAI from the user profile
            userService = CdiUtil.bean(UserService)
            mfaPai = None
            if ( sessionAttributes.get("auth_user") != None and sessionAttributes.get("mfaFlowStatus") == "MFA_2_IN_PROGRESS" ):
                # set the provider to "mfa"
                sessionAttributes.put("selectedProvider", "mfa")
                # get the MFA PAI from the external UID
                mfaOriginalUid = sessionAttributes.get( "authenticatedUser" )
                mfaUserByUid = userService.getUserByAttribute("uid", mfaOriginalUid)
                # go through the values to find the MFA PAI
                mfaUserOxExternalUids = mfaUserByUid.getAttributeValues("oxExternalUid")
                if (mfaUserOxExternalUids != None):
                    for mfaUserOxExternalUid in mfaUserOxExternalUids:
                        if ( mfaUserOxExternalUid.find("passport-mfa:") > -1 ):
                            mfaPai = StringHelper.split(mfaUserOxExternalUid,':')[1]
                print "Passport-social. prepareForStep. Using mfaPai = '%s'" % mfaPai
            elif ( sessionAttributes.get("selectedProvider") == "mfa"):
                print "Passport-social. prepareForStep. ERROR: 'selectedProvider' is 'mfa' but not in the MFA flow, Exiting"
                return False

            # This is added to the script by a previous module if the provider is preselected
            providerFromSession = sessionAttributes.get("selectedProvider")

            if providerFromSession != None:
                # Reset the provider in session in case the choice has to be made again
                print "Passport-social. prepareForStep. Setting selectedProvider from session  = '%s'" % providerFromSession
                identity.setWorkingParameter("selectedProvider", providerFromSession)
                sessionAttributes.remove("selectedProvider")
                ## SESSION_SAFE - update
                CdiUtil.bean(SessionIdService).updateSessionId(sessionId)

            loginHint = None
            if (mfaPai != None):
                entityId = sessionAttributes.get( "entityId" )
                # concatinate mfaPai and entityId
                plaintext = mfaPai + '|' + entityId
                
                randomSource = string.ascii_letters + string.digits
                loginHint = self.encryptAES( self.aesKey , plaintext )

            # This param could have been set previously in authenticate step if current step is being retried
            provider = identity.getWorkingParameter("selectedProvider")
            if provider != None:
                url = self.getPassportRedirectUrl(provider, loginHint)
                identity.setWorkingParameter("selectedProvider", None)

            elif providerParam != None:
                paramValue = sessionAttributes.get(providerParam)

                if paramValue != None:
                    print "Passport-social. prepareForStep. Found value in custom param of authorization request: %s" % paramValue
                    provider = self.getProviderFromJson(paramValue)

                    if provider == None:
                        print "Passport-social. prepareForStep. A provider value could not be extracted from custom authorization request parameter"
                    elif not provider in self.registeredProviders:
                        print "Passport-social. prepareForStep. Provider '%s' not part of known configured IDPs/OPs" % provider
                    else:
                        url = self.getPassportRedirectUrl(provider, loginHint)

            if url == None:
                print "Passport-social. prepareForStep. A page to manually select an identity provider will be shown"
            else:
                facesService = CdiUtil.bean(FacesService)
                facesService.redirectToExternalURL(url)
            
        return True


    def getExtraParametersForStep(self, configurationAttributes, step):
        print "Passport-social. getExtraParametersForStep called with step %s" % str(step)
        if step == 1:
            return Arrays.asList("selectedProvider", "externalProviders")
        elif step == 2:
            return Arrays.asList("passport_user_profile")
        return None


    def getCountAuthenticationSteps(self, configurationAttributes):
        print "Passport-social. getCountAuthenticationSteps called"
        identity = CdiUtil.bean(Identity)
        if identity.getWorkingParameter("passport_user_profile") != None:
            return 2
        if identity.getSessionId().getSessionAttributes().get("switchFlowStatus") != None:
            print "Passport-social. getCountAuthenticationSteps returning 2 because of switchFlowStatus"
            return 2
        if identity.getSessionId().getSessionAttributes().get("mfaFlowStatus") == "MFA_2_IN_PROGRESS":
            print "Passport-social. getCountAuthenticationSteps returning 2 because of mfaFlowStatus MFA_2_IN_PROGRESS"
            return 2
        print "Passport-social. getCountAuthenticationSteps returning 1"
        return 1


    def getPageForStep(self, configurationAttributes, step):
        print "Passport-social. getPageForStep called with step %s" % str(step)

        extensionResult = self.extensionGetPageForStep(configurationAttributes, step)
        if extensionResult != None:
            return extensionResult

        if step == 1:
            return "/auth/passport/passportlogin.xhtml"
        return "/auth/passport/passportpostlogin.xhtml"


    def getNextStep(self, configurationAttributes, requestParameters, step):
        print "Passport-social. getNextStep called with step %s" % str(step)

        if step == 1:
            identity = CdiUtil.bean(Identity)
            provider = identity.getWorkingParameter("selectedProvider")
            print "Passport DEBUG getNextStep. provider = %s" % provider
            if provider != None:
                print "Passport DEBUG getNextStep. returning 1"
                return 1

        print "Passport DEBUG getNextStep. returning -1"
        return -1


    def logout(self, configurationAttributes, requestParameters):
        return True

# Extension module related functions

    def extensionInit(self, configurationAttributes):

        if self.extensionModule == None:
            return None
        return self.extensionModule.init(configurationAttributes)


    def extensionAuthenticate(self, configurationAttributes, requestParameters, step):

        if self.extensionModule == None:
            return None
        return self.extensionModule.authenticate(configurationAttributes, requestParameters, step)


    def extensionPrepareForStep(self, configurationAttributes, requestParameters, step):

        if self.extensionModule == None:
            return None
        return self.extensionModule.prepareForStep(configurationAttributes, requestParameters, step)


    def extensionGetPageForStep(self, configurationAttributes, step):

        if self.extensionModule == None:
            return None
        return self.extensionModule.getPageForStep(configurationAttributes, step)

# Initalization routines

    def loadExternalModule(self, simpleCustProperty):

        if simpleCustProperty != None:
            print "Passport-social. loadExternalModule. Loading passport extension module..."
            moduleName = simpleCustProperty.getValue2()
            try:
                module = __import__(moduleName)
                return module
            except:
                print "Passport-social. loadExternalModule. Failed to load module %s" % moduleName
                print "Exception: ", sys.exc_info()[1]
                print "Passport-social. loadExternalModule. Flow will be driven entirely by routines of main passport script"
        return None


    def processKeyStoreProperties(self, attrs):
        file = attrs.get("key_store_file")
        password = attrs.get("key_store_password")

        if file != None and password != None:
            file = file.getValue2()
            password = password.getValue2()

            if StringHelper.isNotEmpty(file) and StringHelper.isNotEmpty(password):
                self.keyStoreFile = file
                self.keyStorePassword = password
                return True

        print "Passport-social. readKeyStoreProperties. Properties key_store_file or key_store_password not found or empty"
        return False


    def getCustomAuthzParameter(self, simpleCustProperty):

        customAuthzParameter = None
        if simpleCustProperty != None:
            prop = simpleCustProperty.getValue2()
            if StringHelper.isNotEmpty(prop):
                customAuthzParameter = prop

        if customAuthzParameter == None:
            print "Passport-social. getCustomAuthzParameter. No custom param for OIDC authz request in script properties"
            print "Passport-social. getCustomAuthzParameter. Passport flow cannot be initiated by doing an OpenID connect authorization request"
        else:
            print "Passport-social. getCustomAuthzParameter. Custom param for OIDC authz request in script properties: %s" % customAuthzParameter

        return customAuthzParameter

# Configuration parsing

    def getPassportConfigDN(self):

        f = open('/etc/gluu/conf/gluu.properties', 'r')
        for line in f:
            prop = line.split("=")
            if prop[0] == "oxpassport_ConfigurationEntryDN":
              prop.pop(0)
              break

        f.close()
        return "=".join(prop).strip()


    def parseAllProviders(self):

        registeredProviders = {}
        print "Passport-social. parseAllProviders. Adding providers"
        entryManager = CdiUtil.bean(AppInitializer).createPersistenceEntryManager()

        config = LdapOxPassportConfiguration()
        config = entryManager.find(config.getClass(), self.passportDN).getPassportConfiguration()
        config = config.getProviders() if config != None else config

        if config != None and len(config) > 0:
            for prvdetails in config:
                if prvdetails.isEnabled():
                    registeredProviders[prvdetails.getId()] = {
                        "emailLinkingSafe": prvdetails.isEmailLinkingSafe(),
                        "requestForEmail" : prvdetails.isRequestForEmail(),
                        "logo_img": prvdetails.getLogoImg(),
                        "displayName": prvdetails.getDisplayName(),
                        "type": prvdetails.getType(),
                        "samlissuer": prvdetails.getOptions().get("samlissuer")
                    }

        return registeredProviders


    def parseProviderConfigs(self):

        registeredProviders = {}
        try:
            registeredProviders = self.parseAllProviders()
            toRemove = []

            for provider in registeredProviders:
                if registeredProviders[provider]["type"] == "saml":
                    toRemove.append(provider)
                else:
                    registeredProviders[provider]["saml"] = False

            for provider in toRemove:
                registeredProviders.pop(provider)

            if len(registeredProviders.keys()) > 0:
                print "Passport-social. parseProviderConfigs. Configured providers:", registeredProviders
            else:
                print "Passport-social. parseProviderConfigs. No providers registered yet"
        except:
            print "Passport-social. parseProviderConfigs. An error occurred while building the list of supported authentication providers", sys.exc_info()[1]

        self.registeredProviders = registeredProviders

# Auxiliary routines

    def getProviderFromJson(self, providerJson):

        provider = None
        try:
            obj = json.loads(Base64Util.base64urldecodeToString(providerJson))
            provider = obj[self.providerKey]
        except:
            print "Passport-social. getProviderFromJson. Could not parse provided Json string. Returning None"

        return provider


    def getPassportRedirectUrl(self, provider, loginHint):

        # provider is assumed to exist in self.registeredProviders
        url = None
        try:
            facesContext = CdiUtil.bean(FacesContext)
            tokenEndpoint = "https://%s/passport/token" % facesContext.getExternalContext().getRequest().getServerName()

            httpService = CdiUtil.bean(HttpService)
            httpclient = httpService.getHttpsClient()

            print "Passport-social. getPassportRedirectUrl. Obtaining token from passport at %s" % tokenEndpoint
            resultResponse = httpService.executeGet(httpclient, tokenEndpoint, Collections.singletonMap("Accept", "text/json"))
            httpResponse = resultResponse.getHttpResponse()
            bytes = httpService.getResponseContent(httpResponse)

            response = httpService.convertEntityToString(bytes)
            print "Passport-social. getPassportRedirectUrl. Response was %s" % httpResponse.getStatusLine().getStatusCode()

            tokenObj = json.loads(response)
            if (loginHint != None):
                url = "/passport/auth/%s/%s/id/%s" % (provider, tokenObj["token_"], Base64Util.base64urlencode(loginHint))
            else:
                url = "/passport/auth/%s/%s" % (provider, tokenObj["token_"])
            print "Passport-social. getPassportRedirectUrl. Returning URL = %s" % url
        except:
            print "Passport-social. getPassportRedirectUrl. Error building redirect URL: ", sys.exc_info()[1]

        return url


    def validSignature(self, jwt):

        print "Passport-social. validSignature. Checking JWT token signature"
        valid = False

        # security vulnerability - we need to validate
        if ( jwt.getHeader().getAlgorithm() == "RS512" ):
            return False

        try:
            appConfiguration = AppConfiguration()
            appConfiguration.setWebKeysStorage(WebKeyStorage.KEYSTORE)
            appConfiguration.setKeyStoreFile(self.keyStoreFile)
            appConfiguration.setKeyStoreSecret(self.keyStorePassword)

            cryptoProvider = CryptoProviderFactory.getCryptoProvider(appConfiguration)
            valid = cryptoProvider.verifySignature(jwt.getSigningInput(), jwt.getEncodedSignature(), jwt.getHeader().getKeyId(),
                                                        None, None, jwt.getHeader().getAlgorithm())
        except:
            print "Exception: ", sys.exc_info()[1]

        print "Passport-social. validSignature. Validation result was %s" % valid
        return valid


    def jwtHasExpired(self, jwt):
        # Check if jwt has expired
        jwt_claims = jwt.getClaims()
        try:
            exp_date = jwt_claims.getClaimAsDate(JwtClaimName.EXPIRATION_TIME)
            hasExpired = exp_date < datetime.now()
        except:
            print "Exception: The JWT does not have '%s' attribute" % JwtClaimName.EXPIRATION_TIME
            return False

        return hasExpired


    def getUserProfile(self, jwt):
        # Check if there is user profile
        jwt_claims = jwt.getClaims()
        user_profile_json = jwt_claims.getClaimAsString("data")
        if StringHelper.isEmpty(user_profile_json):
            print "Passport-social. getUserProfile. User profile missing in JWT token"
            user_profile = None
        else:
            user_profile = json.loads(user_profile_json)

        return (user_profile, user_profile_json)


    def attemptAuthentication(self, identity, user_profile, user_profile_json):

        uidKey = "uid"
        if not self.checkRequiredAttributes(user_profile, [uidKey, self.providerKey]):
            return False

        provider = user_profile[self.providerKey]
        if not provider in self.registeredProviders:
            print "Passport-social. attemptAuthentication. Identity Provider %s not recognized" % provider
            return False
        #else:
            # TODO - HANDLE ISSUER NOT SET
            # self.registeredProviders[provider]["samlissuer"] == None

        uid = user_profile[uidKey][0]
        externalUid = "passport-%s:%s" % (provider, uid)

        # PERSISTENT_ID - generate the persistentId for the RP if coming from SAML (entityId parameter is set)
        sessionId = identity.getSessionId()
        sessionAttributes = sessionId.getSessionAttributes()
        newPersistentIdSamlRp = sessionAttributes.get("spNameQualifier")
        switchFlowStatus = sessionAttributes.get("switchFlowStatus")
        mfaFlowStatus = sessionAttributes.get("mfaFlowStatus")
        
        # SWITCH - do NOT generate a new persistentId if the switch flow is being executed
        if ( newPersistentIdSamlRp != None and StringHelper.isNotEmptyString(newPersistentIdSamlRp) and switchFlowStatus == None and mfaFlowStatus != "MFA_2_IN_PROGRESS"):
            # PERSISTENT_ID - generate the persistentId for the RP in case there is no further processing/collection happening
            newPersistentIdIdp = self.registeredProviders[provider]["samlissuer"]
            newPersistentIdUid = "sic" + uuid.uuid4().hex
            user_profile["persistentId"][0] = '%s|%s|%s' % (newPersistentIdSamlRp, newPersistentIdIdp, newPersistentIdUid )
        else:
            user_profile.pop("persistentId")
            
        if ( user_profile["claims"] != None ):
            # DISTRIBUTED CLAIMS - save the access token and the userInfo URL
            claimsReturn = user_profile["claims"]
            print "Passport-social. attemptAuthentication. Claims '%s'" % claimsReturn

        print "Passport-social. attemptAuthentication. Looking for user with oxExternalUid = '%s'" % externalUid
        userService = CdiUtil.bean(UserService)
        userByUid = userService.getUserByAttribute("oxExternalUid", externalUid)
        
        # MFA - if MFA is in progress, make sure UID matches the previous one
        if ( provider == "mfa" and sessionAttributes.get("mfaFlowStatus") == "MFA_2_IN_PROGRESS" ):
            # get the MFA PAI from the external UID
            if ( userByUid == None ):
                # the MFA authenticated user is not the same user
                print "Passport-social. attemptAuthentication. ERROR for MFA - MFA user cannot be found"
                return False
            elif ( userByUid.getUserId() != sessionAttributes.get("authenticatedUser") ):
                # the MFA authenticated user is not the same user
                print "Passport-social. attemptAuthentication. ERROR for MFA - The original and MFA users do not match"
                return False
            
        email = None
        if "mail" in user_profile:
            email = user_profile["mail"]
            if len(email) == 0:
                email = None
            else:
                email = email[0]
                user_profile["mail"] = [ email ]

        if email == None and self.registeredProviders[provider]["requestForEmail"]:
            print "Passport-social. attemptAuthentication. Email was not received"

            if userByUid != None:
                # This avoids asking for the email over every login attempt
                email = userByUid.getAttribute("mail")
                if email != None:
                    print "Passport-social. attemptAuthentication. Filling missing email value with %s" % email
                    user_profile["mail"] = [ email ]

            if email == None:
                # Store user profile in session and abort this routine
                identity.setWorkingParameter("passport_user_profile", user_profile_json)
                return True

        userByMail = None if email == None else userService.getUserByAttribute("mail", email)

        # Determine if we should add entry, update existing, or deny access
        doUpdate = False
        doAdd = False
        if userByUid != None:
            print "User with externalUid '%s' already exists" % externalUid
            if userByMail == None:
                doUpdate = True
            else:
                if userByMail.getUserId() == userByUid.getUserId():
                    doUpdate = True
                else:
                    print "Users with externalUid '%s' and mail '%s' are different. Access will be denied. Impersonation attempt?" % (externalUid, email)
                    self.setMessageError(FacesMessage.SEVERITY_ERROR, "Email value corresponds to an already existing provisioned account")
        else:
            if userByMail == None:
                doAdd = True
            elif self.registeredProviders[provider]["emailLinkingSafe"]:

                tmpList = userByMail.getAttributeValues("oxExternalUid")
                tmpList = ArrayList() if tmpList == None else ArrayList(tmpList)
                tmpList.add(externalUid)
                userByMail.setAttribute("oxExternalUid", tmpList)

                userByUid = userByMail
                print "External user supplying mail %s will be linked to existing account '%s'" % (email, userByMail.getUserId())
                doUpdate = True
            else:
                print "An attempt to supply an email of an existing user was made. Turn on 'emailLinkingSafe' if you want to enable linking"
                self.setMessageError(FacesMessage.SEVERITY_ERROR, "Email value corresponds to an already existing account. If you already have a username and password use those instead of an external authentication site to get access.")

        # MFA - if MFA is REQUIRED generate the MFA PAI for the second pass
        if ( provider != "mfa" and sessionAttributes.get("mfaFlowStatus") == "MFA_1_REQUIRED" ):
            # generate a new MFA PAI in case there is none in the user profile
            user_profile[ "oxExternalUid_newMfa" ] = [ "passport-mfa:" + "mfa" + uuid.uuid4().hex ]

        username = None
        try:
            if doUpdate:
                username = userByUid.getUserId()
                print "Passport-social. attemptAuthentication. Updating user %s" % username
                self.updateUser(userByUid, user_profile, userService)
            elif doAdd:
                print "Passport-social. attemptAuthentication. Creating user %s" % externalUid
                user_profile[uidKey][0] = uuid.uuid4().hex
                newUser = self.addUser(externalUid, user_profile, userService)
                username = newUser.getUserId()
        except:
            print "Exception: ", sys.exc_info()[1]
            print "Passport-social. attemptAuthentication. Authentication failed"
            return False

        if username == None:
            print "Passport-social. attemptAuthentication. Authentication attempt was rejected"
            return False
        else:
            logged_in = CdiUtil.bean(AuthenticationService).authenticate(username)
            print "Passport-social. attemptAuthentication. Authentication for %s returned %s" % (username, logged_in)
            if ( logged_in == True ):
                # Save the authenticated data 
                sessionAttributes.put("authenticatedProvider", "passport_social:" + provider)
                sessionAttributes.put("authenticatedUser", username)
                # SWITCH - Save contextual data for the switch flows
                if (switchFlowStatus == "1_GET_SOURCE"):
                    print "Passport-social. attemptAuthentication. SWITCH FLOW: Setting SOURCE provider to %s" % sessionAttributes.get("authenticatedProvider")
                    sessionAttributes.put( "switchSourceAuthenticatedProvider", sessionAttributes.get("authenticatedProvider") )
                    sessionAttributes.put( "switchSourceAuthenticatedUser", username)
                elif (switchFlowStatus == "2_GET_TARGET"):
                    print "Passport-social. attemptAuthentication. SWITCH FLOW: Setting TARGET provider to %s" % sessionAttributes.get("authenticatedProvider")
                    sessionAttributes.put("switchTargetAuthenticatedProvider", sessionAttributes.get("authenticatedProvider") )
                    sessionAttributes.put("switchTargetAuthenticatedUser", username)
                elif (mfaFlowStatus == "MFA_1_REQUIRED"):
                    print "Passport-social. attemptAuthentication. MFA FLOW: starting flow marking status = MFA_2_IN_PROGRESS"
                    sessionAttributes.put("mfaFlowStatus", "MFA_2_IN_PROGRESS" )
                    identity.setWorkingParameter("selectedProvider", "mfa")
                elif ( mfaFlowStatus == "MFA_2_IN_PROGRESS" ):
                    print "Passport-social. attemptAuthentication. MFA FLOW: Marking flow as complete"
                    sessionAttributes.put("mfaFlowStatus", "MFA_3_COMPLETE" )
            elif ( mfaFlowStatus == "MFA_2_IN_PROGRESS" ):
                print "Passport-social. attemptAuthentication. MFA FLOW: Marking flow as FAILED"
                sessionAttributes.put("mfaFlowStatus", "MFA_3_FAILED" )
                
            ## SESSION_SAFE - update
            CdiUtil.bean(SessionIdService).updateSessionId(sessionId)

            return logged_in


    def setMessageError(self, msg, severity):
        facesMessages = CdiUtil.bean(FacesMessages)
        facesMessages.setKeepMessages()
        facesMessages.clear()
        facesMessages.add(severity, msg)


    def encryptAES(self, key, toEncrypt):

        # make sure key length is 16 bytes (128 bits)
        if ( len(key) != 16 ):
            return None
        # generate a random IV
        randomSource = string.ascii_letters + string.digits
        iv = ''.join(random.SystemRandom().choice(randomSource) for i in range(16))
        # configure IV and key specification
        skeySpec = SecretKeySpec(key, "AES")
        ivspec = IvParameterSpec(iv);
        # setup cipher
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", BouncyCastleProvider())
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivspec)
        # encrypt the plaintext
        encryptedBytes = cipher.doFinal( toEncrypt.encode('utf-8') )
        encryptedValue = base64.b64encode( encryptedBytes )
        return iv.encode("ascii") + encryptedValue


    def decryptAES(self, key, encryptedStr):

        # make sure key length is 16 bytes (128 bits)
        if ( len(key) != 16 ):
            return None
        # split the encrypted string into IV and ciphertext
        iv, encrypted = encryptedStr[:16], encryptedStr[16:]
        # configure IV and key specification
        skeySpec = SecretKeySpec(key, "AES")
        ivspec = IvParameterSpec(iv);
        # setup cipher
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", BouncyCastleProvider())
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivspec)
        # decrypt the plaintext
        encodedBytes = base64.b64decode( b'' + encrypted )
        decodedBytes = cipher.doFinal( encodedBytes )
        plaintext    = ''.join(chr(i) for i in decodedBytes)
        return plaintext


    def checkRequiredAttributes(self, profile, attrs):

        for attr in attrs:
            if (not attr in profile) or len(profile[attr]) == 0:
                print "Passport-social. checkRequiredAttributes. Attribute '%s' is missing in profile" % attr
                return False
        return True


    def addUser(self, externalUid, profile, userService):

        newUser = User()
        #Fill user attrs
        newUser.setAttribute( "oxExternalUid", externalUid )
        newUser.setAttribute( "uid", profile["uid"][0] )
        self.fillUser(newUser, profile)
        newUser = userService.addUser(newUser, True)
        return newUser


    def updateUser(self, foundUser, profile, userService):

        # when this is false, there might still some updates taking place (e.g. not related to profile attrs released by external provider)
        if (not self.skipProfileUpdate):
            self.fillUser(foundUser, profile)
        userService.updateUser(foundUser)


    def fillUser(self, foundUser, profile):

        # To save the Persistent ID
        identity = CdiUtil.bean(Identity)
        sessionAttributes = identity.getSessionId().getSessionAttributes()
        currentRp = sessionAttributes.get("entityId")
        issuerSpNameQualifier = sessionAttributes.get("spNameQualifier")

        for attr in profile:
            # "provider" is disregarded if part of mapping
            if attr != self.providerKey:
                values = profile[attr]
                print "Passport-social. fillUser. %s = %s" % (attr, values)
                # COLLECT - here go through existing PersistentIDs add new ones for RPs that if they are not found
                if attr == "persistentId":
                    if (values != None):
                        # There is only one value from the mapping
                        newPersistenId = values[0]
                        # then we look through the old values if there is a matching RP remove if from "values" and do not update
                        userPersistentIds = foundUser.getAttributeValues("persistentId")
                        if ( userPersistentIds != None and issuerSpNameQualifier != None ):
                            for userPersistentId in userPersistentIds:
                                if ( userPersistentId.find(issuerSpNameQualifier) > -1 ):
                                    values.pop(0)

                        # if there still is a persistentId, then add it to the current user profile
                        if ( len(values) > 0):
                            print "Passport-social. fillUser. Updating persistent IDs, original = '%s'" % userPersistentIds
                            # if there are no current Persistent IDs create a new list
                            tmpList = ArrayList(userPersistentIds) if userPersistentIds != None else ArrayList()
                            tmpList.add(newPersistenId)
                            print "Passport-social. fillUser. Updating persistent IDs, updated  = '%s'" % tmpList
                            foundUser.setAttribute(attr, tmpList)
                        else:
                            print "Passport-social. fillUser. PersistentId for RP '%s' already exists, ignoring new RP mapping" % issuerSpNameQualifier

                elif attr == "oxExternalUid_newMfa":
                    # The attribute is here so MFA flow is REQUIRED.
                    # First we check for existing MFA PAI already in the user profile
                    mfaOxExternalUid = values[0]
                    userOxExternalUids = foundUser.getAttributeValues("oxExternalUid")
                    if (userOxExternalUids != None):
                        for userOxExternalUid in userOxExternalUids:
                            if ( userOxExternalUid.find("passport-mfa:") > -1 ):
                                # if we found an MFA PAI then remove the new value
                                mfaOxExternalUid = userOxExternalUid
                                values.pop(0)

                    # if there still is a value for MFA PAI, then add it to the current user profile because it did not exist
                    if ( len(values) > 0):
                        print "Passport-social. fillUser. Updating MFA PAI oxExternalUid, original list = '%s'" % userOxExternalUids
                        # if there are no current Persistent IDs create a new list
                        tmpList = ArrayList(userOxExternalUids) if userOxExternalUids != None else ArrayList()
                        tmpList.add( mfaOxExternalUid )
                        print "Passport-social. fillUser. Updating persistent IDs, updated with MFA = '%s'" % tmpList
                        foundUser.setAttribute("oxExternalUid", tmpList)
                    else:
                        print "Passport-social. fillUser. oxExternalUid for MFA '%s' already exists, ignoring new RP mapping" % mfaOxExternalUid

                elif attr == "mail":
                    oxtrustMails = []
                    for mail in values:
                        oxtrustMails.append('{"value":"%s","primary":false}' % mail)
                    foundUser.setAttribute("oxTrustEmail", oxtrustMails)

                elif attr == "claims":
                    if (values != None):
                        timeSeconds = int(round(time.time()))
                        # load claims: TODO validation of parsing result
                        claims = json.loads(values[0])
                        # create the access token attribute for Shibboleth IDP to extract the value for SAML and save it in "transientId"
                        accessTokenWithRpAndTimestamp = '%s|%s|%s|%s' % (currentRp, timeSeconds, claims["userinfourl"], claims["accesstoken"] )
                        print "Passport-social. updateUser. Claims adding access token (as transientId) '%s'" % accessTokenWithRpAndTimestamp
                        foundUser.setAttribute( "transientId", accessTokenWithRpAndTimestamp )
                        # Save the claims into the session for distributed claims (USELESS TODAY, TODO: REMOVE)
                        sessionAttributes.put("identityClaimsAccessToken", claims["accesstoken"])
                        sessionAttributes.put("identityClaimsUserInfoURL", claims["userinfourl"])

                else:
                    foundUser.setAttribute(attr, values)
