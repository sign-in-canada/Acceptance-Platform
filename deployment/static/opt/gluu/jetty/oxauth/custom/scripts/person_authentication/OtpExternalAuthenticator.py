# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2016, Gluu
#
# Author: Yuriy Movchan
#

# Requires the following custom properties and values:
#   otp_type: totp/hotp
#   issuer: Gluu Inc
#   otp_conf_file: /etc/certs/otp_configuration.json
#
# These are non mandatory custom properties and values:
#   label: Gluu OTP
#   qr_options: { width: 400, height: 400 }
#   registration_uri: https://ce-dev.gluu.org/identity/register

import jarray
import json
import sys
import java
import datetime

from com.google.common.io import BaseEncoding
from com.lochbridge.oath.otp import HOTP
from com.lochbridge.oath.otp import HOTPValidator
from com.lochbridge.oath.otp import HmacShaAlgorithm
from com.lochbridge.oath.otp import TOTP
from com.lochbridge.oath.otp.keyprovisioning import OTPAuthURIBuilder
from com.lochbridge.oath.otp.keyprovisioning import OTPKey
from com.lochbridge.oath.otp.keyprovisioning.OTPKey import OTPType
from java.security import SecureRandom
from java.util import Arrays
from java.util.concurrent import TimeUnit
from javax.faces.application import FacesMessage
from org.gluu.jsf2.message import FacesMessages
from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.service import UserService, AuthenticationService, SessionIdService
from org.gluu.oxauth.util import ServerUtil
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.util import StringHelper
from org.gluu.service import CacheService
from org.gluu.site.ldap.persistence.exception import AuthenticationException
from java.time import LocalDateTime, Duration
from java.time.format import DateTimeFormatter

class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, configurationAttributes):
        print "OTP (with lockout). Initialization"

        #############################################
        ### OTP
        if not configurationAttributes.containsKey("otp_type"):
            print "OTP (with lockout). Initialization. Property otp_type is mandatory"
            return False
        self.otpType = configurationAttributes.get("otp_type").getValue2()

        if not self.otpType in ["hotp", "totp"]:
            print "OTP (with lockout). Initialization. Property value otp_type is invalid"
            return False

        if not configurationAttributes.containsKey("issuer"):
            print "OTP (with lockout). Initialization. Property issuer is mandatory"
            return False
        self.otpIssuer = configurationAttributes.get("issuer").getValue2()

        self.customLabel = None
        if configurationAttributes.containsKey("label"):
            self.customLabel = configurationAttributes.get("label").getValue2()

        self.customQrOptions = {}
        if configurationAttributes.containsKey("qr_options"):
            self.customQrOptions = configurationAttributes.get("qr_options").getValue2()

        self.use_otp_group = False
        if configurationAttributes.containsKey("otp_group"):
            self.otp_group = configurationAttributes.get("otp_group").getValue2()
            self.use_otp_group = True
            print "OTP (with lockout). Initialization. Using otp only if user belong to group: %s" % self.otp_group

        self.no_lockout_admin = "admin"
        if configurationAttributes.containsKey("no_lockout_admin"):
            self.no_lockout_admin = configurationAttributes.get("no_lockout_admin").getValue2()
			
			
        if self.use_otp_group:
            if not configurationAttributes.containsKey("audit_attribute"):
                print "OTP (with lockout). Initialization. Property audit_attribute is not specified"
                return False
            else:
                self.audit_attribute = configurationAttributes.get("audit_attribute").getValue2()

        self.registrationUri = None
        if configurationAttributes.containsKey("registration_uri"):
            self.registrationUri = configurationAttributes.get("registration_uri").getValue2()

        validOtpConfiguration = self.loadOtpConfiguration(configurationAttributes)
        if not validOtpConfiguration:
            return False
        
        print "OTP (with lockout). Initialized successfully"
        ### OTP
        #############################################
        
        #############################################
        ### LOCKOUT
        self.invalidLoginCountAttribute = "oxCountInvalidLogin"
        if configurationAttributes.containsKey("invalid_login_count_attribute"):
            self.invalidLoginCountAttribute = configurationAttributes.get("invalid_login_count_attribute").getValue2()
        else:
            print "OTP (with lockout). Initialization. Using default attribute"

        self.maximumInvalidLoginAttemps = 3
        if configurationAttributes.containsKey("maximum_invalid_login_attemps"):
            self.maximumInvalidLoginAttemps = StringHelper.toInteger(configurationAttributes.get("maximum_invalid_login_attemps").getValue2())
        else:
            print "OTP (with lockout). Initialization. Using default number attempts"

        self.lockExpirationTime = 180
        if configurationAttributes.containsKey("lock_expiration_time"):
            self.lockExpirationTime = StringHelper.toInteger(configurationAttributes.get("lock_expiration_time").getValue2())
        else:
            print "OTP (with lockout). Initialization. Using default lock expiration time"


        print "OTP (with lockout). Initialized successfully. invalid_login_count_attribute: '%s', maximum_invalid_login_attemps: '%s', lock_expiration_time: '%s'" % (self.invalidLoginCountAttribute, self.maximumInvalidLoginAttemps, self.lockExpirationTime)
        ### LOCKOUT
        #############################################

        return True

    def destroy(self, configurationAttributes):
        print "OTP (with lockout). Destroy"
        print "OTP (with lockout). Destroyed successfully"
        return True

    def getApiVersion(self):
        return 1

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        return None

    def authenticate(self, configurationAttributes, requestParameters, step):
        authenticationService = CdiUtil.bean(AuthenticationService)

        identity = CdiUtil.bean(Identity)
        credentials = identity.getCredentials()

        self.setRequestScopedParameters(identity)

        if step == 1:

            #############################################
            ### LOCKOUT
            print "OTP (with lockout). Authenticate for step 1"
            facesMessages = CdiUtil.bean(FacesMessages)
            facesMessages.setKeepMessages()
            identity = CdiUtil.bean(Identity)
            credentials = identity.getCredentials()
            user_name = credentials.getUsername()
            cacheService = CdiUtil.bean(CacheService)
            
            print "OTP (with lockout). Authenticate for step 1"
            authenticated_user = self.processBasicAuthentication(credentials)


            if authenticated_user != None:
                self.setUserAttributeValue(user_name, self.invalidLoginCountAttribute, StringHelper.toString(0))            
            elif user_name != self.no_lockout_admin:
                countInvalidLoginArributeValue = self.getUserAttributeValue(user_name, self.invalidLoginCountAttribute)
                userSatus = self.getUserAttributeValue(user_name, "gluuStatus")
                print "Current user '%s' status is '%s'" % ( user_name, userSatus )

                countInvalidLogin = StringHelper.toInteger(countInvalidLoginArributeValue, 0)

                if countInvalidLogin < self.maximumInvalidLoginAttemps:
                    countInvalidLogin = countInvalidLogin + 1
                    remainingAttempts = self.maximumInvalidLoginAttemps - countInvalidLogin

                    print "Remaining login count attempts '%s' for user '%s'" % ( remainingAttempts, user_name )

                    self.setUserAttributeValue(user_name, self.invalidLoginCountAttribute, StringHelper.toString(countInvalidLogin))
                    if remainingAttempts > 0 and userSatus == "active":
                        facesMessages.add(FacesMessage.SEVERITY_INFO, StringHelper.toString(remainingAttempts)+" more attempt(s) before account is LOCKED!")

                if (countInvalidLogin >= self.maximumInvalidLoginAttemps) and ((userSatus == None) or (userSatus == "active")):
                    print "OTP (with lockout). Locking '%s' for '%s' seconds" % ( user_name, self.lockExpirationTime)
                    self.lockUser(user_name, self.maximumInvalidLoginAttemps)
                    return False

                if (countInvalidLogin >= self.maximumInvalidLoginAttemps) and userSatus == "inactive":
                    print "OTP (with lockout). User '%s' is locked. Checking if we can unlock him" % user_name
                    
                    unlock_and_authenticate = False

                    object_from_store = cacheService.get(None, "lock_user_" + user_name)
                    if object_from_store == None:
                        # Object in cache was expired. We need to unlock user
                        print "OTP (with lockout). User locking details for user '%s' not exists" % user_name
                        unlock_and_authenticate = True
                    else:
                        # Analyze object from cache
                        user_lock_details = json.loads(object_from_store)

                        user_lock_details_locked = user_lock_details['locked']
                        user_lock_details_created = user_lock_details['created']
                        user_lock_details_created_date = LocalDateTime.parse(user_lock_details_created, DateTimeFormatter.ISO_LOCAL_DATE_TIME)
                        user_lock_details_created_diff = Duration.between(user_lock_details_created_date, LocalDateTime.now()).getSeconds()
                        print "OTP (with lockout). Get user '%s' locking details. locked: '%s', Created: '%s', Difference in seconds: '%s'" % ( user_name, user_lock_details_locked, user_lock_details_created, user_lock_details_created_diff )

                        if user_lock_details_locked and user_lock_details_created_diff >= self.lockExpirationTime:
                            print "OTP (with lockout). Unlocking user '%s' after lock expiration" % user_name
                            unlock_and_authenticate = True

                    if unlock_and_authenticate:
                        self.unLockUser(user_name)
                        self.setUserAttributeValue(user_name, self.invalidLoginCountAttribute, StringHelper.toString(0))
                        ### TODO: Fix free attempt after unlock
                        authenticated_user = self.processBasicAuthentication(credentials)
                        if authenticated_user == None:
                            self.setUserAttributeValue(user_name, self.invalidLoginCountAttribute, StringHelper.toString(1))

            if authenticated_user == None:
                return False
            ### LOCKOUT
            #############################################

            # Check the otp_group user membership
            if (self.use_otp_group):
                print "OTP (with lockout). Authenticate for step 1. Checking if user '%s' belongs to otp_group" % authenticated_user.getUserId()
                is_member_otp_group = self.isUserMemberOfGroup(authenticated_user, self.audit_attribute, self.otp_group)
                if not is_member_otp_group:
                    print "OTP (with lockout). Authenticate for step 1. User '%s' not a member of otp group, skipping OTP" % authenticated_user.getUserId()
                    identity.setWorkingParameter("otp_count_login_steps", 1)
                    return True
                else:
                    print "OTP (with lockout). Authenticate for step 1. User '%s' is a member of otp group, continue to OTP" % authenticated_user.getUserId()

            otp_auth_method = "authenticate"
            # Uncomment this block if you need to allow user second OTP registration
            #enrollment_mode = ServerUtil.getFirstValue(requestParameters, "loginForm:registerButton")
            #if StringHelper.isNotEmpty(enrollment_mode):
            #    otp_auth_method = "enroll"
            
            if otp_auth_method == "authenticate":
                user_enrollments = self.findEnrollments(authenticated_user.getUserId())
                if len(user_enrollments) == 0:
                    otp_auth_method = "enroll"
                    print "OTP (with lockout). Authenticate for step 1. There is no OTP enrollment for user '%s'. Changing otp_auth_method to '%s'" % (authenticated_user.getUserId(), otp_auth_method)
                    
            if otp_auth_method == "enroll":
                print "OTP (with lockout). Authenticate for step 1. Setting count steps: '%s'" % 3
                identity.setWorkingParameter("otp_count_login_steps", 3)

            print "OTP (with lockout). Authenticate for step 1. otp_auth_method: '%s'" % otp_auth_method
            identity.setWorkingParameter("otp_auth_method", otp_auth_method)

            return True
        elif step == 2:
            print "OTP (with lockout). Authenticate for step 2"

            authenticationService = CdiUtil.bean(AuthenticationService)
            user = authenticationService.getAuthenticatedUser()
            if user == None:
                print "OTP (with lockout). Authenticate for step 2. Failed to determine user name"
                return False

            session_id_validation = self.validateSessionId(identity)
            if not session_id_validation:
                return False

            # Restore state from session
            otp_auth_method = identity.getWorkingParameter("otp_auth_method")
            if otp_auth_method == 'enroll':
                auth_result = ServerUtil.getFirstValue(requestParameters, "auth_result")
                if not StringHelper.isEmpty(auth_result):
                    print "OTP (with lockout). Authenticate for step 2. User not enrolled OTP"
                    return False

                print "OTP (with lockout). Authenticate for step 2. Skipping this step during enrollment"
                return True

            otp_auth_result = self.processOtpAuthentication(requestParameters, user.getUserId(), identity, otp_auth_method)
            print "OTP (with lockout). Authenticate for step 2. OTP authentication result: '%s'" % otp_auth_result

            return otp_auth_result
        elif step == 3:
            print "OTP (with lockout). Authenticate for step 3"

            authenticationService = CdiUtil.bean(AuthenticationService)
            user = authenticationService.getAuthenticatedUser()
            if user == None:
                print "OTP (with lockout). Authenticate for step 2. Failed to determine user name"
                return False

            session_id_validation = self.validateSessionId(identity)
            if not session_id_validation:
                return False

            # Restore state from session
            otp_auth_method = identity.getWorkingParameter("otp_auth_method")
            if otp_auth_method != 'enroll':
                return False

            otp_auth_result = self.processOtpAuthentication(requestParameters, user.getUserId(), identity, otp_auth_method)
            print "OTP (with lockout). Authenticate for step 3. OTP authentication result: '%s'" % otp_auth_result

            return otp_auth_result
        else:
            return False

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        identity = CdiUtil.bean(Identity)
        credentials = identity.getCredentials()

        self.setRequestScopedParameters(identity)

        if step == 1:
            print "OTP (with lockout). Prepare for step 1"

            return True
        elif step == 2:
            print "OTP (with lockout). Prepare for step 2"

            session_id_validation = self.validateSessionId(identity)
            if not session_id_validation:
                return False

            otp_auth_method = identity.getWorkingParameter("otp_auth_method")
            print "OTP (with lockout). Prepare for step 2. otp_auth_method: '%s'" % otp_auth_method

            if otp_auth_method == 'enroll':
                authenticationService = CdiUtil.bean(AuthenticationService)
                user = authenticationService.getAuthenticatedUser()
                if user == None:
                    print "OTP (with lockout). Prepare for step 2. Failed to load user enty"
                    return False

                if self.otpType == "hotp":
                    otp_secret_key = self.generateSecretHotpKey()
                    otp_enrollment_request = self.generateHotpSecretKeyUri(otp_secret_key, self.otpIssuer, user.getAttribute("displayName"))
                elif self.otpType == "totp":
                    otp_secret_key = self.generateSecretTotpKey()
                    otp_enrollment_request = self.generateTotpSecretKeyUri(otp_secret_key, self.otpIssuer, user.getAttribute("displayName"))
                else:
                    print "OTP (with lockout). Prepare for step 2. Unknown OTP type: '%s'" % self.otpType
                    return False

                print "OTP (with lockout). Prepare for step 2. Prepared enrollment request for user: '%s'" % user.getUserId()
                identity.setWorkingParameter("otp_secret_key", self.toBase64Url(otp_secret_key))
                identity.setWorkingParameter("otp_enrollment_request", otp_enrollment_request)

            return True
        elif step == 3:
            print "OTP (with lockout). Prepare for step 3"

            session_id_validation = self.validateSessionId(identity)
            if not session_id_validation:
                return False

            otp_auth_method = identity.getWorkingParameter("otp_auth_method")
            print "OTP (with lockout). Prepare for step 3. otp_auth_method: '%s'" % otp_auth_method

            if otp_auth_method == 'enroll':
                return True

        return False

    def getExtraParametersForStep(self, configurationAttributes, step):
        return Arrays.asList("otp_auth_method", "otp_count_login_steps", "otp_secret_key", "otp_enrollment_request")

    def getCountAuthenticationSteps(self, configurationAttributes):
        identity = CdiUtil.bean(Identity)

        if identity.isSetWorkingParameter("otp_count_login_steps"):
            return StringHelper.toInteger("%s" % identity.getWorkingParameter("otp_count_login_steps"))
        else:
            return 2

    def getPageForStep(self, configurationAttributes, step):
        if step == 2:
            identity = CdiUtil.bean(Identity)
    
            otp_auth_method = identity.getWorkingParameter("otp_auth_method")
            print "OTP (with lockout). Gep page for step 2. otp_auth_method: '%s'" % otp_auth_method
    
            if otp_auth_method == 'enroll':
                return "/admin/enroll.xhtml"
            else:
                return "/admin/otplogin.xhtml"
        elif step == 3:
            return "/admin/otplogin.xhtml"

        return "/admin/login.xhtml"

    def logout(self, configurationAttributes, requestParameters):
        return True

    def setRequestScopedParameters(self, identity):
        if self.registrationUri != None:
            identity.setWorkingParameter("external_registration_uri", self.registrationUri)

        if self.customLabel != None:
            identity.setWorkingParameter("qr_label", self.customLabel)

        identity.setWorkingParameter("qr_options", self.customQrOptions)

    def loadOtpConfiguration(self, configurationAttributes):
        print "OTP (with lockout). Load OTP configuration"
        if not configurationAttributes.containsKey("otp_conf_file"):
            return False

        otp_conf_file = configurationAttributes.get("otp_conf_file").getValue2()

        # Load configuration from file
        f = open(otp_conf_file, 'r')
        try:
            otpConfiguration = json.loads(f.read())
        except:
            print "OTP (with lockout). Load OTP configuration. Failed to load configuration from file:", otp_conf_file
            return False
        finally:
            f.close()
        
        # Check configuration file settings
        try:
            self.hotpConfiguration = otpConfiguration["hotp"]
            self.totpConfiguration = otpConfiguration["totp"]
            
            hmacShaAlgorithm = self.totpConfiguration["hmacShaAlgorithm"]
            hmacShaAlgorithmType = None

            if StringHelper.equalsIgnoreCase(hmacShaAlgorithm, "sha1"):
                hmacShaAlgorithmType = HmacShaAlgorithm.HMAC_SHA_1
            elif StringHelper.equalsIgnoreCase(hmacShaAlgorithm, "sha256"):
                hmacShaAlgorithmType = HmacShaAlgorithm.HMAC_SHA_256
            elif StringHelper.equalsIgnoreCase(hmacShaAlgorithm, "sha512"):
                hmacShaAlgorithmType = HmacShaAlgorithm.HMAC_SHA_512
            else:
                print "OTP (with lockout). Load OTP configuration. Invalid TOTP HMAC SHA algorithm: '%s'" % hmacShaAlgorithm
                 
            self.totpConfiguration["hmacShaAlgorithmType"] = hmacShaAlgorithmType
        except:
            print "OTP (with lockout). Load OTP configuration. Invalid configuration file '%s' format. Exception: '%s'" % (otp_conf_file, sys.exc_info()[1])
            return False
        

        return True

    def processBasicAuthentication(self, credentials):
        authenticationService = CdiUtil.bean(AuthenticationService)

        user_name = credentials.getUsername()
        user_password = credentials.getPassword()

        logged_in = False
        if (StringHelper.isNotEmptyString(user_name) and StringHelper.isNotEmptyString(user_password)):
            try:
                logged_in = authenticationService.authenticate(user_name, user_password)
            except AuthenticationException:
                print "OTP (with lockout). Authenticate. Failed to authenticate user '%s'" % user_name

        if not logged_in:
            return None

        find_user_by_uid = authenticationService.getAuthenticatedUser()
        if find_user_by_uid == None:
            print "OTP (with lockout). Process basic authentication. Failed to find user '%s'" % user_name
            return None

        return find_user_by_uid

    def findEnrollments(self, user_name, skipPrefix = True):
        result = []

        userService = CdiUtil.bean(UserService)
        user = userService.getUser(user_name, "oxExternalUid")
        if user == None:
            print "OTP (with lockout). Find enrollments. Failed to find user"
            return result
        
        user_custom_ext_attribute = userService.getCustomAttribute(user, "oxExternalUid")
        if user_custom_ext_attribute == None:
            return result

        otp_prefix = "%s:" % self.otpType
        
        otp_prefix_length = len(otp_prefix) 
        for user_external_uid in user_custom_ext_attribute.getValues():
            index = user_external_uid.find(otp_prefix)
            if index != -1:
                if skipPrefix:
                    enrollment_uid = user_external_uid[otp_prefix_length:]
                else:
                    enrollment_uid = user_external_uid

                result.append(enrollment_uid)
        
        return result

    def validateSessionId(self, identity):
        session_id = CdiUtil.bean(SessionIdService).getSessionIdFromCookie()
        if StringHelper.isEmpty(session_id):
            print "OTP (with lockout). Validate session id. Failed to determine session_id"
            return False

        otp_auth_method = identity.getWorkingParameter("otp_auth_method")
        if not otp_auth_method in ['enroll', 'authenticate']:
            print "OTP (with lockout). Validate session id. Failed to authenticate user. otp_auth_method: '%s'" % otp_auth_method
            return False

        return True

    def processOtpAuthentication(self, requestParameters, user_name, identity, otp_auth_method):
        facesMessages = CdiUtil.bean(FacesMessages)
        facesMessages.setKeepMessages()

        userService = CdiUtil.bean(UserService)

        otpCode = ServerUtil.getFirstValue(requestParameters, "loginForm:otpCode")
        if StringHelper.isEmpty(otpCode):
            facesMessages.add(FacesMessage.SEVERITY_ERROR, "Failed to authenticate. OTP code is empty")
            print "OTP (with lockout). Process OTP authentication. otpCode is empty"

            return False
        
        if otp_auth_method == "enroll":
            # Get key from session
            otp_secret_key_encoded = identity.getWorkingParameter("otp_secret_key")
            if otp_secret_key_encoded == None:
                print "OTP (with lockout). Process OTP authentication. OTP secret key is invalid"
                return False
            
            otp_secret_key = self.fromBase64Url(otp_secret_key_encoded)

            if self.otpType == "hotp":
                validation_result = self.validateHotpKey(otp_secret_key, 1, otpCode)
                
                if (validation_result != None) and validation_result["result"]:
                    print "OTP (with lockout). Process HOTP authentication during enrollment. otpCode is valid"
                    # Store HOTP Secret Key and moving factor in user entry
                    otp_user_external_uid = "hotp:%s;%s" % ( otp_secret_key_encoded, validation_result["movingFactor"] )

                    # Add otp_user_external_uid to user's external GUID list
                    find_user_by_external_uid = userService.addUserAttribute(user_name, "oxExternalUid", otp_user_external_uid)
                    if find_user_by_external_uid != None:
                        return True

                    print "OTP (with lockout). Process HOTP authentication during enrollment. Failed to update user entry"
            elif self.otpType == "totp":
                validation_result = self.validateTotpKey(otp_secret_key, otpCode)
                if (validation_result != None) and validation_result["result"]:
                    print "OTP (with lockout). Process TOTP authentication during enrollment. otpCode is valid"
                    # Store TOTP Secret Key and moving factor in user entry
                    otp_user_external_uid = "totp:%s" % otp_secret_key_encoded

                    # Add otp_user_external_uid to user's external GUID list
                    find_user_by_external_uid = userService.addUserAttribute(user_name, "oxExternalUid", otp_user_external_uid)
                    if find_user_by_external_uid != None:
                        return True

                    print "OTP (with lockout). Process TOTP authentication during enrollment. Failed to update user entry"
        elif otp_auth_method == "authenticate":
            user_enrollments = self.findEnrollments(user_name)

            if len(user_enrollments) == 0:
                print "OTP (with lockout). Process OTP authentication. There is no OTP enrollment for user '%s'" % user_name
                facesMessages.add(FacesMessage.SEVERITY_ERROR, "There is no valid OTP user enrollments")
                return False

            if self.otpType == "hotp":
                for user_enrollment in user_enrollments:
                    user_enrollment_data = user_enrollment.split(";")
                    otp_secret_key_encoded = user_enrollment_data[0]

                    # Get current moving factor from user entry
                    moving_factor = StringHelper.toInteger(user_enrollment_data[1])
                    otp_secret_key = self.fromBase64Url(otp_secret_key_encoded)

                    # Validate TOTP
                    validation_result = self.validateHotpKey(otp_secret_key, moving_factor, otpCode)
                    if (validation_result != None) and validation_result["result"]:
                        print "OTP (with lockout). Process HOTP authentication during authentication. otpCode is valid"
                        otp_user_external_uid = "hotp:%s;%s" % ( otp_secret_key_encoded, moving_factor )
                        new_otp_user_external_uid = "hotp:%s;%s" % ( otp_secret_key_encoded, validation_result["movingFactor"] )
    
                        # Update moving factor in user entry
                        find_user_by_external_uid = userService.replaceUserAttribute(user_name, "oxExternalUid", otp_user_external_uid, new_otp_user_external_uid)
                        if find_user_by_external_uid != None:
                            return True
    
                        print "OTP (with lockout). Process HOTP authentication during authentication. Failed to update user entry"
            elif self.otpType == "totp":
                for user_enrollment in user_enrollments:
                    otp_secret_key = self.fromBase64Url(user_enrollment)

                    # Validate TOTP
                    validation_result = self.validateTotpKey(otp_secret_key, otpCode)
                    if (validation_result != None) and validation_result["result"]:
                        print "OTP (with lockout). Process TOTP authentication during authentication. otpCode is valid"
                        return True

        facesMessages.add(FacesMessage.SEVERITY_ERROR, "Failed to authenticate. OTP code is invalid")
        print "OTP (with lockout). Process OTP authentication. OTP code is invalid"

        return False

    # Shared HOTP/TOTP methods
    def generateSecretKey(self, keyLength):
        bytes = jarray.zeros(keyLength, "b")
        secureRandom = SecureRandom()
        secureRandom.nextBytes(bytes)
        
        return bytes
    
    # HOTP methods
    def generateSecretHotpKey(self):
        keyLength = self.hotpConfiguration["keyLength"]
        
        return self.generateSecretKey(keyLength)

    def generateHotpKey(self, secretKey, movingFactor):
        digits = self.hotpConfiguration["digits"]

        hotp = HOTP.key(secretKey).digits(digits).movingFactor(movingFactor).build()
        
        return hotp.value()

    def validateHotpKey(self, secretKey, movingFactor, totpKey):
        lookAheadWindow = self.hotpConfiguration["lookAheadWindow"]
        digits = self.hotpConfiguration["digits"]

        hotpValidationResult = HOTPValidator.lookAheadWindow(lookAheadWindow).validate(secretKey, movingFactor, digits, totpKey)
        if hotpValidationResult.isValid():
            return { "result": True, "movingFactor": hotpValidationResult.getNewMovingFactor() }

        return { "result": False, "movingFactor": None }

    def generateHotpSecretKeyUri(self, secretKey, issuer, userDisplayName):
        digits = self.hotpConfiguration["digits"]

        secretKeyBase32 = self.toBase32(secretKey)
        otpKey = OTPKey(secretKeyBase32, OTPType.HOTP)
        label = issuer + " %s" % userDisplayName

        otpAuthURI = OTPAuthURIBuilder.fromKey(otpKey).label(label).issuer(issuer).digits(digits).build()

        return otpAuthURI.toUriString()

    # TOTP methods
    def generateSecretTotpKey(self):
        keyLength = self.totpConfiguration["keyLength"]
        
        return self.generateSecretKey(keyLength)

    def generateTotpKey(self, secretKey):
        digits = self.totpConfiguration["digits"]
        timeStep = self.totpConfiguration["timeStep"]
        hmacShaAlgorithmType = self.totpConfiguration["hmacShaAlgorithmType"]

        totp = TOTP.key(secretKey).digits(digits).timeStep(TimeUnit.SECONDS.toMillis(timeStep)).hmacSha(hmacShaAlgorithmType).build()
        
        return totp.value()

    def validateTotpKey(self, secretKey, totpKey):
        localTotpKey = self.generateTotpKey(secretKey)
        if StringHelper.equals(localTotpKey, totpKey):
            return { "result": True }

        return { "result": False }

    def generateTotpSecretKeyUri(self, secretKey, issuer, userDisplayName):
        digits = self.totpConfiguration["digits"]
        timeStep = self.totpConfiguration["timeStep"]

        secretKeyBase32 = self.toBase32(secretKey)
        otpKey = OTPKey(secretKeyBase32, OTPType.TOTP)
        label = issuer + " %s" % userDisplayName

        otpAuthURI = OTPAuthURIBuilder.fromKey(otpKey).label(label).issuer(issuer).digits(digits).timeStep(TimeUnit.SECONDS.toMillis(timeStep)).build()

        return otpAuthURI.toUriString()

    # Utility methods
    def toBase32(self, bytes):
        return BaseEncoding.base32().omitPadding().encode(bytes)

    def toBase64Url(self, bytes):
        return BaseEncoding.base64Url().encode(bytes)

    def fromBase64Url(self, chars):
        return BaseEncoding.base64Url().decode(chars)

    def isUserMemberOfGroup(self, user, attribute, group):
        is_member = False
        member_of_list = user.getAttributeValues(attribute)
        if (member_of_list != None):
            for member_of in member_of_list:
                if StringHelper.equalsIgnoreCase(group, member_of) or member_of.endswith(group):
                    is_member = True
                    break

        return is_member
        
    def getUserAttributeValue(self, user_name, attribute_name):
        if StringHelper.isEmpty(user_name):
            return None

        userService = CdiUtil.bean(UserService)

        find_user_by_uid = userService.getUser(user_name, attribute_name)
        if find_user_by_uid == None:
            return None

        custom_attribute_value = userService.getCustomAttribute(find_user_by_uid, attribute_name)
        if custom_attribute_value == None:
            return None
        
        attribute_value = custom_attribute_value.getValue()

        print "OTP (with lockout). Get user attribute. User's '%s' attribute '%s' value is '%s'" % (user_name, attribute_name, attribute_value)

        return attribute_value

    def setUserAttributeValue(self, user_name, attribute_name, attribute_value):
        if StringHelper.isEmpty(user_name):
            return None

        userService = CdiUtil.bean(UserService)

        find_user_by_uid = userService.getUser(user_name)
        if find_user_by_uid == None:
            return None
        
        userService.setCustomAttribute(find_user_by_uid, attribute_name, attribute_value)
        updated_user = userService.updateUser(find_user_by_uid)

        print "OTP (with lockout). Set user attribute. User's '%s' attribute '%s' value is '%s'" % (user_name, attribute_name, attribute_value)

        return updated_user

    def lockUser(self, user_name, maxCount):
        if StringHelper.isEmpty(user_name):
            return None

        userService = CdiUtil.bean(UserService)
        cacheService= CdiUtil.bean(CacheService)
        facesMessages = CdiUtil.bean(FacesMessages)
        facesMessages.setKeepMessages()

        find_user_by_uid = userService.getUser(user_name)
        if (find_user_by_uid == None):
            return None

        status_attribute_value = userService.getCustomAttribute(find_user_by_uid, "gluuStatus")
        if status_attribute_value != None:
            user_status = status_attribute_value.getValue()
            if StringHelper.equals(user_status, "inactive"):
                print "OTP (with lockout). Lock user. User '%s' locked already" % user_name
                return
        
        userService.setCustomAttribute(find_user_by_uid, "gluuStatus", "inactive")
        updated_user = userService.updateUser(find_user_by_uid)

        object_to_store = json.dumps({'locked': True, 'created': LocalDateTime.now().toString()}, separators=(',',':'))

        cacheService.put(StringHelper.toString(self.lockExpirationTime), "lock_user_"+user_name, object_to_store);
        facesMessages.add(FacesMessage.SEVERITY_ERROR, "Your account is locked. Please try again after " + StringHelper.toString(self.lockExpirationTime) + " secs")

        print "OTP (with lockout). Lock user. User '%s' locked" % user_name

    def unLockUser(self, user_name):
        if StringHelper.isEmpty(user_name):
            return None

        userService = CdiUtil.bean(UserService)
        cacheService= CdiUtil.bean(CacheService)

        find_user_by_uid = userService.getUser(user_name)
        if (find_user_by_uid == None):
            return None

        object_to_store = json.dumps({'locked': False, 'created': LocalDateTime.now().toString()}, separators=(',',':'))
        cacheService.put(StringHelper.toString(self.lockExpirationTime), "lock_user_"+user_name, object_to_store);

        userService.setCustomAttribute(find_user_by_uid, "gluuStatus", "active")
        userService.setCustomAttribute(find_user_by_uid, self.invalidLoginCountAttribute, None)
        updated_user = userService.updateUser(find_user_by_uid)


        print "OTP (with lockout). Lock user. User '%s' unlocked" % user_name
