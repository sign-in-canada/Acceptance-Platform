# Module for Notify
#
# Author: Mustapha Radi

from org.gluu.service.cdi.util import CdiUtil
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.i18n import LanguageBean
from org.gluu.oxauth.service.net import HttpService
from javax.ws.rs.core import Response
from org.apache.http.util import EntityUtils
from java.lang import String

import sys
import java
import json

sys.path.append("/opt/gluu/jetty/oxauth/custom/scripts/person_authentication")

from sic import aws
class NotifyError(Exception):
    """Base class for exceptions in this module."""
    pass

class Notify:

    def __init__(self):
        return None
    
    def init(self, configurationAttributes, scriptName):

        self.scriptName = scriptName
        print ("Notify. init called from " + self.scriptName)

        self.notifyKey = aws.getSsmParameter("NOTIFY_KEY", True)

        if configurationAttributes.containsKey("oob_api_url"):
            self.apiUrl = configurationAttributes.get("oob_api_url").getValue2()

        if configurationAttributes.containsKey("oob_template_ids"):
            self.template_ids = json.loads(configurationAttributes.get("oob_template_ids").getValue2())

    def sendOobEmail(self, recipient, code):
        # Fail safely
        valid = False

        try:
            # Execute the post request and get the http response
            httpResponse = self.getHttpPostResponse("email", recipient, code)
            responseEntity = httpResponse.getEntity()

            # Validate if Notify has placed the message in a queue, ready to be sent to the provider.
            valid = (httpResponse.getStatusLine().getStatusCode() == Response.Status.CREATED.getStatusCode())
            if not valid and responseEntity:
                    print ("GCNotify error: %s" % String(EntityUtils.toByteArray(responseEntity)))
        except:
            message = "GCNotify Email sending Exception: " + str(sys.exc_info()[1])
            print ("GCNotify error: %s" % message)
        finally:
            if responseEntity:
                EntityUtils.consume(responseEntity)

        return valid
    
    def sendOobSMS(self, recipient, code):
        # Fail safely
        valid = False

        try:
            # Execute the post request and get the http response
            httpResponse = self.getHttpPostResponse("sms", recipient, code)
            responseEntity = httpResponse.getEntity()
                
            # Validate if Notify has placed the sms in a queue, ready to be sent to the provider.
            valid = (httpResponse.getStatusLine().getStatusCode() == Response.Status.CREATED.getStatusCode())
            if not valid and responseEntity:
                    print ("GCNotify error: %s" % String(EntityUtils.toByteArray(responseEntity)))
        except:
            message = "GCNotify SMS sending Exception: " + str(sys.exc_info()[1])
            print ("GCNotify error: %s" % message)
        finally:
            if responseEntity:
                EntityUtils.consume(responseEntity)

        return valid

    def getHttpPostResponse(self, service, recipient, code):
        httpService = CdiUtil.bean(HttpService)
        httpclient = httpService.getHttpsClient()
        lang = CdiUtil.bean(LanguageBean).getLocale().getLanguage()
        apiUrl = self.apiUrl + "/" + service
        recipient_metadata = "phone_number" if service == 'sms' else "email_address"
        template_id = self.template_ids[service + "-fr"] if lang == 'fr' else self.template_ids[service + "-en"]
        personalisation = '{"code":"' + code + '"}'

        # Prepare the post data
        postData = '{"' + recipient_metadata + '": "' + recipient + '", "template_id": "' + template_id + '", "personalisation": ' + personalisation + '}'

        # Execute the post request
        resultResponse = httpService.executePost(httpclient, apiUrl, "", self.getPostRequestHeaders(), postData)
        
        # Return HTTP response
        return resultResponse.getHttpResponse()

    def getPostRequestHeaders(self):
        apiKey = "ApiKey-v1 " + self.notifyKey
        return {"Authorization": apiKey, "Content-Type": "application/json"}