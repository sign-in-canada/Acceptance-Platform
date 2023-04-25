# Module for AWS Integration
#
# Author: Doug Harris

from software.amazon.awssdk.auth.credentials import InstanceProfileCredentialsProvider
from software.amazon.awssdk.regions.providers import InstanceProfileRegionProvider
from software.amazon.awssdk.imds import Ec2MetadataClient
from software.amazon.awssdk.services.ssm import SsmClient
from software.amazon.awssdk.services.ssm.model import GetParameterRequest

import sys

def getSsmParameter(parameterNane, isSecret = True):

    ssmClient = None
    try:
        metadataClient = Ec2MetadataClient.create()
        environment = metadataClient.get("/latest/meta-data/tags/instance/Environment").asString()
        region = InstanceProfileRegionProvider().getRegion()

        credentialsProvider = InstanceProfileCredentialsProvider.create()
        ssmClient = SsmClient.builder().region(region).credentialsProvider(credentialsProvider).build()
        parameterRequestBuilder = GetParameterRequest.builder().name("/SIC/%s/%s" % (environment, parameterNane))
        if isSecret:
            parameterRequestBuilder = parameterRequestBuilder.withDecryption(True)
        parameterRequest = parameterRequestBuilder.build()
        parameterResponse = ssmClient.getParameter(parameterRequest)
        return parameterResponse.parameter().value()
    except:
        print ("AWS: getSsmParameter failed to retreive %s. Error %s" % (parameterNane, sys.exc_info()[1]))
    finally:
        if ssmClient:
            ssmClient.close()
