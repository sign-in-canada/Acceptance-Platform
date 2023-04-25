# Module for AWS Integration
#
# Author: Doug Harris

from software.amazon.awssdk.auth.credentials import InstanceProfileCredentialsProvider
from software.amazon.awssdk.regions.providers import InstanceProfileRegionProvider
from software.amazon.awssdk.imds import Ec2MetadataClient
from software.amazon.awssdk.services.ssm import SsmClient
from software.amazon.awssdk.services.ssm.model import GetParameterRequest

def getSsmParameter(parameterNane, isSecret = True):

    try:
        metadataClient = Ec2MetadataClient.create()
        region = InstanceProfileRegionProvider.getRegion()
        environment = metadataClient.get("/latest/meta-data/tags/instance/Environment").asString()

        credentialsProvider = InstanceProfileCredentialsProvider.create()
        ssmClient = SsmClient.builder().region(region).credentialsProvider(credentialsProvider).build()
        parameterRequestBuilder = GetParameterRequest.builder().name("/SIC/%s/%s" % (environment, parameterNane))
        if isSecret:
            parameterRequestBuilder = parameterRequestBuilder.withDecryption()
        parameterRequest = parameterRequestBuilder.build()
        parameterResponse = ssmClient.getParameter(parameterRequest)
        return parameterResponse.value()
    except:
        print ("AWS: getSsmParameter failed to retreive %s" % parameterNane)
    finally:
        if ssmClient:
            ssmClient.close()
