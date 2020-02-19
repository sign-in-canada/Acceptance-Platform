StringArray = Java.type("java.lang.String[]");
NameIDBuilder = Java.type("org.opensaml.saml.saml2.core.impl.NameIDBuilder");
XMLObjectAttributeValue = Java.type("net.shibboleth.idp.attribute.XMLObjectAttributeValue");

var logger = Java.type("org.slf4j.LoggerFactory").getLogger("net.shibboleth.idp.attribute");

//TODO: test to see if this respects affilliations
var recipientId = resolutionContext.getAttributeRecipientID();
logger.debug("Attribute Recipient ID {} ", recipientId);

var persistentIds = persistentId.getValues().toArray(new StringArray(0));
if (persistentIds.length === 1 && persistentIds[0].startsWith("[")) {
   persistentIds = persistentIds[0].slice(1, -1).split(', ');
}

for each (pai in persistentIds) {
   if (pai.startsWith(recipientId + "|")) {
      logger.debug("Found a persistentId attribute value for {}", recipientId);
      matches = pai.match(/^([^\|]+)\|([^\|]+)\|(.*)$/);

      logger.debug("Creating a NameID for {}", matches[1]);
      nameIdBuilder = new NameIDBuilder();
      nameIdObject = nameIdBuilder.buildObject();
      nameIdObject.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
      nameIdObject.setNameQualifier(matches[2]);
      nameIdObject.setSPNameQualifier(matches[1]);
      nameIdObject.setValue(matches[3]);

      nameIdAttributeValue = new XMLObjectAttributeValue(nameIdObject);

      nameId.addValue(nameIdAttributeValue);
      break;
   }
}
