addEventListener('DOMContentLoaded', async (event) => {
  attestationRequest = document.getElementById('attestationRequest').value;
  console.log(attestationRequest)
  if (attestationRequest) {
    try {
      attestationRequest = attestationRequest.replace(/\\"/g, '"').replace(/(^"|"$)/g, '');
      attestationResponse = await webauthn.createCredential(JSON.parse(attestationRequest));
      if (attestationResponse) {
        document.getElementById('attestationResponse').value = JSON.stringify(webauthn.responseToObject(attestationResponse));
      }
    } catch (error) {
      console.log(error.name)
      console.error(error);
      document.getElementById('attestationResponse').value = '';
    }
    finally {
      document.getElementById('attestation').submit();
    }
  } else {
    window.location.replace('/oxauth/error.htm')
  }

})
