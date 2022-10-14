addEventListener('DOMContentLoaded', async (event) => {
  attestationRequest = document.getElementById('attestationRequest').value;
  console.log(attestationRequest)
  if (!attestationRequest) {
    document.getElementById('signup').classList.replace('hidden', 'show')
    document.getElementById('spinner').classList.replace('show', 'hidden')
  } else {
    document.getElementById('spinner').classList.replace('hidden', 'show')
    document.getElementById('signup').classList.replace('show', 'hidden')
    try {
      attestationRequest = attestationRequest.replace(/\\"/g, '"').replace(/(^"|"$)/g, '');
      attestationResponse = await webauthn.createCredential(JSON.parse(attestationRequest));
      if (attestationResponse) {
        document.getElementById('attestationResponse').value = JSON.stringify(webauthn.responseToObject(attestationResponse));
        document.getElementById('nickname').value = document.getElementById('memorablename').value;
      }
    } catch (error) {
      console.log(error.name)
      console.error(error);
      document.getElementById('attestationResponse').value = '';
    }
    finally {
      document.getElementById('attestation').submit();
    }
  }
})
