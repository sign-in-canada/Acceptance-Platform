let abortController;
let abortSignal;

async function generateAssertionRequest(options) {
  try {
    response = await fetch('/fido2/restv1/fido2/assertion/options',
                          {method: 'POST',
                            body: JSON.stringify(options),
                            headers: {
                              'Content-Type': 'application/json'
                                }
                            })
    console.log('OK? ', response.ok)
    console.log('Status ', response.status)
    return await response.json();
  } catch (error) {
    document.getElementById('notfounderror').classList.replace('hidden', 'show')
  }
}

async function performModalAuth() {
  if (abortController) {
    abortController.abort();
    }
  username = document.getElementById('username').value || 'fidodiscoverer'
  options = {
    username: username,
    userVerification: 'required'
  };
  console.log('Options:', options)
  request = await generateAssertionRequest(options);
  console.log(JSON.stringify(request));
  if (request) {
    try {
      assertion = await webauthn.getAssertion(request);
      console.log('Assertion: ', JSON.stringify(webauthn.responseToObject(assertion)));
      document.getElementById('assertionResponse').value = JSON.stringify(webauthn.responseToObject(assertion));
    } catch (error) {
      console.error(error);
    } finally {
      document.getElementById('fido2').submit();
    }
  }
}

addEventListener('DOMContentLoaded', async (event) => {
  if (!PublicKeyCredential) {
    document.getElementById('roaming').classList.replace('show', 'hidden');
    document.getElementById('nearby').classList.replace('show', 'hidden');
  }
  else {
    if (PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable &&
        await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()) {
        document.getElementById('passkey').classList.replace('hidden', 'show');
      }

    if (false && PublicKeyCredential.isConditionalMediationAvailable) {
      if (await PublicKeyCredential.isConditionalMediationAvailable()) {
        console.log('Conditional mediation is available')
        document.getElementById('passkey').classList.replace('hidden', 'show');
        options = {
          username: 'fidodiscoverer',
          userVerification: 'required'
        };
        request = await generateAssertionRequest(options);
        delete request.allowCredentials;
        abortController = new AbortController();
        abortSignal = abortController.signal;
        try {
          assertion = await webauthn.getAssertion(request, true, abortSignal);
          if (assertion) {
            document.getElementById('assertionResponse').value = JSON.stringify(webauthn.responseToObject(assertion));
            document.getElementById('fido2').submit();
          }
        } catch (error) {
          console.log("Conditional authentication aborted")
        }
      }
    }
  }
})
 
  document.getElementById('chooser').addEventListener('submit', event => {
    if (abortController) {
      abortController.abort();
      }
    })

document.getElementById('passkey').addEventListener('click', async event => {
  event.preventDefault();
  await performModalAuth();
})

document.getElementById('nearby').addEventListener('click', async event => {
  event.preventDefault();
  await performModalAuth();
})

document.getElementById('signin').addEventListener('click', async (event) => {
  event.preventDefault();
  await performModalAuth();
})
