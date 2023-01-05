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

async function performModalAuth(request) {
  console.log('Model Auth')
  console.log(request)
  if (abortController) {
    abortController.abort();
    }
  if (!request) {
    username = 'fidodiscoverer'
    options = {
      username: username,
      userVerification: 'required'
    };
    console.log('Options:', options)
    request = await generateAssertionRequest(options);
  }
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

passkeyButton = document.getElementById('passkey')
assertionRequest = document.getElementById('assertionRequest');
console.log(assertionRequest);
if (passkeyButton) {
  passkeyButton.addEventListener('click', async event => {
    event.preventDefault();
    await performModalAuth();
  })
} else if (assertionRequest){
  console.log("server side")
  console.log(assertionRequest.value)
  request = JSON.parse(assertionRequest.value.replace(/\\"/g, '"').replace(/(^"|"$)/g, ''));
  console.log(request);
  performModalAuth(request);
}

