import base64url from './base64url-arraybuffer'

/**
 * Converts PublicKeyCredential into serialised JSON
 * @param  {Object} pubKeyCred
 * @return {Object}            - JSON encoded publicKeyCredential
 */
const publicKeyCredentialToJSON = (pubKeyCred) => {
  if (pubKeyCred instanceof Array) {
    let arr = [];
    for (let i of pubKeyCred)
      arr.push(publicKeyCredentialToJSON(i));

    return arr
  }

  if (pubKeyCred instanceof ArrayBuffer) {
    return base64url.encode(pubKeyCred)
  }

  if (pubKeyCred instanceof Object) {
    let obj = {};

    for (let key in pubKeyCred) {
      obj[key] = publicKeyCredentialToJSON(pubKeyCred[key])
    }

    return obj
  }

  return pubKeyCred
}

const register = async () => {

  const username = document.getElementById('handleInput').value;

  // 1. Gen Public Key
  const {
    publicKey
  } = await fetch(`http://localhost:3000/register/${username}`, {
      method: 'get',
      credentials: 'include',
    })
    .then(res => res.json())
  publicKey.challenge = base64url.decode(publicKey.challenge)
  publicKey.user.id = base64url.decode(publicKey.user.id)

  // 2. Create Credential
  const credential = await navigator.credentials.create({
    publicKey
  });

  // 3. Store Credential
  const credentialJSON = publicKeyCredentialToJSON(credential);
  await fetch('http://localhost:3000/verifyresponse', {
      method: 'post',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(credentialJSON)
    })
    .then(res => res.json())
    .then(console.log)
}

const signIn = async () => {

  const username = document.getElementById('handleInput').value;

  // 1. Get Public Key
  const publicKey = await fetch('http://localhost:3000/login', {
      method: 'post',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username
      })
    })
    .then(res => res.json())

  publicKey.challenge = base64url.decode(publicKey.challenge);

  for (let allowCred of publicKey.allowCredentials) {
    allowCred.id = base64url.decode(allowCred.id);
  }

  // 2. Get Credential
  const credential = await navigator.credentials.get({
    publicKey
  });

  // 3. Verify Response
  const credentialJSON = publicKeyCredentialToJSON(credential);
  await fetch('http://localhost:3000/verifyresponse', {
      method: 'post',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(credentialJSON)
    })
    .then(res => res.json())
    .then(console.log)

}


const registerBtn = document.getElementById('registerBtn');
const signInBtn = document.getElementById('signInBtn');
registerBtn.onclick = register;
signInBtn.onclick = signIn;