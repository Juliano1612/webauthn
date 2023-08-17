// easy way to go from string to ByteArray
const enc = new TextEncoder();

// another function to go from string to ByteArray, but we first encode the
// string as base64 - note the use of the atob() function
function strToBin(str) {
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

// function to encode raw binary to string, which is subsequently
// encoded to base64 - note the use of the btoa() function
function binToStr(bin) {
  return btoa(new Uint8Array(bin).reduce(
    (s, byte) => s + String.fromCharCode(byte), ''
  ));
}

const register = async () => {
  console.log("register")
  const publicKeyCredentialCreationOptions = {
    challenge: enc.encode('someRandomStringThatSHouldBeReLLYLoooong&Random'),
    rp: {
      name: "WebAuthn",
      id: "localhost"
    },
    user: {
      id: Uint8Array.from(
        "UZSL85T9AFC", c => c.charCodeAt(0)),
      name: "lee@webauthn.guide",
      displayName: "Lee",
    },
    authenticatorSelection: {
      authenticatorAttachment: "all-supported"
    },
    timeout: 60000,
    attestation: "direct",
    pubKeyCredParams: [
    {
      "type": "public-key",
      "alg": -257
    },
    {
      "type": "public-key",
      "alg": -35
    },
    {
      "type": "public-key",
      "alg": -36
    },
    {
      "type": "public-key",
      "alg": -7
    },
    {
      "type": "public-key",
      "alg": -8
    }
  ]
  };

  const credential = await navigator.credentials.create({
    publicKey: publicKeyCredentialCreationOptions
  });
  console.log(credential)
  // Below two lines store the most important info - the ID representing the created credentials
  // Typically they are sent via POST to your server, not stored locally - here for DEMO purposes only
  localStorage.setItem('rawId', binToStr(credential.rawId));
  localStorage.setItem('id', binToStr(credential.id));
}

const signIn = async () => {
  console.log("sign-in")

  ////// START server generated info //////
  // Usually the below publicKey object is constructed on your server
  // here for DEMO purposes only
  const rawId = localStorage.getItem('rawId');
  const AUTH_CHALLENGE = 'someRandomString';
  const publicKey = {
    // your domain
    rpId: "localhost",
    // random, cryptographically secure, at least 16 bytes
    challenge: enc.encode(AUTH_CHALLENGE),
authenticatorSelection: {
  authenticatorAttachment: "all-supported"
},
    allowCredentials: [{
      id: strToBin(rawId),
      type: 'public-key'
    }],
    authenticatorSelection: {
      userVerification: "preferred"
    },
  };
  ////// END server generated info //////

  const credential = await navigator.credentials.get({
    publicKey: publicKey
  });
  console.log(credential)
}


const registerBtn = document.getElementById('registerBtn');
const signInBtn = document.getElementById('signInBtn');
registerBtn.onclick = register;
signInBtn.onclick = signIn;