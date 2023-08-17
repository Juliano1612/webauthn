import cors from 'cors';
import express from 'express';
import crypto from 'crypto';
import base64url from 'base64url';
import bodyParser from 'body-parser';
import cookieSession from 'cookie-session';
import cookieParser from 'cookie-parser';
import cbor from 'cbor';

const app = express();
app.use(bodyParser.json());
app.use(express.json());
app.use(cors({
  credentials: true,
  origin: true
}));

/* ----- session ----- */
app.use(cookieSession({
  name: 'session',
  keys: [crypto.randomBytes(32).toString('hex')],

  // Cookie Options
  maxAge: 24 * 60 * 60 * 1000 // 24 hours
}))
app.use(cookieParser())

/**
 * Returns base64url encoded buffer of the given length
 * @param  {Number} len - length of the buffer
 * @return {String}     - base64url random buffer
 */
let randomBase64URLBuffer = (len) => {
  len = len || 32;

  let buff = crypto.randomBytes(len);

  return base64url(buff);
}

const database = {};

app.get('/register/:username', async function (req, res) {

  const {
    username
  } = req.params;

  database[username] = {
    name: username,
    registered: false,
    id: randomBase64URLBuffer(),
    authenticators: []
  }

  const publicKey = {
    challenge: randomBase64URLBuffer(32),
    rp: {
      name: "WebAuthn",
      id: "localhost"
    },
    user: {
      id: database[username].id,
      name: username,
      displayName: username
    },
    authenticatorSelection: {
      authenticatorAttachment: "all-supported"
    },
    timeout: 60000,
    attestation: "direct",
    pubKeyCredParams: [{
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

  req.session.challenge = publicKey.challenge;
  req.session.username = username;

  res.json({
    publicKey
  })
});


app.post('/verifyresponse', async function (req, res) {

  const webauthnResponse = req.body;
  const clientData = JSON.parse(base64url.decode(webauthnResponse.response.clientDataJSON))

  if (clientData.challenge !== req.session.challenge) {
    return res.json({
      status: 'failed',
      message: 'Challenges dont match'
    })
  }

  let result;
  if (webauthnResponse.response.attestationObject !== undefined) {
    /* This is create cred */
    result = verifyAuthenticatorAttestationResponse(webauthnResponse);

    if (result.verified) {
      database[req.session.username].authenticators.push(result.authrInfo);
      database[req.session.username].registered = true
    }
  } else if (webauthnResponse.response.authenticatorData !== undefined) {
    /* This is get assertion */
    result = verifyAuthenticatorAssertionResponse(webauthnResponse, database[req.session.username].authenticators);
  } else {
    response.json({
      'status': 'failed',
      'message': 'Can not determine type of response!'
    })
  }

  if (result.verified) {
    req.session.loggedIn = true;
    res.json({
      'status': 'ok'
    })
  } else {
    res.json({
      'status': 'failed',
      'message': 'Can not authenticate signature!'
    })
  }
});

/**
 * Parses authenticatorData buffer.
 * @param  {Buffer} buffer - authenticatorData buffer
 * @return {Object}        - parsed authenticatorData struct
 */
let parseMakeCredAuthData = (buffer) => {
  let rpIdHash = buffer.slice(0, 32);
  buffer = buffer.slice(32);
  let flagsBuf = buffer.slice(0, 1);
  buffer = buffer.slice(1);
  let flags = flagsBuf[0];
  let counterBuf = buffer.slice(0, 4);
  buffer = buffer.slice(4);
  let counter = counterBuf.readUInt32BE(0);
  let aaguid = buffer.slice(0, 16);
  buffer = buffer.slice(16);
  let credIDLenBuf = buffer.slice(0, 2);
  buffer = buffer.slice(2);
  let credIDLen = credIDLenBuf.readUInt16BE(0);
  let credID = buffer.slice(0, credIDLen);
  buffer = buffer.slice(credIDLen);
  let COSEPublicKey = buffer;

  return {
    rpIdHash,
    flagsBuf,
    flags,
    counter,
    counterBuf,
    aaguid,
    credID,
    COSEPublicKey
  }
}

/**
 * Takes COSE encoded public key and converts it to RAW PKCS ECDHA key
 * @param  {Buffer} COSEPublicKey - COSE encoded public key
 * @return {Buffer}               - RAW PKCS encoded public key
 */
let COSEECDHAtoPKCS = (COSEPublicKey) => {
  /* 
     +------+-------+-------+---------+----------------------------------+
     | name | key   | label | type    | description                      |
     |      | type  |       |         |                                  |
     +------+-------+-------+---------+----------------------------------+
     | crv  | 2     | -1    | int /   | EC Curve identifier - Taken from |
     |      |       |       | tstr    | the COSE Curves registry         |
     |      |       |       |         |                                  |
     | x    | 2     | -2    | bstr    | X Coordinate                     |
     |      |       |       |         |                                  |
     | y    | 2     | -3    | bstr /  | Y Coordinate                     |
     |      |       |       | bool    |                                  |
     |      |       |       |         |                                  |
     | d    | 2     | -4    | bstr    | Private key                      |
     +------+-------+-------+---------+----------------------------------+
  */

  let coseStruct = cbor.decodeAllSync(COSEPublicKey)[0];
  let tag = Buffer.from([0x04]);
  let x = coseStruct.get(-2);
  let y = coseStruct.get(-3);

  return Buffer.concat([tag, x, y])
}

const verifyAuthenticatorAttestationResponse = (webAuthnResponse) => {
  let attestationBuffer = base64url.toBuffer(webAuthnResponse.response.attestationObject);
  let ctapMakeCredResp = cbor.decodeAllSync(attestationBuffer)[0];

  let response = {
    'verified': true
  };

  let authrDataStruct = parseMakeCredAuthData(ctapMakeCredResp.authData);
  /** we must implement how to verify different stuff https://medium.com/webauthnworks/verifying-fido2-responses-4691288c8770 */
  /** https://github.com/fido-alliance/webauthn-demo/blob/completed-demo/utils.js#L196C25-L196C25 */

  let publicKey = COSEECDHAtoPKCS(authrDataStruct.COSEPublicKey)
  if (response.verified) {
    response.authrInfo = {
      fmt: ctapMakeCredResp.fmt,
      publicKey: base64url.encode(publicKey),
      counter: authrDataStruct.counter,
      credID: base64url.encode(authrDataStruct.credID)
    }
  }

  return response
}

/**
 * Takes an array of registered authenticators and find one specified by credID
 * @param  {String} credID        - base64url encoded credential
 * @param  {Array} authenticators - list of authenticators
 * @return {Object}               - found authenticator
 */
let findAuthr = (credID, authenticators) => {
  for (let authr of authenticators) {
    if (authr.credID === credID)
      return authr
  }

  throw new Error(`Unknown authenticator with credID ${credID}!`)
}

const verifyAuthenticatorAssertionResponse = (webAuthnResponse, authenticators) => {
  let authr = findAuthr(webAuthnResponse.id, authenticators);
  let authenticatorData = base64url.toBuffer(webAuthnResponse.response.authenticatorData);
  let response = {
    'verified': true
  };

  /** we must implement how to verify different stuff https://medium.com/webauthnworks/verifying-fido2-responses-4691288c8770 */
  /** https://github.com/fido-alliance/webauthn-demo/blob/completed-demo/utils.js#L261 */

  return response
}


app.post('/login', async function (req, res) {
  let username = req.body.username;
  if (!database[username] || !database[username].registered) {
    res.json({
      'status': 'failed',
      'message': `User ${username} does not exist!`
    })

    return
  }

  console.log(database[username])
  let getAssertion = generateServerGetAssertion(database[username].authenticators)
  getAssertion.status = 'ok'

  req.session.challenge = getAssertion.challenge;
  req.session.username = username;

  res.json(getAssertion)

})

/**
 * Generates getAssertion request
 * @param  {Array} authenticators              - list of registered authenticators
 * @return {PublicKeyCredentialRequestOptions} - server encoded get assertion request
 */
let generateServerGetAssertion = (authenticators) => {
  let allowCredentials = [];
  for (let authr of authenticators) {
    allowCredentials.push({
      type: 'public-key',
      id: authr.credID,
      // transports: ['usb', 'nfc', 'ble']
    })
  }
  return {
    challenge: randomBase64URLBuffer(32),
    allowCredentials: allowCredentials,
    authenticatorSelection: {
      userVerification: "preferred"
    },
  }
}


app.listen(3000);