let uportLiteGet = require('uport-lite')({
  networks: {
    '0x16962': {
      rpcUrl: 'http://54.179.188.40:8545',
      registry: '0x6e3037af2f9019e66baa44cd7889cb1caa2c66fd'
    },
    '0x1691': {
      rpcUrl: 'http://127.0.0.1:7545',
      registry: '0x2467636bea0f3c2441227eedbffac59f11d54a80'
    }
  }
})

let didDocumentTemplate = {
  "authenticationCredential": [{
    "id": "",
    "type": ["CryptographicKey", "EcdsaPublicKey"],
    "curve": "secp256k1",
    "publicKeyHex":  ""
  }]
}

let uportResolveLegacy = (did, callback) => {
  
  if (did.length < 9 || did.slice(0,10) !== 'did:uport:') {
    throw(new Error('Not a uport DID'))
  }
  let mnid = did.slice(10)

  console.log(mnid)
  uportLiteGet(mnid, (err, doc) => {
    try {
    let pubKey = doc.publicKey.slice(2)
    var didDoc = didDocumentTemplate
    didDoc.authenticationCredential[0].id = did + "#auth"
    didDoc.authenticationCredential[0].publicKeyHex = pubKey
    callback(null, didDoc)
    } 
    catch(error) {
      callback(error, null)
    }
  })
}

// let did = 'did:uport:2ok9oMAM54TeFMfLb3ZX4i9Qu6x5pcPA7nV'
// uportResolveLegacy(did, (err, doc) => {
//   console.log(doc)
// })

module.exports = {uportResolveLegacy}
