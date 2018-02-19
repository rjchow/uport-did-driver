let uportLiteGet = require('uport-lite')({
  networks: {
    '0x16962': {
      rpcUrl: '54.179.188.40',
      registry: '0xeecd5cc4e10f92ab7b1af41b0e9c19983e6cf4be'
    },
    '0x1691': {
      rpcUrl: 'http://127.0.0.1:7545',
      registry: '0x0d8cc4b8d15d4c3ef1d70af0071376fb26b5669b'
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

  uportLiteGet(mnid, (err, doc) => {    
    let pubKey = doc.publicKey.slice(2)
    var didDoc = didDocumentTemplate
    didDoc.authenticationCredential[0].id = did + "#auth"
    didDoc.authenticationCredential[0].publicKeyHex = pubKey
    callback(null, didDoc)
  })
}

// let did = 'did:uport:2ok9oMAM54TeFMfLb3ZX4i9Qu6x5pcPA7nV'
// uportResolveLegacy(did, (err, doc) => {
//   console.log(doc)
// })

module.exports = {uportResolveLegacy}
