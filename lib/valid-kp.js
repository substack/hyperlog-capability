var sodium = require('chloride')
var randombytes = require('randombytes')

module.exports = function (opts) {
  var pk = opts.publicKey
  var sk = opts.secretKey
  var kp = opts.sodium.crypto_box_keypair()
  var nonce = randombytes(24)
  var testmsg = randombytes(32)
  var enc = sodium.crypto_box_easy(testmsg, nonce, pk, kp.secretKey)
  var ok = sodium.crypto_box_open_easy(enc, nonce, kp.publicKey, sk)
  return ok
}
