var sodium = require('chloride')
var randombytes = require('randombytes')

module.exports = function (sodium, kp) {
  var okp = opts.sodium.crypto_box_keypair()
  var nonce = randombytes(24)
  var testmsg = randombytes(32)
  var enc = sodium.crypto_box_easy(testmsg, nonce, kp.publicKey, okp.secretKey)
  var ok = sodium.crypto_box_open_easy(enc, nonce, okp.publicKey, kp.secretKey)
  return ok
}
