var sodium = require('chloride')
var randombytes = require('randombytes')

module.exports = function (sodium, kp) {
  var okp = sodium.crypto_box_keypair()
  var nonce = randombytes(24)
  var testmsg = randombytes(32)
  var enc = sodium.crypto_box_easy(testmsg, nonce, kp.publicKey, okp.secretKey)
  var out = sodium.crypto_box_open_easy(enc, nonce, okp.publicKey, kp.secretKey)
  return Buffer.compare(out, testmsg) === 0
}
