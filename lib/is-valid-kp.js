var sodium = require('chloride')
var randombytes = require('randombytes')

module.exports = function (sodium, kp) {
  if (!kp.sign || !kp.box) return false
  if (kp.box.secretKey) {
    var okp = sodium.crypto_box_keypair()
    var nonce = randombytes(24)
    var testmsg = randombytes(32)
    try {
      var enc = sodium.crypto_box_easy(
        testmsg, nonce, kp.box.publicKey, okp.secretKey)
      var out = sodium.crypto_box_open_easy(
        enc, nonce, okp.publicKey, kp.box.secretKey)
    } catch (err) { return false }
    if (Buffer.compare(out, testmsg) !== 0) return false
  }
  if (kp.sign.secretKey) {
    var data = randombytes(64)
    try {
      var sig = sodium.crypto_sign_detached(data, kp.sign.secretKey)
      var ok = sodium.crypto_sign_verify_detached(sig, data, kp.sign.publicKey)
    } catch (err) { return false }
    if (!ok) return false
  }
  return true
}
