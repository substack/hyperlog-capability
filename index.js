var hyperlog = require('hyperlog')
var deflog = require('deferred-hyperlog')
var hsodium = require('hyperlog-sodium')
var sub = require('subleveldown')
var inherits = require('inherits')
var EventEmitter = require('events').EventEmitter
var hindex = require('hyperlog-index')
var collect = require('collect-stream')
var defaults = require('levelup-defaults')
var xtend = require('xtend')
var duplexify = require('duplexify')
var through = require('through2')
var randombytes = require('randombytes')
var isvalidkp = require('./lib/is-valid-kp.js')

inherits(Cap, EventEmitter)
module.exports = Cap

var CAPDEX = 'c', LOGDEX = 'l'

// todo: sign the group-create message with the appropriate public key

function Cap (opts) {
  var self = this
  if (!(self instanceof Cap)) return new Cap(opts)
  self.db = defaults(opts.db, { valueEncoding: 'json' })
  self.idb = defaults(opts.idb, { valueEncoding: 'json' })
  self.log = deflog()
  self.caplog = deflog()
  self.sodium = opts.sodium
  self._groupfn = opts.group

  self._logdex = hindex({
    db: sub(self.idb, LOGDEX),
    log: self.log,
    map: function (row, next) {
      self._decode(row, function (err, next) {
        if (err) return next(err)
        
      })
    }
  })
  self._capdex = hindex({
    db: sub(self.idb,CAPDEX),
    log: self.caplog,
    map: function (row, next) {
      var v = row.value
      if (v && v.type === 'group-create') {
        self.idb.put('g!' + , {
          
        }, next)
      } else if (v && v.type === 'group-invite') {
        
      }
    }
  })
}

Cap.prototype.createGroup = function (name, cb) {
  var self = this
  var kp = {
    box: self.sodium.crypto_box_keypair(),
    sign: self.sodium.crypto_sign_keypair()
  }
  self.db.batch([
    {
      type: 'put',
      key: 'sk!' + kp.sign.publicKey.toString('hex'),
      value: {
        sign: {
          publicKey: kp.sign.publicKey.toString('hex'),
          secretKey: kp.sign.secretKey.toString('hex')
        },
        box: {
          publicKey: kp.box.publicKey.toString('hex'),
          secretKey: kp.box.secretKey.toString('hex')
        }
      }
    }
  ], onbatch)
  function onbatch (err) {
    if (err) return cb(err)
    self.caplog.put({
      type: 'group-create',
      name: name,
      publicKey: {
        sign: kp.sign.publicKey.toString('hex'),
        box: kp.box.publicKey.toString('hex')
      }
    }, onput)
  }
  function onput (err) {
    if (err) return cb(err)
    cb(null, {
      sign: kp.sign.publickey,
      box: kp.box.publicKey
    })
  }
}

Cap.prototype.share = function (dockey) {
}

Cap.prototype.invite = function (opts, cb) {
  var self = this
  if (!opts) opts = {}
  if (typeof opts.to !== 'string' || !/^[0-9a-f]$/i.test(opts.to)) {
    return errtick(cb, 'opts.to must be a hex string')
  }
  if (typeof opts.group !== 'string' || !/^[0-9a-f]$/i.test(opts.group)) {
    return errtick(cb, 'opts.group must be a hex string')
  }
  if (typeof opts.mode !== 'string' || !/^[rw]+$/) {
    return errtick(cb, 'opts.mode string must be one of: r, w, rw')
  }
  self.idb.get('sk!' + opts.group, function (err, kp) {
    if (err) return cb(err)
    var nonce = randombytes(self.sodium.crypto_box_NONCEBYTES || 24)
    var bufs = {
      pk: Buffer(opts.to, 'hex'),
      sk: Buffer(kp.box.secretKey, 'hex')
    }
    var obj = {}
    if (/r/.test(opts.mode)) {
      obj.box = {
        secretKey: kp.box.secretKey.toString('hex'),
        publicKey: kp.box.publicKey.toString('hex')
      }
    }
    if (/w/.test(opts.mode)) {
      opts.sign = {
        secretKey: kp.sign.secretKey.toString('hex'),
        publicKey: kp.sign.publicKey.toString('hex')
      }
    }
    var secret = Buffer(JSON.stringify(obj))
    self.caplog.append({
      type: 'group-invite',
      to: opts.to,
      group: opts.group,
      nonce: nonce,
      data: self.sodium.crypto_box_easy(secret, nonce, pk, sk)
    }, cb)
  })
}

Cap.prototype._decode = function (msg, cb) {
  var self = this
  self.idb.get('sk!' + msg.to, function (err, kp) {
    if (notFound(err)) return cb(null, null)
    if (err) return cb(err)
    try {
      var bufs = {
        data: Buffer(msg.data, 'hex'),
        nonce: Buffer(msg.nonce, 'hex'),
        to: Buffer(msg.to, 'hex'),
        sk: kp.box.secretKey
      }
    } catch (err) { return cb(err) }
    try {
      var decoded = self.sodium.crypto_box_open_easy(
        bufs.data, bufs.nonce, bufs.to, bufs.sk
      )
    } catch (err) { return cb(err)
    cb(null, decoded)
  })
}

function notFound (err) {
  return err && (/^notfound/i.test(err.message) || err.notFound)
}

function errtick (cb, msg) {
  var err = new Error(msg)
  process.nextTick(function () { cb(err) })
}
