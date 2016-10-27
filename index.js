var hyperlog = require('hyperlog')
var hsodium = require('hyperlog-sodium')
var sub = require('subleveldown')
var hindex = require('hyperlog-index')
var collect = require('collect-stream')
var defaults = require('levelup-defaults')
var xtend = require('xtend')
var duplexify = require('duplexify')
var through = require('through2')
var readonly = require('read-only-stream')
var randombytes = require('randombytes')

var inherits = require('inherits')
var EventEmitter = require('events').EventEmitter

var isvalidkp = require('./lib/is-valid-kp.js')

inherits(Cap, EventEmitter)
module.exports = Cap

// todo: sign the group-create message with the appropriate public key

function Cap (opts) {
  var self = this
  if (!(self instanceof Cap)) return new Cap(opts)
  self.db = defaults(opts.db, { valueEncoding: 'json' })
  self.log = hyperlog(opts.logdb, opts)
  self.caplog = hyperlog(opts.capdb, { valueEncoding: 'json' })
  self.sodium = opts.sodium

  /*
  self._logdex = hindex({
    db: sub(self.idb, LOGDEX),
    log: self.log,
    map: function (row, next) {
      self._decode(row, function (err, next) {
        if (err) return next(err)
      })
      return next()
    }
  })
  self._capdex = hindex({
    db: sub(self.idb,CAPDEX),
    log: self.caplog,
    map: function (row, next) {
      return next()
      var v = row.value
      if (v && v.type === 'group-create') {
      } else if (v && v.type === 'group-invite') {
        var group = JSON.parse(v.data)
        console.error('group', group)
        if (group.sign && !isvalidkp(self.sodium, group.sign)) {
        }
      }
    }
  })
  */
  self._capdex = hindex({
    db: sub(self.db, 'ic'),
    log: self.caplog,
    map: function (row, next) {
      var v = row.value
      if (v && v.type === 'group-create' && v.name
      && /^[0-9a-f]+$/i.test(v.sign.publicKey)) {
        self.db.batch([
          {
            type: 'put',
            key: 'pk-name!' + v.sign.publicKey + '!' + v.name,
            value: { key: row.key }
          }
        ], next)
      } else next()
    }
  })
}

Cap.prototype.createGroup = function (name, cb) {
  if (!cb) cb = noop
  var self = this
  var kp = {
    box: self.sodium.crypto_box_keypair(),
    sign: self.sodium.crypto_sign_keypair()
  }
  self.db.batch([
    {
      type: 'put',
      key: 'sk-sign!' + kp.sign.publicKey.toString('hex'),
      value: {
        publicKey: kp.sign.publicKey.toString('hex'),
        secretKey: kp.sign.secretKey.toString('hex')
      }
    },
    {
      type: 'put',
      key: 'sk-box!' + kp.box.publicKey.toString('hex'),
      value: {
        publicKey: kp.box.publicKey.toString('hex'),
        secretKey: kp.box.secretKey.toString('hex')
      }
    }
  ], onbatch)
  function onbatch (err) {
    if (err) return cb(err)
    self.caplog.append({
      type: 'group-create',
      name: name,
      sign: { publicKey: kp.sign.publicKey.toString('hex') },
      box: { publicKey: kp.box.publicKey.toString('hex') }
    }, onput)
  }
  function onput (err) {
    if (err) return cb(err)
    cb(null, kp.sign.publicKey)
  }
}

Cap.prototype.listGroups = function (cb) {
  var self = this
  var stream = self.db.createReadStream({
    gt: 'pk-name!',
    lt: 'pk-name!\uffff'
  })
  var output = readonly(stream.pipe(through.obj(write)))
  if (cb) collect(output, cb)
  return output
  function write (row, enc, next) {
    var sp = row.key.split('!')
    next(null, {
      name: sp.slice(1,-1).join('!'),
      publicKey: sp[sp.length-1]
    })
  }
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
    var obj = {
      box: { publicKey: kp.box.publicKey.toString('hex') },
      sign: { publicKey: kp.sign.publicKey.toString('hex') }
    }
    if (/r/.test(opts.mode)) {
      obj.box.secretKey = kp.box.secretKey.toString('hex')
    }
    if (/w/.test(opts.mode)) {
      opts.sign.secretKey = kp.sign.secretKey.toString('hex')
    }
    var secret = Buffer(JSON.stringify(obj))
    var encdata = self.sodium.crypto_box_easy(secret, nonce, pk, sk)
    self.caplog.append({
      type: 'group-invite',
      to: opts.to,
      group: opts.group,
      nonce: nonce,
      encdata: 'base64:' + encdata.toString('base64')
    }, cb)
  })
}

Cap.prototype._decode = function (msg, cb) {
  var self = this
  if (!msg.to) {
    return errtick(cb, '.to not provided in encrypted message')
  }
  if (!msg.encdata) {
    return errtick(cb, '.encdata not provided in encrypted message')
  }
  self.idb.get('sk!' + msg.to, function (err, kp) {
    if (notFound(err)) return cb(null, null)
    if (err) return cb(err)
    try {
      var bufs = {
        data: Buffer(msg.encdata, 'hex'),
        nonce: Buffer(msg.nonce, 'hex'),
        to: Buffer(msg.to, 'hex'),
        sk: kp.box.secretKey
      }
    } catch (err) { return cb(err) }
    try {
      var decoded = self.sodium.crypto_box_open_easy(
        bufs.data, bufs.nonce, bufs.to, bufs.sk
      )
    } catch (err) { return cb(err) }
    cb(null, decoded)
  })
}

Cap.prototype.format = function (opts) {
}

Cap.prototype.add = function () {}
Cap.prototype.append = function () {}
Cap.prototype.get = function () {}
Cap.prototype.createReadStream = function () {}
Cap.prototype.batch = function () {}
Cap.prototype.put = function () {}
Cap.prototype.del = function () {}

function notFound (err) {
  return err && (/^notfound/i.test(err.message) || err.notFound)
}
function errtick (cb, msg) {
  var err = new Error(msg)
  process.nextTick(function () { cb(err) })
}
function noop () {}
