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

var LOG = 'l', CAPLOG = 'c', CAPIX = 'i'

function Cap (opts) {
  var self = this
  if (!(self instanceof Cap)) return new Cap(opts)
  self.db = defaults(opts.db, { valueEncoding: 'json' })
  self.idb = defaults(opts.idb, { valueEncoding: 'json' })
  self.log = deflog()
  self.caplog = deflog()
  self.sodium = opts.sodium
  self.db.get('_keypair', function (err, kp) {
    if (err && !notFound(err)) self.emit('error', err)
    else if (kp) {
      self._keypair = fromhexkp(kp)
      self.emit('_keypair', self._keypair)
    } else {
      kp = self.sodium.crypto_box_keypair()
      self.db.put('_keypair', tohexkp(kp), function (err) {
        if (err) return self.emit('error')
        self._keypair = kp
        self.emit('_keypair', kp)
      })
    }
  })
  self._groupfn = opts.group
  self._dex = hindex({
    db: sub(self.idb,CAPIX),
    log: self.caplog,
    map: function (row, next) {
      self.getKeys(function (err, kp) {
        if (err) return next(err)
        var v = row.value || {}
        if (v.type === 'auth') {
          /*
          && v.user === kp.publicKey.toString('hex')) {
          var sk = self.sodium.crypto_box_open_easy(
            v.data, v.nonce, row.identity, kp.secretKey)
          if (!sk) {
            // decryption failed
            console.error('decryption failed!')
            return next()
          }
          if (!isvalidkp(self.sodium, )) {
            // sodium: self.sodium, secretKey })) {
          }
          // test that the key is valid by encrypting a message
          self.idb.batch([
            {
              type: 'put',
              key: 'sk!' + v.group + '!' + row.key,
              value: msg
            }
          ], next)
          */
        } else if (v.type === 'add-key') {
          self.idb.batch([
            { type: 'put', key: 'g!'+v.group+'!'+v.pubkey, value: row.key },
            { type: 'put', key: 'pk!'+v.pubkey+'!'+v.group, value: row.key }
          ], next)
        } else if (v.type === 'remove') {
          self.idb.batch([
            { type: 'put', key: 'g!'+v.group+'!'+v.pubkey, value: row.key },
            { type: 'put', key: 'pk!'+v.pubkey+'!'+v.group, value: row.key }
          ], next)
        } else next()
      })
    }
  })
  self.getKeys(function (err, kp) {
    if (err) return self.emit('error', err)
    var log = hyperlog(
      sub(opts.db,LOG),
      hsodium(self.sodium, kp, opts)
    )
    var caplog = hyperlog(
      sub(opts.db,CAPLOG),
      hsodium(self.sodium, kp, { valueEncoding: 'json' })
    )
    self.log.setLog(log)
    self.caplog.setLog(caplog)
  })
}

Cap.prototype.getKeys = function (opts, cb) {
  if (typeof opts === 'function') {
    cb = opts
    opts = {}
  }
  if (typeof opts === 'string') opts = { encoding: opts }
  if (!opts) opts = {}
  var self = this
  if (self._keypair) done(self._keypair)
  else self.once('_keypair', done)
  function done (kp) {
    if (opts.encoding === 'hex') cb(null, tohexkp(kp))
    else cb(null, kp)
  }
}

Cap.prototype.createGroup = function (name, cb) {
  // generate a shared keypair and send it encrypted to ourselves
  var self = this
  var groupkp = self.sodium.crypto_box_keypair()
  var secret = groupkp.secretKey
  var nonce = randombytes(self.sodium.crypto_box_NONCEBYTES || 24)
  self.getKeys(function (err, kp) {
    self.caplog.append({
      type: 'auth',
      user: kp.publicKey.toString('hex'),
      group: groupkp.publicKey.toString('hex'),
      nonce: nonce,
      data: self.sodium.crypto_box_easy(
        secret, nonce, kp.publicKey, kp.secretKey)
    })
  })
}

Cap.prototype.addKey = function (gid, pubkey, cb) {
  // store a key and save a message with the shared secret
  this.caplog.append({
    type: 'add-key',
    group: gid,
    pubkey: pubkey
  })
  //this.caplog.append({
  //  type: 'secret',
  //})
}

Cap.prototype.remove = function (gid, pubkey, cb) {
  this.caplog.append({
    type: 'remove',
    group: group,
    pubkey: pubkey
  })
}

Cap.prototype.list = function (gid, cb) {
  var self = this
  var d = duplexify.obj()
  if (cb) collect(d, cb)
  self._dex.ready(function () {
    var r = self.idb.createReadStream({
      gt: 'g!'+gid+'!',
      lt: 'g!'+gid+'!~'
    })
    var tr = through.obj(write)
    r.on('error', function (err) { d.emit('error', err) })
    d.setReadable(r.pipe(tr))
  })
  return d
  function write (row, enc, next) {
    next(null, { publicKey: row.key.split('!')[2] })
  }
}

Cap.prototype._decode = function (msg, cb) {
  var self = this
  self.idb.get('sk!' + msg.to, function (err, sk) {
    if (notFound(err)) return cb(null, null)
    if (err) return cb(err)
    try {
      var bufs = {
        data: Buffer(msg.data, 'hex'),
        nonce: Buffer(msg.nonce, 'hex'),
        to: Buffer(msg.to, 'hex'),
        sk: Buffer(sk.key, 'hex')
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

function tohexkp (obj) {
  return {
    publicKey: obj.publicKey.toString('hex'),
    secretKey: obj.secretKey.toString('hex')
  }
}
function fromhexkp (obj) {
  return {
    publicKey: Buffer(obj.publicKey,'hex'),
    secretKey: Buffer(obj.secretKey,'hex')
  }
}
function notFound (err) {
  return err && (/^notfound/i.test(err.message) || err.notFound)
}
