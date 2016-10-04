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
      kp = {
        sign: self.sodium.crypto_sign_keypair(),
        box: self.sodium.crypto_box_keypair()
      }
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
      var v = row.value || {}
      if (v.type === 'add-key') {
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
    }
  })
  self.getKeys(function (err, kp) {
    if (err) return self.emit('error', err)
    var log = hyperlog(
      sub(opts.db,LOG),
      hsodium(self.sodium, kp.sign, opts)
    )
    var caplog = hyperlog(
      sub(opts.db,CAPLOG),
      hsodium(self.sodium, kp.sign, { valueEncoding: 'json' })
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

Cap.prototype.createGroup = function (cb) {
  // generate a shared secret and send the secret encrypted to ourselves
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

function tohexkp (obj) {
  return {
    sign: {
      publicKey: obj.sign.publicKey.toString('hex'),
      secretKey: obj.sign.secretKey.toString('hex')
    },
    box: {
      publicKey: obj.box.publicKey.toString('hex'),
      secretKey: obj.box.secretKey.toString('hex')
    }
  }
}
function fromhexkp (obj) {
  return {
    sign: {
      publicKey: Buffer(obj.sign.publicKey,'hex'),
      secretKey: Buffer(obj.sign.secretKey,'hex')
    },
    box: {
      publicKey: Buffer(obj.box.publicKey,'hex'),
      secretKey: Buffer(obj.box.secretKey,'hex')
    }
  }
}

function notFound (err) {
  return err && (/^notfound/i.test(err.message) || err.notFound)
}
