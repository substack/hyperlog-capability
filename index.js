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

inherits(Cap, EventEmitter)
module.exports = Cap

var LOG = 'l', CAPLOG = 'c', CAPIX = 'i', CAPS = 'l'

function Cap (opts) {
  var self = this
  if (!(self instanceof Cap)) return new Cap(opts)
  self.db = defaults(opts.db, { valueEncoding: 'json' })
  self.idb = opts.idb
  self.log = deflog()
  self.caplog = deflog()
  self.sodium = opts.sodium
  self.db.get('_keypair', function (err, kp) {
    if (err && !notFound(err)) self.emit('error', err)
    else if (kp) {
      self._keypair = fromhexkp(kp)
      self.emit('_keypair', self._keypair)
    } else {
      kp = self.sodium.crypto_sign_keypair()
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
    map: function (row, enc, next) {
      var g = self._groupfn(row)
      if (!g) return next()
      var v = row.value || {}
      if (v.type === 'add') {
        self.idb.batch([
          { type: 'put', key: 'g!'+v.group+'!'+v.pubkey, value: row.key },
          { type: 'put', key: 'pk!'+v.pubkey+'!'+group, value: row.key }
        ], next)
      } else if (row.type === 'remove') {
        self.idb.batch([
          { type: 'put', key: 'g!'+v.group+'!'+v.pubkey, value: row.key },
          { type: 'put', key: 'pk!'+v.pubkey+'!'+v.group, value: row.key }
        ], next)
      } else next()
    }
  })
  self.keypair(function (err, kp) {
    if (err) return self.emit('error', err)
    var log = hyperlog(sub(opts.db,LOG), hsodium(self.sodium, kp, opts))
    var caplog = hyperlog(sub(opts.db,CAPLOG), hsodium(self.sodium, kp, {
      valueEncoding: 'json'
    }))
    self.log.setLog(log)
    self.caplog.setLog(caplog)
  })
}

Cap.prototype.keypair = function (opts, cb) {
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

Cap.prototype.add = function (group, pubkey, cb) {
  this.caplog.append({
    type: 'add',
    group: group,
    pubkey: pubkey
  })
}

Cap.prototype.remove = function (group, pubkey, cb) {
  this.caplog.append({
    type: 'remove',
    group: group,
    pubkey: pubkey
  })
}

Cap.prototype.getGroups = function (pubkey) {
}

Cap.prototype.getKeys = function (group) {
}

Cap.prototype.list = function (group, cb) {
  var r = this.idb.createReadStream({
    gt: 'g!'+group+'!',
    lt: 'g!'+group+'!~'
  })
  if (cb) collect(r, cb)
  return r
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
