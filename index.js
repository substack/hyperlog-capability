var hyperlog = require('hyperlog')
var hsodium = require('hyperlog-sodium')
var sub = require('subleveldown')
var hindex = require('hyperlog-index')
var collect = require('collect-stream')
var defaults = require('levelup-defaults')
var xtend = require('xtend')
var duplexify = require('duplexify')
var through = require('through2')
var to = require('to2')
var readonly = require('read-only-stream')
var randombytes = require('randombytes')
var framedHash = require('hyperlog/lib/hash.js')
var encoder = require('hyperlog/lib/encode.js')
var isbuffer = require('is-buffer')
var once = require('once')

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
  self.log = hyperlog(opts.logdb, { valueEncoding: 'json' })
  self.sodium = opts.sodium
  self._dex = hindex({
    db: sub(self.db, 'ic'),
    log: self.log,
    map: function (row, next) {
      var v = row.value
      if (!v) return next()
      if (v.type === 'group-create' && ishex(v.id)) {
        self.db.batch([
          {
            type: 'put',
            key: 'pk-name!' + v.id + '!' + v.name,
            value: { key: row.key }
          }
        ], next)
      } else if (v.type === 'doc-key' && ishex(v.key)) {
        self.db.batch([
          {
            type: 'put',
            key: 'dk!' + v.key + '!' + row.key,
            value: ''
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
  var gid = kp.sign.publicKey.toString('hex') + kp.box.publicKey.toString('hex')
  self.db.batch([
    {
      type: 'put',
      key: 'sk!' + gid,
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
    self.log.append({
      type: 'group-create',
      name: name,
      id: gid
    }, onput)
  }
  function onput (err) {
    if (err) return cb(err)
    cb(null, gid)
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
      id: sp[1],
      name: sp.slice(2).join('!')
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
    self.log.append(jstr({
      type: 'group-invite',
      to: opts.to,
      group: opts.group,
      nonce: nonce,
      encdata: encdata
    }), cb)
  })
}

Cap.prototype._decode = function (key, doc, cb) {
  var self = this
  cb = once(cb || noop)
  if (!doc.encdata) {
    return errtick(cb, '.encdata not provided in encrypted message')
  }
  var r = self.db.createReadStream({
    gt: 'dk!' + key + '!',
    lt: 'dk!' + key + '!~'
  })
  r.on('error', cb)
  r.pipe(to.obj(write, end)).on('error', cb)

  function write (row, enc, next) {
    var key = row.key.split('!')[2]
    self.log.get(key, function (err, row) {
      if (notFound(err)) next()
      else if (err) next(err)
      else self._decodeRow(row, doc, function (err, data) {
        if (err) next(err)
        else if (data) {
          cb(null, data)
          r.destroy()
        } else next()
      })
    })
  }
  function end () {
    cb(null, null)
  }
}

Cap.prototype._decodeRow = function (row, doc, cb) {
  var self = this
  var v = row.value
  if (!v) return cb()
  self.db.get('sk!' + v.group, function (err, kp) {
    if (notFound(err)) return cb()
    if (err) return cb(err)
    try {
      var bufs = {
        data: Buffer(v.encdata, 'base64'),
        nonce: Buffer(v.nonce, 'base64'),
        pk: Buffer(v.from, 'hex'),
        sk: Buffer(kp.box.secretKey, 'hex')
      }
    } catch (err) { return cb(err) }
    try {
      var dockey = self.sodium.crypto_box_open_easy(
        bufs.data, bufs.nonce, bufs.pk, bufs.sk
      )
    } catch (err) { return cb(err) }
    if (!dockey) return cb()
    try {
      var bufs = {
        data: Buffer(doc.encdata, 'base64'),
        nonce: Buffer(doc.nonce, 'base64')
      }
    } catch (err) { return cb(err) }
    try {
      var data = self.sodium.crypto_secretbox_open_easy(
        bufs.data, bufs.nonce, dockey)
    } catch (err) { return cb(err) }
    cb(null, data)
  })
}

Cap.prototype.format = function (data, opts, links) {
  var self = this
  if (!opts) opts = {}
  if (!links) links = []
  var groups = [].concat(opts.group || []).concat(opts.groups || [])
  for (var i = 0; i < groups.length; i++) {
    if (typeof groups[i] === 'string' && !ishex(groups[i])) {
      return errtick(cb, 'group public key must be a buffer or hex string')
    } else if (typeof groups[i] === 'string') {
      groups[i] = Buffer(groups[i], 'hex')
    }
  }
  var batch = []
  var dockey = randombytes(self.sodium.crypto_secretbox_KEYBYTES || 32)
  var nonce = randombytes(self.sodium.crypto_secretbox_NONCEBYTES || 24)
  var doc = {
    value: jstr({
      type: 'doc-enc',
      nonce: nonce,
      encdata: self.sodium.crypto_secretbox_easy(data, nonce, dockey)
    })
  }
  var key = framedHash(links, encoder.encode(doc.value, 'json'))

  // throw-away key to send a message to the group
  var kp = self.sodium.crypto_box_keypair()

  // encrypt the document key for each group public key
  groups.forEach(function (g) {
    var nonce = randombytes(self.sodium.crypto_secretbox_NONCEBYTES || 24)
    var siglen = self.sodium.crypto_sign_PUBLICKEYByTES || 32
    var boxlen = self.sodium.crypto_box_PUBLICKEYBYTES || 32
    var boxpk = g.slice(siglen, siglen + boxlen)
    batch.push({
      value: jstr({
        type: 'doc-key',
        group: g.toString('hex'),
        key: key,
        from: kp.publicKey.toString('hex'), // todo: use device key
        nonce: nonce,
        encdata: self.sodium.crypto_box_easy(dockey, nonce, boxpk, kp.secretKey)
      })
    })
  })
  batch.push(doc)
  return batch
}

Cap.prototype.add = function (links, row, opts, cb) {
  var self = this
  if (typeof opts === 'function') {
    cb = opts
    opts = {}
  }
  if (!opts) opts = {}
  var batch = self.format(row, opts, links)
  self.log.batch(batch, function (err, nodes) {
    if (err) cb(err)
    else cb(null, nodes[nodes.length-1])
  })
}

Cap.prototype.append = function (row, opts, cb) {
  var self = this
  if (typeof opts === 'function') {
    cb = opts
    opts = {}
  }
  if (!opts) opts = {}
  var batch = self.format(row, opts, opts.links)
  self.log.batch(batch, function (err, nodes) {
    if (err) cb(err)
    else cb(null, nodes[nodes.length-1])
  })
}

Cap.prototype.batch = function (rows, opts, cb) {
  var self = this
  if (typeof opts === 'function') {
    cb = opts
    opts = {}
  }
  if (!opts) opts = {}
  var batch = [], lens = [], sum = 0
  rows.forEach(function (row) {
    var nbatch = self.format(row, opts, opts.links)
    batch = batch.concat(nbatch)
    sum += nbatch.length;
    lens.push(sum)
  })
  self.log.batch(batch, function (err, nodes) {
    if (err) return cb(err)
    var xnodes = []
    for (var i = 0; i < lens.length; i++) {
      xnodes.push(nodes[lens[i]-1])
    }
    else cb(null, xnodes)
  })
}

Cap.prototype.get = function (key, cb) {
  var self = this
  if (!cb) cb = noop
  self.log.get(key, function (err, doc) {
    if (err) return cb(err)
    var v = doc && doc.value
    if (!v) cb(null, undefined)
    else if (v.type === 'doc') cb(null, v.value)
    else if (v.type === 'doc-enc') {
      self._decode(key, v, cb)
    } else cb(null, undefined)
  })
}

Cap.prototype.createReadStream = function (opts) {
  var self = this
  var pkey = null
  var r = self.log.createReadStream(opts)
  var s = through.obj(write)
  r.on('error', function (err) { s.emit('error', err) })
  return readonly(r.pipe(s))

  function write (row, enc, next) {
    //if (pkey) console.log(row.key, pkey.value.key)
    var v = row.value
    if (!v) return next()
    if (v.type === 'doc-key') {
      pkey = row
      next()
    } else if (v.type === 'doc-enc' && pkey && row.key === pkey.value.key) {
      self._decodeRow(pkey, v, function (err, data) {
        if (err) return next(err)
        else if (!data) return next()
        next(null, {
          key: row.key,
          value: data,
          identity: row.identity,
          signature: row.signature,
          links: row.links
        })
      })
    } else {
      pkey = null
      next()
    }
  }
}

function notFound (err) {
  return err && (/^notfound/i.test(err.message) || err.notFound)
}
function errtick (cb, msg) {
  var err = new Error(msg)
  process.nextTick(function () { cb(err) })
}
function noop () {}

function jstr (doc) {
  var ndoc = {}
  Object.keys(doc).sort().forEach(function (key) {
    if (isbuffer(doc[key])) {
      ndoc[key] = doc[key].toString('base64')
    } else ndoc[key] = doc[key]
  })
  return ndoc
}

function ishex (s) {
  return /^[0-9a-f]+$/i.test(s)
}
