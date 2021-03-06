var hyperlog = require('hyperlog')
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
var isbuffer = require('is-buffer')
var once = require('once')

var protobuf = require('protocol-buffers')
var fs = require('fs')
var messages = protobuf(fs.readFileSync(__dirname + '/schema.proto'))

var inherits = require('inherits')
var EventEmitter = require('events').EventEmitter

var encoder = require('hyperlog/lib/encode.js')
var empty = new Buffer(0)
var isvalidkp = require('./lib/is-valid-kp.js')
var hashof = require('./lib/hash.js')

inherits(Cap, EventEmitter)
module.exports = Cap

function Cap (opts) {
  var self = this
  if (!(self instanceof Cap)) return new Cap(opts)
  EventEmitter.call(self)
  self.db = defaults(opts.db, { valueEncoding: 'json' })
  self.log = hyperlog(opts.logdb, {
    sign: function (node, cb) {
      try { var doc = messages.Doc.decode(node.value) }
      catch (err) { return cb(err) }
      var key = null
      if (doc.key || doc.invite) { // sent to a group
        key = 'sk!' + (doc.key || doc.invite).group.toString('hex')
      } else if (doc.doc && node.identity) {
        key = 'sk!' + node.identity.toString('hex')
      }
      if (key) {
        self.db.get(key, function (err, kp) {
          if (err) return cb(err)
          var sk = Buffer(kp.sign.secretKey, 'hex')
          cb(null, self.sodium.crypto_sign_detached(node.value, sk))
        })
      } else {
        cb(null, empty)
      }
    },
    verify: function (node, cb) {
      try { var doc = messages.Doc.decode(node.value) }
      catch (err) { return cb(err) }
      var slen = self.sodium.crypto_sign_PUBLICKEYBYTES || 32
      var pk
      if (doc.invite || doc.key) {
        pk = (doc.invite || doc.key).group.slice(0, slen)
      } else if (doc.doc) {
        pk = node.identity.slice(0, slen)
      }
      if (pk) {
        cb(null, self.sodium.crypto_sign_verify_detached(
          node.signature, node.value, pk))
      } else cb(null, false)
    }
  })
  self.log.on('error', function (err) { self.emit('error', err) })
  self.sodium = opts.sodium
  var plen = self.sodium.crypto_box_PUBLICKEYBYTES || 32
  var slen = self.sodium.crypto_sign_PUBLICKEYBYTES || 32

  self._valueEncoding = opts.valueEncoding
  self._dex = hindex({
    db: sub(self.db, 'ic'),
    log: self.log,
    map: function (row, next) {
      try { var doc = messages.Doc.decode(row.value) }
      catch (err) { return next(err) }

      if (doc.key) { // encrypted secret key
        var k = doc.key.dockey.toString('hex')
        self.db.put('dk!' + k + '!' + row.key, {}, next)
      } else if (doc.invite) {
        var iv = doc.invite
        self.db.get('sk!' + iv.to.toString('hex'), function (err, kp) {
          if (notFound(err)) return next()
          if (err) return next(err)
          var pk = iv.group.slice(plen, plen + slen)
          var sk = Buffer(kp.box.secretKey, 'hex')
          try {
            var data = self.sodium.crypto_box_open_easy(
              iv.data, iv.nonce, pk, sk)
            var ikp = data && JSON.parse(data)
          } catch (err) { return next(err) }
          if (ikp) self._addSK(ikp, next)
          else next()
        })
      } else next()
    }
  })
  self._dex.on('error', function (err) { self.emit('error', err) })
}

Cap.prototype._addSK = function (kp, cb) {
  var self = this
  if (!kp.sign && !kp.box) {
    return errtick(cb, 'keypair must have sign, box, or both')
  }
  try {
    var bkp = {
      sign: kp.sign && {
        publicKey: tobuf(kp.sign.publicKey),
        secretKey: tobuf(kp.sign.secretKey)
      },
      box: kp.box && {
        publicKey: tobuf(kp.box.publicKey),
        secretKey: tobuf(kp.box.secretKey)
      }
    }
  } catch (err) { return errtick(cb, err) }
  if (!isvalidkp(self.sodium, bkp)) {
    return errtick(cb, 'invalid keypair')
  }
  var spub = kp.sign.publicKey.toString('hex')
  var bpub = kp.box.publicKey.toString('hex')
  var gid = spub + bpub
  self.db.get('sk!' + gid, function (err, ekp) {
    if (err && !notFound(err)) return cb(err)
    if (ekp) { // already have a key, merge new data without dropping existing
      kp.box = {
        publicKey: (kp.box || {}).publicKey || (ekp.box || {}).publicKey,
        secretKey: (kp.box || {}).secretKey || (ekp.box || {}).secretKey
      }
      kp.sign = {
        publicKey: (kp.sign || {}).publicKey || (ekp.sign || {}).publicKey,
        secretKey: (kp.sign || {}).secretKey || (ekp.sign || {}).secretKey
      }
      self.db.put('sk!' + gid, kp, cb)
    } else {
      self.db.put('sk!' + gid, kp, cb)
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
    },
    {
      type: 'put',
      key: 'pk-name!' + gid + '!' + name,
      value: {}
    }
  ], onbatch)
  function onbatch (err) {
    if (err) cb(err)
    else cb(null, gid)
  }
}

Cap.prototype.listGroups = function (cb) {
  var self = this
  var d = duplexify()
  self._dex.ready(function () {
    var stream = self.db.createReadStream({
      gt: 'pk-name!',
      lt: 'pk-name!\uffff'
    })
    var output = stream.pipe(through.obj(write))
    if (cb) collect(output, cb)
    d.setReadable(output)
  })
  return d
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
  var to = opts.to
  if (typeof to === 'string') {
    try { to = Buffer(to, 'hex') }
    catch (err) { return errtick(cb, err) }
  } else if (!isbuffer(to)) {
    return errtick(cb, 'opts.to must be a hex string or buffer')
  }
  var group = opts.group
  if (typeof group === 'string') {
    try { group = Buffer(group, 'hex') }
    catch (err) { return errtick(cb, err) }
  } else if (!isbuffer(group)) {
    return errtick(cb, 'opts.group must be a hex string or buffer')
  }
  if (typeof opts.mode !== 'string' || !/^[rw]+$/) {
    return errtick(cb, 'opts.mode string must be one of: r, w, rw')
  }
  self.db.get('sk!' + group.toString('hex'), function (err, kp) {
    if (err) return cb(err)
    var nonce = randombytes(self.sodium.crypto_box_NONCEBYTES || 24)
    var sk = Buffer(kp.box.secretKey, 'hex')
    var plen = self.sodium.crypto_box_PUBLICKEYBYTES
    var slen = self.sodium.crypto_sign_PUBLICKEYBYTES
    var pk = to.slice(plen, plen + slen)
    var id = opts.identity
    if (!id && kp.sign && kp.sign.secretKey) {
      id = group
    }
    var obj = {
      box: { publicKey: kp.box.publicKey.toString('hex') },
      sign: { publicKey: kp.sign.publicKey.toString('hex') }
    }
    if (/r/.test(opts.mode)) {
      obj.box.secretKey = kp.box.secretKey.toString('hex')
    }
    if (/w/.test(opts.mode)) {
      obj.sign.secretKey = kp.sign.secretKey.toString('hex')
    }
    var secret = Buffer(JSON.stringify(obj))
    var encdata = self.sodium.crypto_box_easy(secret, nonce, pk, sk)
    self.log.append(messages.Doc.encode({
      invite: {
        to: to,
        group: group,
        nonce: nonce,
        data: encdata
      }
    }), { identity: id }, cb)
  })
}

Cap.prototype._decode = function (key, doc, cb) {
  var self = this
  cb = once(cb || noop)
  var r = self.db.createReadStream({
    gt: 'dk!' + key + '!',
    lt: 'dk!' + key + '!~'
  })
  r.on('error', cb)
  r.pipe(to.obj(write, end)).on('error', cb)

  function write (row, enc, next) {
    var key = row.key.split('!')[2]
    self.log.get(key, function (err, row) {
      if (notFound(err)) return next()
      else if (err) return next(err)
      try { var rdoc = messages.Doc.decode(row.value) }
      catch (err) { return cb(err) }
      if (!rdoc.key) return next()
      self._decodeRow(rdoc.key, doc, function (err, data) {
        if (err) next(err)
        else if (data) {
          cb(null, xtend(row, { value: data }))
          r.destroy()
        } else next()
      })
    })
  }
  function end () {
    cb(null, null)
  }
}

Cap.prototype._decodeRow = function (v, doc, cb) {
  var self = this
  var gid = v.group.toString('hex')

  self.db.get('sk!' + gid, function (err, kp) {
    if (notFound(err)) return cb()
    if (err) return cb(err)
    try {
      var sk = Buffer(kp.box.secretKey, 'hex')
      var pk = v.from
    } catch (err) { return cb(err) }
    try {
      var dockey = self.sodium.crypto_box_open_easy(v.data, v.nonce, pk, sk)
    } catch (err) { return cb(err) }
    if (!dockey) return cb()
    try {
      var bufs = {
        data: doc.data,
        nonce: doc.nonce,
      }
    } catch (err) { return cb(err) }
    try {
      var data = self.sodium.crypto_secretbox_open_easy(
        doc.data, doc.nonce, dockey)
    } catch (err) { return cb(err) }
    try { var dec = encoder.decode(data, self._valueEncoding) }
    catch (err) { return cb(err) }
    cb(null, dec)
  })
}

Cap.prototype.format = function (row, opts, links) {
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
  if (groups.length === 0) {
    throw new Error('must specify one or more groups')
  }
  var id = opts.identity
  if (typeof id === 'string' && ishex(id)) {
    id = Buffer(id, 'hex')
  } else if (!isbuffer(id)) {
    throw new Error('must provide opts.identity')
  }
  var data = encoder.encode(row || empty, self._valueEncoding)
  var batch = []
  var dockey = randombytes(self.sodium.crypto_secretbox_KEYBYTES || 32)
  var nonce = randombytes(self.sodium.crypto_secretbox_NONCEBYTES || 24)
  var doc = {
    value: messages.Doc.encode({
      doc: {
        nonce: nonce,
        data: self.sodium.crypto_secretbox_easy(data, nonce, dockey)
      }
    }),
    identity: id,
    links: links
  }
  var dochash = hashof(links, doc.value)

  // throw-away key to send a message to the group
  var kp = self.sodium.crypto_box_keypair()

  // encrypt the document key for each group public key
  groups.forEach(function (g) {
    var nonce = randombytes(self.sodium.crypto_secretbox_NONCEBYTES || 24)
    var siglen = self.sodium.crypto_sign_PUBLICKEYByTES || 32
    var boxlen = self.sodium.crypto_box_PUBLICKEYBYTES || 32
    var boxpk = g.slice(siglen, siglen + boxlen)
    batch.push({
      value: messages.Doc.encode({
        key: {
          group: g,
          dockey: dochash,
          from: kp.publicKey, // todo: use device key
          nonce: nonce,
          data: self.sodium.crypto_box_easy(dockey, nonce, boxpk, kp.secretKey)
        }
      }),
      identity: id
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
  try {
    var batch = self.format(row, opts, links)
  } catch (err) { return errtick(cb, err) }
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
  try {
    var batch = self.format(row, opts, opts.links)
  } catch (err) { return errtick(cb, err) }
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
    try {
      var nbatch = self.format(row.value, opts, row.links)
    } catch (err) { return errtick(cb, err) }
    batch = batch.concat(nbatch)
    sum += nbatch.length;
    lens.push(sum-1)
  })
  self.log.batch(batch, function (err, nodes) {
    if (err) return cb(err)
    var xnodes = []
    for (var i = 0; i < lens.length; i++) {
      xnodes.push(nodes[lens[i]])
    }
    cb(null, xnodes)
  })
}

Cap.prototype.get = function (key, cb) {
  var self = this
  if (!cb) cb = noop
  self._dex.ready(function () {
    self.log.get(key, onget)
  })
  function onget (err, row) {
    if (err) return cb(err)
    try { var doc = messages.Doc.decode(row.value) }
    catch (err) { return cb(err) }
    if (doc.doc) self._decode(key, doc.doc, cb)
    else cb(null, undefined)
  }
}

Cap.prototype.createReadStream = function (opts) {
  var self = this
  var pkey = null, phex = null
  var r = self.log.createReadStream(opts)
  var s = through.obj(write)
  r.on('error', function (err) { s.emit('error', err) })
  return readonly(r.pipe(s))

  function write (row, enc, next) {
    try { var doc = messages.Doc.decode(row.value) }
    catch (err) { return next(err) }
    if (doc.key) {
      pkey = doc.key
      phex = doc.key.dockey.toString('hex'),
      next()
    } else if (doc.doc && pkey && row.key === phex) {
      self._decodeRow(pkey, doc.doc, function (err, value) {
        if (err) return next(err)
        else if (!value) return next()
        next(null, {
          key: row.key,
          value: value,
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
  var err = typeof msg === 'string' ? new Error(msg) : msg
  process.nextTick(function () { cb(err) })
}
function noop () {}

function ishex (s) {
  return /^[0-9a-f]+$/i.test(s)
}

function tobuf (s) {
  if (typeof s === 'string' && ishex(s)) return new Buffer(s, 'hex')
  else if (isbuffer(s)) return s
  else return null
}
