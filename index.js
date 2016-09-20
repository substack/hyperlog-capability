var hyperlog = require('hyperlog')
var hsodium = require('hyperlog-sodium')
var sub = require('subleveldown')
var inherits = require('inherits')
var EventEmitter = require('events').EventEmitter
var hindex = require('hyperlog-index')
var collect = require('collect-stream')

inherits(Cap, EventEmitter)
module.exports = Cap

var LOG = 'l', CAPLOG = 'c', CAPIX = 'i', CAPS = 'l'

function Cap (opts) {
  var self = this
  if (!(self instanceof Cap)) return new Cap(opts)
  self.db = opts.db
  self.idb = opts.idb
  self.log = hyperlog(sub(opts.db,LOG), opts)
  self.caplog = hyperlog(sub(opts.db,CAPLOG), {
    valueEncoding: 'json'
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
