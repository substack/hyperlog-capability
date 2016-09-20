var hyperlog = require('hyperlog')
var hsodium = require('hyperlog-sodium')
var sub = require('subleveldown')
var inherits = require('inherits')
var EventEmitter = require('events').EventEmitter

inherits(Cap, EventEmitter)
module.exports = Cap

var LOG = 'l', KEYLOG = 'k'

function Cap (opts) {
  if (!(this instanceof Cap)) return new Cap(opts)
  this.log = hyperlog(sub(opts.db,LOG), opts)
  this.clog = hyperlog(sub(opts.db,KEYLOG), { valueEncoding: 'json' })
  this.db = opts.db
  this._groupfn = opts.group
}

Cap.prototype.add = function (group, pubkey, cb) {
}

Cap.prototype.remove = function (group, pubkey, cb) {
  
}

Cap.prototype.list = function (cb) {
}
