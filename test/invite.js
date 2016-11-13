var test = require('tape')
var memdb = require('memdb')
var sodium = require('chloride')
var collect = require('collect-stream')
var hcap = require('../')

test('invite', function (t) {
  t.plan(8)
  var cap0 = hcap({
    logdb: memdb(),
    db: memdb(),
    sodium: sodium,
    valueEncoding: 'json'
  })
  var cap1 = hcap({
    logdb: memdb(),
    db: memdb(),
    sodium: sodium,
    valueEncoding: 'json'
  })
  var pending = 2
  var groups = {}
  var dockey = null
  cap0.createGroup('u0', function (err, gid) {
    t.error(err)
    groups.u0 = gid
    cap0.createGroup('shared', function (err, gid) {
      t.error(err)
      groups.shared = gid
      var opts = {
        group: gid,
        identity: gid
      }
      cap0.append('secret message', opts, function (err, node) {
        t.error(err)
        dockey = node.key
        if (--pending === 0) invite()
      })
    })
  })
  cap1.createGroup('u1', function (err, gid) {
    t.error(err)
    groups.u1 = gid
    if (--pending === 0) invite()
  })
  function invite () {
    cap0.invite({
      to: groups.u1,
      group: groups.shared,
      mode: 'rw'
    }, oninvite)
    function oninvite (err) {
      t.error(err)
      var r0 = cap0.log.replicate()
      var r1 = cap1.log.replicate()
      r0.pipe(r1).pipe(r0)
      r1.once('end', checkRead)
    }
  }
  function checkRead () {
    cap1.get(dockey, function (err, doc) {
      t.error(err)
      t.equal(doc.value, 'secret message')
      t.equal(doc.identity.toString('hex'), groups.shared.toString('hex'),
        'expected identity for secret message')
    })
  }
})

test('invite r+w', function (t) {
  t.plan(9)
  var cap0 = hcap({
    logdb: memdb(),
    db: memdb(),
    sodium: sodium,
    valueEncoding: 'json'
  })
  var cap1 = hcap({
    logdb: memdb(),
    db: memdb(),
    sodium: sodium,
    valueEncoding: 'json'
  })
  var pending = 2
  var groups = {}
  var dockey = null
  cap0.createGroup('u0', function (err, gid) {
    t.error(err)
    groups.u0 = gid
    cap0.createGroup('shared', function (err, gid) {
      t.error(err)
      groups.shared = gid
      var opts = {
        group: gid,
        identity: gid
      }
      cap0.append('secret message', opts, function (err, node) {
        t.error(err)
        dockey = node.key
        if (--pending === 0) invite()
      })
    })
  })
  cap1.createGroup('u1', function (err, gid) {
    t.error(err)
    groups.u1 = gid
    if (--pending === 0) invite()
  })
  function invite () {
    cap0.invite({
      to: groups.u1,
      group: groups.shared,
      mode: 'r'
    }, function (err) {
      t.error(err)
      cap0.invite({
        to: groups.u1,
        group: groups.shared,
        mode: 'w'
      }, oninvite)
    })
    function oninvite (err) {
      t.error(err)
      var r0 = cap0.log.replicate()
      var r1 = cap1.log.replicate()
      r0.pipe(r1).pipe(r0)
      r1.once('end', checkRead)
    }
  }
  function checkRead () {
    cap1.get(dockey, function (err, doc) {
      t.error(err)
      t.equal(doc.value, 'secret message')
      t.equal(doc.identity.toString('hex'), groups.shared.toString('hex'),
        'expected identity for secret message')
    })
  }
})
