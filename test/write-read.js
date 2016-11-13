var test = require('tape')
var memdb = require('memdb')
var sodium = require('chloride')
var collect = require('collect-stream')
var hcap = require('../')

test('write read', function (t) {
  t.plan(20)

  var cap = hcap({
    logdb: memdb(),
    db: memdb(),
    sodium: sodium,
    valueEncoding: 'json'
  })
  cap.createGroup('test', function (err, gid) {
    t.error(err)
    cap.listGroups(function (err, groups) {
      t.error(err)
      var exgroups = groups.map(function (g) {
        return { name: g.name, id: g.id }
      })
      t.deepEqual(exgroups, [ { name: 'test', id: gid } ],
        'expected group name and id')
      appendData(gid)
    })
  })
  function appendData (gid) {
    var opts = {
      group: gid,
      identity: gid
    }
    cap.append('hello', opts, function (err, node) {
      t.error(err)
      var pending = 2
      cap.get(node.key, function (err, doc) {
        t.error(err)
        t.equal(doc.value, 'hello', 'expected result from append')
        if (--pending === 0) done()
      })
      var r = cap.createReadStream()
      collect(r, function (err, rows) {
        t.error(err)
        t.deepEqual(rows.map(function (n) { return n.key }), [node.key],
          'expected append key in createReadStream')
        if (--pending === 0) done()
      })
      function done () { addData(node.key, gid) }
    })
  }
  function addData (key, gid) {
    var opts = {
      group: gid,
      identity: gid
    }
    cap.add([key], 'world', opts, function (err, node) {
      t.error(err)
      var pending = 2
      cap.get(node.key, function (err, doc) {
        t.error(err)
        t.equal(doc.value, 'world', 'expected result from append')
        if (--pending === 0) done()
      })
      var r = cap.createReadStream()
      collect(r, function (err, rows) {
        t.error(err)
        t.deepEqual(
          rows.map(function (n) { return n.key }),
          [key,node.key],
          'expected add keys in createReadStream')
        if (--pending === 0) done()
      })
      function done () { batchData([key,node.key], gid) }
    })
  }
  function batchData (prev, gid) {
    var batch = [
      {
        value: 'what',
        links: [prev[0],prev[1]]
      },
      {
        value: 'ever',
        links: [prev[1]]
      }
    ]
    var opts = {
      group: gid,
      identity: gid
    }
    cap.batch(batch, opts, function (err, nodes) {
      t.error(err)
      var pending = 3
      cap.get(nodes[0].key, function (err, doc) {
        t.error(err)
        t.equal(doc.value, 'what', 'batch value 0')
        if (--pending === 0) done()
      })
      cap.get(nodes[1].key, function (err, doc) {
        t.error(err)
        t.equal(doc.value, 'ever', 'batch value 1')
        if (--pending === 0) done()
      })
      var r = cap.createReadStream()
      collect(r, function (err, rows) {
        t.error(err)
        t.deepEqual(
          rows.map(function (n) { return n.key }),
          prev.concat(nodes[0].key, nodes[1].key),
          'expected batch keys in createReadStream')
        if (--pending === 0) done()
      })
    })
    function done () { t.end() }
  }
})
