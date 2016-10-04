var level = require('level')
var cap = require('../')({
  db: level('/tmp/cap.db'),
  idb: level('/tmp/icap.db'),
  sodium: require('chloride'),
  valueEncoding: 'json',
  group: function (row, next) {
    next(null, row.value.group)
  }
})
if (process.argv[2] === 'create-group') {
  cap.createGroup(function (err, gid) {
    if (err) console.error(err)
    else console.log(gid)
  })
} else if (process.argv[2] === 'add-key') {
  var gid = process.argv[3]
  var pubkey = process.argv[4]
  cap.addKey(gid, pubkey, function (err, keys) {
    if (err) console.error(err)
    else console.log(keys.join('\n'))
  })
} else if (process.argv[2] === 'id') {
  cap.getKeys({ encoding: 'hex' }, function (err, kp) {
    if (err) console.error(err)
    else console.log(kp.sign.publicKey)
  })
} else if (process.argv[2] === 'list-keys') {
  var gid = process.argv[3]
  cap.list(gid, function (err, keys) {
    if (err) console.error(err)
    else console.log(keys.map(function (x) {
      return x.publicKey
    }).join('\n'))
  })
} else if (process.argv[2] === 'write') {
  cap.log.append({
    group: process.argv[3],
    message: process.argv.slice(3).join(' ')
  })
}
