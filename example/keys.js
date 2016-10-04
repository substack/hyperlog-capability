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
var group = process.argv[2]
cap.list(group, function (err, keys) {
  if (err) console.error(err)
  else console.log(keys.map(function (x) { return x.publicKey }).join('\n'))
})
