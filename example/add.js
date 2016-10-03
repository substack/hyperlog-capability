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
var pubkey = process.argv[3]

cap.add(group, pubkey, function (err, keys) {
  if (err) console.error(err)
  else console.log(keys.join('\n'))
})
