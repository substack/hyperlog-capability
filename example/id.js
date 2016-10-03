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
cap.keypair({ encoding: 'hex' }, function (err, kp) {
  if (err) console.error(err)
  else console.log(kp)
})
