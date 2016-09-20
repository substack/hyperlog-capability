var cap = require('../')({
  db: level('/tmp/cap.db'),
  sodium: require('chloride'),
  valueEncoding: 'json',
  group: function (row, next) {
    next(null, row.value.group)
  }
})
var msg = process.argv.slice(2).join(' ')
cap.log.append(msg)
