var cap = require('../')({
  db: level('/tmp/cap.db'),
  sodium: require('chloride'),
  valueEncoding: 'json',
  group: function (row, next) {
    next(null, row.value.group)
  }
})
var groups = process.argv[2].split(',')
var msg = process.argv.slice(3).join(' ')
cap.log.append({
  group: group,
  message: msg
})
