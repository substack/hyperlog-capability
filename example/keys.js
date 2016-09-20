var cap = require('../')({
  db: level('/tmp/cap.db'),
  sodium: require('chloride'),
  valueEncoding: 'json',
  group: function (row, next) {
    next(null, row.value.group)
  }
})
cap.list(function (err, keys) {
  if (err) console.error(err)
  else console.log(keys.join('\n'))
})
