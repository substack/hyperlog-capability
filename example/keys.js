var cap = require('../')({
  db: level('/tmp/cap.db'),
  sodium: require('chloride')
})
cap.list(function (err, keys) {
  if (err) console.error(err)
  else console.log(keys.join('\n'))
})
