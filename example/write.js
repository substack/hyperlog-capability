var cap = require('../')({
  db: level('/tmp/cap.db'),
  sodium: require('chloride')
})
var msg = process.argv.slice(2).join(' ')
cap.log.append(msg)
