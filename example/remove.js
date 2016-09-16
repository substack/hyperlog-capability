var cap = require('../')({
  db: level('/tmp/cap.db'),
  sodium: require('chloride')
})
var pubkey = process.argv[2]

cap.remove(pubkey, function (err, keys) {
  if (err) console.error(err)
  else console.log(keys.join('\n'))
})
