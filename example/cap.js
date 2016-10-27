var level = require('level')
var cap = require('../')({
  logdb: level('/tmp/cap/log'),
  capdb: level('/tmp/cap/cap'),
  db: level('/tmp/cap/db'),
  sodium: require('chloride'),
  valueEncoding: 'json',
})
if (process.argv[2] === 'create') {
  cap.createGroup(process.argv[3], function (err, gid) {
    if (err) console.error(err)
    else console.log(gid.toString('hex'))
  })
} else if (process.argv[2] === 'list') {
  cap.listGroups(function (err, groups) {
    if (err) return console.error(err)
    groups.forEach(function (g) {
      console.log(g.name, g.publicKey)
    })
  })
} else if (process.argv[2] === 'write') {
  cap.append({
    group: process.argv[3],
    data: {
      message: process.argv.slice(3).join(' ')
    }
  })
}
