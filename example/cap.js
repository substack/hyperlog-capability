var level = require('level')
var cap = require('../')({
  logdb: level('/tmp/cap/log'),
  db: level('/tmp/cap/db'),
  sodium: require('chloride'),
  valueEncoding: 'json',
})
if (process.argv[2] === 'create') {
  var name = process.argv[3]
  cap.createGroup(name, function (err, gid) {
    if (err) console.error(err)
    else console.log(name, gid.toString('hex'))
  })
} else if (process.argv[2] === 'list') {
  cap.listGroups(function (err, groups) {
    if (err) return console.error(err)
    groups.forEach(function (g) {
      console.log(g.name, g.id)
    })
  })
} else if (process.argv[2] === 'stream') {
  cap.createReadStream().on('data', function (row) {
    console.log(row.key, row.value.toString())
  })
} else if (process.argv[2] === 'write') {
  var data = Buffer(process.argv.slice(4).join(' '))
  var groups = process.argv[3].split(',')
  cap.append(data, { groups: groups }, function (err, node) {
    if (err) console.error(err)
    else console.log(node.key)
  })
} else if (process.argv[2] === 'get') {
  cap.get(process.argv[3], function (err, doc) {
    if (err) console.error(err)
    else console.log(doc.toString())
  })
}
