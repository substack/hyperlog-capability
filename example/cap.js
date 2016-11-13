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
  cap.createReadStream().on('data', console.log)
} else if (process.argv[2] === 'append') {
  var id = Buffer(process.argv[3], 'hex')
  var groups = process.argv[4].split(',')
  var data = process.argv.slice(5).join(' ')
  var opts = { groups: groups, identity: id }
  cap.append(data, opts, function (err, node) {
    if (err) console.error(err)
    else console.log(node.key)
  })
} else if (process.argv[2] === 'get') {
  cap.get(process.argv[3], function (err, doc) {
    if (err) console.error(err)
    else console.log(doc.toString())
  })
}
