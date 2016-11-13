# hyperlog-capability

group permissions for [hyperlog][1]

WARNING: experimental, unproven cryptosystem!

[Capability systems][3] enforce "who can do what" with a resource. Unix file
permissions are a good example: a bitfield specifies who is allowed to read,
write, or execute each file.

This package provides a familiar read+write capability system using cryptography
designed for group-to-group collaboration.

In the literature you can read about some p2p group key management schemes, but
they too often assume a low-latency, available network which is not a reasonable
assumption for many off grid, real-world settings. This package makes tradeoffs
that work for high-latency scenarios like passing around a usb thumb drive
between remote off-grid communities.

[1]: https://npmjs.com/package/hyperlog
[3]: http://srl.cs.jhu.edu/pubs/SRL2003-02.pdf

# example

``` js
var level = require('level')
var cap = require('hyperlog-capability')({
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
```

# api

``` js
var hcap = require('hyperlog-capability')
```

## var log = hcap(opts)

* `opts.logdb` - [leveldb][2] instance to store log data
* `opts.db` - [leveldb][2] instance to store capability tables
* `opts.sodium` - sodium interface (`require('chloride')` works well)
* `opts.valueEncoding` - store log records with this encoding

`log` provides the [hyperlog][1] interface plus the methods documented below.

Every insertion with `log.batch()`, `log.append()`, or `log.add()` must provide:

* `opts.groups` - array of group hex id strings that are allowed access to the
document being inserted
* `opts.identity` - group id to use to sign the document being inserted

[2]: https://npmjs.com/package/levelup

## log.createGroup(name, cb)

Create a group identified by the human-meaningful, non-exclusive string `name`.

`cb(err, gid)` fires with the group id hex string `gid`.

## var stream = log.listGroups(cb)

Get a list of all groups as a readable stream or as `cb(err, groups)`.

Each group object has:

* `group.id` - unique group id hex string
* `group.name` - human-meaningful, non-exclusive name

## log.invite(opts, cb)

* `opts.to` - recipient group of this invitation
* `opts.group` - the group to be joined
* `opts.mode` - read/write mode string: `'r'`, `'w'`, or `'rw'`

If you have read access to a group, you will be able to decrypt messages.

If you have write access to a group, you will be able to sign messages on behalf
of the group that will be accepted as a legitimate.

# design

The cryptographic capabilities of the system are enforced implicitly by
knowledge of secret keys. Each group has two keypairs: a signing key (sign) and
an encryption key (box). The sign/box terminology corresponds to the underlying
sodium `crypto_sign` and `crypto_box` methods for each keypair.

The group id is the concatenation of the signing public key with
the box public key.

If you know the box key, you can read messages addressed to the group.
If you know the sign key, you can create messages that will be accepted as
legitimate communications on behalf of that group by other peers.

When you write a document into the log, the document is encrypted with a unique
32-byte document key. Each group that will get access to this document receives
a secret message encrypted to the group's box key. The secret message contains
the document key.

When you invite group A to join group B, you encrypt a message to A's box key
with B's box and/or sign key. If A has access from an invite to B's box key,
then A can decrypt any documents encrypted for B, including future invites.
However, invites are one-way, so B can't read A's documents.

The only unit of social organization in this package is the group where a group
refers to the agents that have access to that group's secret keys. For
bootstrapping and other purposes, you will probably want to have each machine or
personal identity belong to a single-member group.

# install

```
npm install hyperlog-capability
```

# license

BSD
