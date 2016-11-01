// from hyperlog/lib/hash.js with buffer digest
// this should always be in sync with hyperlog core

var framedHash = require('framed-hash')

module.exports = function (links, value) {
  var hash = framedHash('sha256')
  for (var i = 0; i < links.length; i++) hash.update(links[i])
  hash.update(value)
  return hash.digest('buffer')
}
