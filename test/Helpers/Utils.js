const packet = require('dns-packet');

function isException(error) {
  let strError = error.toString();
  return (
    strError.includes('invalid opcode') ||
    strError.includes('invalid JUMP') ||
    strError.includes('revert')
  );
}

function ensureException(error) {
  assert(isException(error), error.toString());
}

function hexEncodeName(name) {
  return '0x' + packet.name.encode(name).toString('hex');
}

function hexEncodeTXT(keys) {
  return '0x' + packet.answer.encode(keys).toString('hex');
}

module.exports = {
  zeroAddress: '0x0000000000000000000000000000000000000000',
  ensureException: ensureException,
  hexEncodeTXT: hexEncodeTXT,
  hexEncodeName: hexEncodeName
};
