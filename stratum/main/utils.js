// Declare all module variables at the very top to avoid temporal dead zone issues
let bchaddr, bech32, bs58check, crypto, merkleTree, net;

// Define loadCommonJSModules and ensureModules before any usage
const loadCommonJSModules = async () => {
  if (!bchaddr) bchaddr = (await import('bchaddrjs')).default || (await import('bchaddrjs'));
  if (!bech32) bech32 = (await import('bech32')).default || (await import('bech32'));
  if (!bs58check) bs58check = (await import('bs58check')).default || (await import('bs58check'));
  if (!crypto) crypto = (await import('crypto')).default || (await import('crypto'));
  if (!merkleTree) merkleTree = (await import('merkle-lib')).default || (await import('merkle-lib'));
  if (!net) net = (await import('net')).default || (await import('net'));
};


// Ensure all modules are loaded at startup
ensureModules();

// Immediately load modules if top-level await is supported
if (typeof process !== 'undefined' && process.env && process.env.NODE_ENV !== 'test') {
  loadCommonJSModules();
}

// Helper to ensure modules are loaded before use
async function ensureModules() {
  if (!bchaddr || !bech32 || !bs58check || !crypto || !merkleTree || !net) {
    await loadCommonJSModules();
  }
}

////////////////////////////////////////////////////////////////////////////////

// Convert Address to Script
export function addressToScript(addr, network) {
  if ((network || {}).coin === 'bch' && isCashAddress(addr)) {
    const processed = toLegacyAddress(addr);
    return decodeAddress(processed, network || {});
  } else if (typeof (network || {}).coin !== 'undefined') {
    return decodeAddress(addr, network || {});
  } else {
    const processed = decodeBase58Address(addr).hash;
    return encodeAddress(processed, 'pubkey');
  }
}

// Convert Bits into Target BigInt
export function bigIntFromBitsBuffer(bitsBuff) {
  const numBytes = bitsBuff.readUInt8(0);
  const bigBits = bufferToBigInt(bitsBuff.slice(1));
  return bigBits * (BigInt(2) ** (BigInt(8) * BigInt(numBytes - 3)));
}

// Convert Bits into Target BigInt
export function bigIntFromBitsHex(bitsString) {
  const bitsBuff = Buffer.from(bitsString, 'hex');
  return bigIntFromBitsBuffer(bitsBuff);
}

// Convert Buffer to BigInt
export function bufferToBigInt(buffer, start = 0, end = buffer.length) {
  const hexStr = buffer.slice(start, end).toString('hex');
  return BigInt(`0x${hexStr}`);
}

// Check if Host/Port is Active
export function checkConnection(host, port, timeout) {
  return new Promise((resolve, reject) => {
    timeout = timeout || 10000;
    const timer = setTimeout(() => {
      reject('timeout');
      /* eslint-disable-next-line no-use-before-define */
      socket.end();
    }, timeout);
    const socket = createConnection(port, host, () => {
      clearTimeout(timer);
      resolve();
      socket.end();
    });
    socket.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

// Convert Transaction Hashes to Buffers
export function convertHashToBuffer(txs) {
  const txHashes = txs.map((tx) => {
    if (tx.txid !== undefined) return uint256BufferFromHash(tx.txid);
    return uint256BufferFromHash(tx.hash);
  });
  return txHashes;
}

// Determine Type + Decode Any Address
export function decodeAddress(address, network) {

  // Try to Decode Base58 Address
  try {
    const decoded = decodeBase58Address(address);
    if (decoded) {
      if (decoded.version === (network.pubKeyHash || 0x00)) return encodeAddress(decoded.hash, 'pubkey');
      if (decoded.version === (network.scriptHash || 0x05)) {
        return encodeAddress(decoded.hash, 'script');
      }
    }
  } catch(e) {
    console.error(`decodeBase58Address failed for address (${address}):`, e);
    throw e;
  }

  // Try to Decode Bech32 Address
  try {
    const decoded = decodeBech32Address(address);
    if (decoded.prefix !== (network.bech32 || 'bc')) throw new Error(`The address (${ address }) given has an invalid prefix`);
    if (decoded) {
      if (decoded.data.length === 20) return encodeAddress(decoded.data, 'witnesspubkey');
      if (decoded.data.length === 32) return encodeAddress(decoded.data, 'witnessscript');
    }
  /* eslint-disable-next-line no-empty */
  } catch(e) {}

  // Invalid Address Specified
  throw new Error(`The address (${ address }) given has no matching address script`);
}

// Decode Any Base58 Address
export function decodeBase58Address(address) {
  let payload;
  try {
    payload = bs58check.decode(address);
  } catch (e) {
    throw new Error(`${e.message}`);
  }
  
  if (payload.length < 21) throw new Error(`The address (${ address }) given is too short`);
  if (payload.length > 22) throw new Error(`The address (${ address }) given is too long`);

  const version = payload.length === 22 ? payload.readUInt16BE(0) : payload[0];
  const hash = payload.slice(payload.length === 22 ? 2 : 1);
  return { version: version, hash: hash };
}

// Decode Any Bech32 Address
export function decodeBech32Address (address) {
  const payload = decode(address);
  const data = fromWords(payload.words.slice(1));
  return { version: payload.words[0], prefix: payload.prefix, data: Buffer.from(data) };
}

// Encode Input Buffer Data
export function encodeAddress(address, type) {
  switch(type) {
  case 'pubkey':
    return encodeChunks([
      getBitcoinOPCodes('OP_DUP'),
      getBitcoinOPCodes('OP_HASH160'), address,
      getBitcoinOPCodes('OP_EQUALVERIFY'),
      getBitcoinOPCodes('OP_CHECKSIG'),
    ]);
  case 'script':
    return encodeChunks([
      getBitcoinOPCodes('OP_HASH160'), address,
      getBitcoinOPCodes('OP_EQUAL'),
    ]);
  case 'witnesspubkey':
    return encodeChunks([
      getBitcoinOPCodes('OP_0'), address,
    ]);
  case 'witnessscript':
    return encodeChunks([
      getBitcoinOPCodes('OP_0'), address,
    ]);
  }
}

// Encode Input Buffer Data
export function encodeBuffer(buffer, number, offset) {
  const size = getEncodingLength(number);
  if (size === 1) {
    buffer.writeUInt8(number, offset);
  } else if (size === 2) {
    buffer.writeUInt8(getBitcoinOPCodes('OP_PUSHDATA1'), offset);
    buffer.writeUInt8(number, offset + 1);
  } else if (size === 3) {
    buffer.writeUInt8(getBitcoinOPCodes('OP_PUSHDATA2'), offset);
    buffer.writeUInt16LE(number, offset + 1);
  } else {
    buffer.writeUInt8(getBitcoinOPCodes('OP_PUSHDATA4'), offset);
    buffer.writeUInt32LE(number, offset + 1);
  }
  return size;
}

// Encode Input Address Chunks
export function encodeChunks(chunks) {

  // Reduce Chunk Data to Buffer
  const bufferSize = chunks.reduce((accum, chunk) => {
    if (Buffer.isBuffer(chunk)) {
      if (chunk.length === 1 && getMinimalOPCodes(chunk) !== undefined) {
        return accum + 1;
      }
      return accum + getEncodingLength(chunk.length) + chunk.length;
    }
    return accum + 1;
  }, 0.0);

  let offset = 0;
  const buffer = Buffer.allocUnsafe(bufferSize);

  // Encode + Write Individual Chunks to Buffer
  chunks.forEach((chunk) => {
    if (Buffer.isBuffer(chunk)) {
      const opcode = getMinimalOPCodes(chunk);
      if (opcode !== undefined) {
        buffer.writeUInt8(opcode, offset);
        offset += 1;
        return;
      }
      offset += encodeBuffer(buffer, chunk.length, offset);
      chunk.copy(buffer, offset);
      offset += chunk.length;
    } else {
      buffer.writeUInt8(chunk, offset);
      offset += 1;
    }
  });

  if (offset !== buffer.length) throw new Error('The pool could not decode the chunks of the given address');
  return buffer;
}

// Generate Unique ExtraNonce for each Subscriber
/* istanbul ignore next */
export function extraNonceCounter(size) {
  return {
    size: size,
    next: function() {
      return(randomBytes(this.size).toString('hex'));
    }
  };
}

// Calculate Merkle Hash Position
// https://github.com/p2pool/p2pool/blob/53c438bbada06b9d4a9a465bc13f7694a7a322b7/p2pool/bitcoin/data.py#L218
// https://stackoverflow.com/questions/8569113/why-1103515245-is-used-in-rand
export function getAuxMerklePosition(chain_id, size) {
  return (1103515245 * chain_id + 1103515245 * 12345 + 12345) % size;
}

// Calculate PushData OPCodes
export function getBitcoinOPCodes(type) {
  switch(type) {
  case 'OP_0':
    return 0;
  case 'OP_PUSHDATA1':
    return 76;
  case 'OP_PUSHDATA2':
    return 77;
  case 'OP_PUSHDATA4':
    return 78;
  case 'OP_1NEGATE':
    return 79;
  case 'OP_RESERVED':
    return 80;
  case 'OP_DUP':
    return 118;
  case 'OP_EQUAL':
    return 135;
  case 'OP_EQUALVERIFY':
    return 136;
  case 'OP_HASH160':
    return 169;
  case 'OP_CHECKSIG':
    return 172;
  default:
    return 0;
  }
}

// Calculate Encoding Length
export function getEncodingLength(data) {
  return data < getBitcoinOPCodes('OP_PUSHDATA1') ? 1
    : data <= 0xff ? 2
      : data <= 0xffff ? 3
        : 5;
}

// Calculate Merkle Steps for Transactions
export function getMerkleSteps(transactions) {
  const hashes = convertHashToBuffer(transactions);
  const merkleData = [Buffer.from([], 'hex')].concat(hashes);
  const merkleTreeFull = merkleTree(merkleData, sha256d);
    // If merkleTreeFull.proof exists, use it. Otherwise, implement proof logic or throw an error.
    if (typeof merkleTreeFull.proof === 'function') {
      return merkleTreeFull.proof(merkleData[0]).slice(1, -1).filter((node) => node !== null);
    } else if (typeof merkleTree.proof === 'function') {
      return merkleTree.proof(merkleTreeFull, merkleData[0]).slice(1, -1).filter((node) => node !== null);
    } else {
      throw new Error('Merkle proof function not found in merkle-lib. Please check the library documentation.');
    }
}

// Calculate Minimal OPCodes for Buffer
export function getMinimalOPCodes(buffer) {
  if (buffer.length === 0) return getBitcoinOPCodes('OP_0');
  if (buffer.length !== 1) return;
  if (buffer[0] >= 1 && buffer[0] <= 16) {
    return getBitcoinOPCodes('OP_RESERVED') + buffer[0];
  }
  if (buffer[0] === 0x81) return getBitcoinOPCodes('OP_1NEGATE');
}

// Calculate Equihash Solution Length
export function getSolutionLength(nParam, kParam) {
  switch(`${nParam}_${kParam}`) {
  case '125_4':
    return 106;
  case '144_5':
    return 202;
  case '192_7':
    return 806;
  case '200_9':
    return 2694;
  }
}

// Calculate Equihash Solution Slice
export function getSolutionSlice(nParam, kParam) {
  switch(`${nParam}_${kParam}`) {
  case '125_4':
    return 2;
  case '144_5':
    return 2;
  case '192_7':
    return 6;
  case '200_9':
    return 6;
  }
}

// Check if Input is Hex String
export function isHexString(s) {
  const check = String(s).toLowerCase();
  if(check.length % 2) {
    return false;
  }
  for (let i = 0; i < check.length; i = i + 2) {
    const c = check[i] + check[i+1];
    if (!isHex(c))
      return false;
  }
  return true;
}

// Check if Input is Hex
export function isHex(c) {
  const a = parseInt(c,16);
  let b = a.toString(16).toLowerCase();
  if(b.length % 2) {
    b = '0' + b;
  }
  if (b !== c) {
    return false;
  }
  return true;
}

// Generate Unique Job for each Template
/* istanbul ignore next */
export function jobCounter() {
  return {
    counter: 0,
    next: function() {
      this.counter += 1;
      if (this.counter % 0xffff === 0) {
        this.counter = 1;
      }
      return this.cur();
    },
    cur: function() {
      return this.counter.toString(16);
    }
  };
}

// Alloc/Write UInt16LE
export function packUInt16LE(num) {
  const buff = Buffer.alloc(2);
  buff.writeUInt16LE(num, 0);
  return buff;
}

// Alloc/Write UInt16LE
export function packUInt16BE(num) {
  const buff = Buffer.alloc(2);
  buff.writeUInt16BE(num, 0);
  return buff;
}

// Alloc/Write UInt32LE
export function packUInt32LE(num) {
  const buff = Buffer.alloc(4);
  buff.writeUInt32LE(num, 0);
  return buff;
}

// Alloc/Write UInt32BE
export function packUInt32BE(num) {
  const buff = Buffer.alloc(4);
  buff.writeUInt32BE(num, 0);
  return buff;
}

// Alloc/Write Int64LE
export function packUInt64LE(num) {
  const buff = Buffer.alloc(8);
  buff.writeUInt32LE(num % Math.pow(2, 32), 0);
  buff.writeUInt32LE(Math.floor(num / Math.pow(2, 32)), 4);
  return buff;
}

// Alloc/Write Int64LE
export function packUInt64BE(num) {
  const buff = Buffer.alloc(8);
  buff.writeUInt32BE(Math.floor(num / Math.pow(2, 32)), 0);
  buff.writeUInt32BE(num % Math.pow(2, 32), 4);
  return buff;
}

// Alloc/Write Int32LE
export function packInt32LE(num) {
  const buff = Buffer.alloc(4);
  buff.writeInt32LE(num, 0);
  return buff;
}

// Alloc/Write Int32BE
export function packInt32BE(num) {
  const buff = Buffer.alloc(4);
  buff.writeInt32BE(num, 0);
  return buff;
}

// Convert PubKey to Script
export function pubkeyToScript(key){
  if (key.length !== 66) throw new Error(`The pubkey (${ key }) is invalid`);
  const pubKey = Buffer.concat([Buffer.from([0x21]), Buffer.alloc(33), Buffer.from([0xac])]);
  const bufferKey = Buffer.from(key, 'hex');
  bufferKey.copy(pubKey, 1);
  return pubKey;
}

// Range Function
export function range(start, stop, step) {
  if (typeof step === 'undefined') {
    step = 1;
  }
  if (typeof stop === 'undefined') {
    stop = start;
    start = 0;
  }
  if ((step > 0 && start >= stop) || (step < 0 && start <= stop)) {
    return [];
  }
  const result = [];
  for (let i = start; step > 0 ? i < stop : i > stop; i += step) {
    result.push(i);
  }
  return result;
}

// Reverse Input Buffer
export function reverseBuffer(buff) {
  const reversed = Buffer.alloc(buff.length);
  for (let i = buff.length - 1; i >= 0; i--) {
    reversed[buff.length - i - 1] = buff[i];
  }
  return reversed;
}

// Reverse Byte Order of Input Buffer
export function reverseByteOrder(buff) {
  for (let i = 0; i < 8; i += 1) {
    buff.writeUInt32LE(buff.readUInt32BE(i * 4), i * 4);
  }
  return reverseBuffer(buff);
}

// Reverse Input Buffer + Hex String
export function reverseHex(hex) {
  return reverseBuffer(Buffer.from(hex, 'hex')).toString('hex');
}

// Round to # of Digits Given
export function roundTo(n, digits) {
  if (!digits) {
    digits = 0;
  }
  const multiplicator = Math.pow(10, digits);
  n = parseFloat((n * multiplicator).toFixed(11));
  const test = Math.round(n) / multiplicator;
  return +(test.toFixed(digits));
}

// Serialize Height/Date Input
/* istanbul ignore next */
export function serializeNumber(n) {
  if (n >= 1 && n <= 16) {
    return Buffer.from([0x50 + n]);
  }
  let l = 1;
  const buff = Buffer.alloc(9);
  while (n > 0x7f) {
    buff.writeUInt8(n & 0xff, l++);
    n >>= 8;
  }
  buff.writeUInt8(l, 0);
  buff.writeUInt8(n, l++);
  return buff.slice(0, l);
}

// Serialize Strings used for Signature
/* istanbul ignore next */
export function serializeString(s) {
  if (s.length < 253) {
    return Buffer.concat([
      Buffer.from([s.length]),
      Buffer.from(s)
    ]);
  } else if (s.length < 0x10000) {
    return Buffer.concat([
      Buffer.from([253]),
      packUInt16LE(s.length),
      Buffer.from(s)
    ]);
  } else if (s.length < 0x100000000) {
    return Buffer.concat([
      Buffer.from([254]),
      packUInt32LE(s.length),
      Buffer.from(s)
    ]);
  } else {
    return Buffer.concat([
      Buffer.from([255]),
      packUInt16LE(s.length),
      Buffer.from(s)
    ]);
  }
}

// Hash Input w/ Sha256
export function sha256(buffer) {
  const hash1 = createHash('sha256');
  hash1.update(buffer);
  return hash1.digest();
}

// Hash Input w/ Sha256d
export function sha256d(buffer) {
  return sha256(sha256(buffer));
}

// Generate Reverse Buffer from Input Hash
export function uint256BufferFromHash(hex) {
  let fromHex = Buffer.from(hex, 'hex');
  if (fromHex.length != 32) {
    const empty = Buffer.alloc(32);
    empty.fill(0);
    fromHex.copy(empty);
    fromHex = empty;
  }
  return reverseBuffer(fromHex);
}

// Generate VarInt Buffer
export function varIntBuffer(n) {
  if (n < 0xfd) {
    return Buffer.from([n]);
  } else if (n <= 0xffff) {
    const buff = Buffer.alloc(3);
    buff[0] = 0xfd;
    packUInt16LE(n).copy(buff, 1);
    return buff;
  } else if (n <= 0xffffffff) {
    const buff = Buffer.alloc(5);
    buff[0] = 0xfe;
    packUInt32LE(n).copy(buff, 1);
    return buff;
  } else {
    const buff = Buffer.alloc(9);
    buff[0] = 0xff;
    packUInt64LE(n).copy(buff, 1);
    return buff;
  }
}

// Generate VarString Buffer
export function varStringBuffer(string) {
  const strBuff = Buffer.from(string);
  return Buffer.concat([varIntBuffer(strBuff.length), strBuff]);
}
