const anchor = require('@project-serum/anchor');
const secp256k1 = require('secp256k1');
const {keccak_256 } = require('js-sha3');
const { snakeCase } = require('snake-case');
const { sha256 } = require("js-sha256");

const {struct, u8, u16, u32, blob} = require("@solana/buffer-layout");
const {Buffer} = require('buffer');

function buf_hexdump(buffer, blockSize) {
    
	blockSize = blockSize || 16;
    var lines = [];
    var hex = "0123456789ABCDEF";
    for (var b = 0; b < buffer.length; b += blockSize) {
        var block = buffer.slice(b, Math.min(b + blockSize, buffer.length));
        var addr = ("0000" + b.toString(16)).slice(-4);
        var codes = Array.from(block).map( ch => " " + hex[(0xF0 & ch) >> 4] + hex[0x0F & ch]).join("");
        codes += "   ".repeat(blockSize - block.length);
        var chars = block.toString().replace(/[\x00-\x1F\x20]/g, '.');
        chars +=  " ".repeat(blockSize - block.length);
        lines.push(addr + " " + codes + "  " + chars);
    }
    return lines.join("\n");
}

function MsgsToInstructionData(messages, instr_index) {
  
  const START_OFFSET = 1;
  const PUBKEY_SIZE = 20;

  let secpStruct = struct([
      u16('secp_signature_offset'),
      u8('secp_instruction_index'),
      u16('secp_pubkey_offset'),
      u8('secp_pubkey_instruction_index'),
      u16('secp_message_data_offset'),
      u16('secp_message_data_size'),
      u8('secp_message_instruction_index')
  ]);

  let sigStruct = struct([
    blob(64, 'signature'),
    u8('recid'),
    blob(PUBKEY_SIZE, 'pubkey'),
  ]);

  let BUFFER_SIZE = START_OFFSET + // messages count
  secpStruct.span * messages.length + // headers * messages count
  sigStruct.span * messages.length + // signatures * messages count
  //messages[0].msg.length - may be adappted to compact variant
  messages.reduce((total, msg) => total + msg.msg.length, 0) // messages total length

  // console.log(`Allocating buffer of size: ${BUFFER_SIZE}`)

  let DATA_OFFSET = secpStruct.span * messages.length + START_OFFSET;
  // console.log(`Data offset: ${DATA_OFFSET}`);

  let instruction = Buffer.alloc(BUFFER_SIZE)
  instruction[0] = messages.length

  let result = {offset: DATA_OFFSET, buffer: instruction}

  messages.reduce((acc, message, index) => {

    //console.log(`[Filling header #${index}] Current offset: ${acc.offset}, header offset: ${secpStruct.span*index+START_OFFSET}`)
    
    // fill header
    secpStruct.encode({
      secp_signature_offset: acc.offset,
      secp_instruction_index: instr_index,
      secp_pubkey_offset: acc.offset+65,
      secp_pubkey_instruction_index: instr_index,
      secp_message_data_offset: acc.offset + sigStruct.span,//BUFFER_SIZE-message.msg.length - may be adapted to compact variant
      secp_message_data_size: message.msg.length,
      secp_message_instruction_index: instr_index,
    }, acc.buffer, secpStruct.span*index+START_OFFSET);

    //console.log(`[Filled header #${index}] Current offset: ${acc.offset}`)

    // fill signature
    sigStruct.encode({
      signature: message.sig,
      recid: message.recid,
      pubkey: message.ethPubkey
    }, acc.buffer, acc.offset);
    acc.offset += sigStruct.span;

    //console.log(`[Filled signature #${index}, recid: ${message.recid}] Current offset: ${acc.offset}`)

    //if (index===messages.length-1) { - may be adapted to compact varaint
      // fill message
    //}
    
    blob(message.msg.length).encode(message.msg, acc.buffer, acc.offset);
    acc.offset += message.msg.length;

    //console.log(`[Filled message ${index}] Current offset: ${acc.offset}`)

    return acc;
  }, result);

  return result.buffer
}

function CreateSignedMsg(message, signer) {
  let plaintext = Buffer.from(message);
  let plaintextHash = Buffer.from(keccak_256.update(plaintext).digest());
  let {signature, recid: recoveryId} = secp256k1.ecdsaSign(
    plaintextHash,
    signer.privateKey
  );
  return {
    msg: plaintext,
    sig: signature,
    recid: recoveryId,
    ethPubkey: anchor.web3.Secp256k1Program.publicKeyToEthAddress(signer.publicKey)
  }
}

function CreateMsgWithMulipleSigs(message, signers, instr_index) {
  return MsgsToInstructionData(
    Array.from(signers, signer => CreateSignedMsg(message, signer), instr_index)
  )
}

function CreateSigner() {
  let secp256k1PrivateKey;
  do {
    secp256k1PrivateKey = anchor.web3.Keypair.generate().secretKey.slice(0, 32); 
  } while (!secp256k1.privateKeyVerify(secp256k1PrivateKey));
    
  let secp256k1PublicKey = secp256k1.publicKeyCreate(secp256k1PrivateKey, false).slice(1);

  return {
    publicKey: secp256k1PublicKey,
    privateKey: secp256k1PrivateKey
  }
}

function sbxInstrData(message) {

    let name = snakeCase('initialize');
    let method = Buffer.from(sha256.digest(`global:${name}`)).slice(0, 8)

    methStruct = struct([
      blob(8, 'meth_hash'),
      u32('size'),
      blob(message.length, 'message')
    ])

    let buffer = Buffer.alloc(12+message.length)
    methStruct.encode({
      meth_hash: method,
      size: message.length,
      message: message
    }, buffer);

    return buffer
}

function defaultSecp256(message, signer) {
  let plaintext = Buffer.from(message);
  let plaintextHash = Buffer.from(keccak_256.update(plaintext).digest());
  let {signature, recid: recoveryId} = secp256k1.ecdsaSign(
      plaintextHash,
      signer.privateKey
  );
  
  let ethPubkey = anchor.web3.Secp256k1Program.publicKeyToEthAddress(signer.publicKey).toString('hex');
  
  // Create transaction to verify the signature
  let instr = anchor.web3.Secp256k1Program.createInstructionWithEthAddress({
      ethAddress: ethPubkey,
      message: plaintext,
      signature: signature,
      recoveryId: recoveryId,
  })
  let transaction = new anchor.web3.Transaction().add(instr)
  return transaction
}

describe('sandbox-anchor', () => {

  // Configure the client to use the local cluster.

  const provider = anchor.Provider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.SandboxAnchor;

  let programPk = new anchor.web3.PublicKey("9DxrDu7MwthUNerqq3VYKksSWugck2sa8y27q4y6nrAj");
  
  it('Checks if default secp256k1 works fine', async () => {
    let signers = [CreateSigner()];
    let message = "test_default";
    let signed = CreateMsgWithMulipleSigs(message, signers, 0);
    
    let secp_instr = new anchor.web3.TransactionInstruction({
      data: signed, 
      programId: anchor.web3.Secp256k1Program.programId,
      keys: []
    });

    let sbx_instr = new anchor.web3.TransactionInstruction({
      data: sbxInstrData(Buffer.from(message)),
      programId: programPk,
      keys: [
        { isSigner: 0, isWritable: 0, pubkey: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY },
      ],
    });

    let trans = defaultSecp256(message, signers[0]);

    trans
    .add(sbx_instr);

    let listener = null
    let [event, slot] = await new Promise((resolve, _reject) => {
      listener = program.addEventListener("Initialized", (event, slot) => {
        resolve([event, slot]);
      });
      
      program.provider.send(trans)
    });
    await program.removeEventListener(listener);
    console.log(event, slot);
  });

  it('Checks if custom secp256k1with one signature works fine', async () => {
    let signers = [CreateSigner()];
    let message = "test_custom_single";
    let signed = CreateMsgWithMulipleSigs(message, signers, 0);
    
    let secp_instr = new anchor.web3.TransactionInstruction({
      data: signed, 
      programId: anchor.web3.Secp256k1Program.programId,
      keys: []
    });

    let sbx_instr = new anchor.web3.TransactionInstruction({
      data: sbxInstrData(Buffer.from(message)),
      programId: programPk,
      keys: [
        { isSigner: 0, isWritable: 0, pubkey: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY },
      ],
    });

    let trans = new anchor.web3.Transaction()
    .add(secp_instr)
    .add(sbx_instr);

    let listener = null
    let [event, slot] = await new Promise((resolve, _reject) => {
      listener = program.addEventListener("Initialized", (event, slot) => {
        resolve([event, slot]);
      });
      
      program.provider.send(trans)
    });
    await program.removeEventListener(listener);
    console.log(event, slot);
  });

  it('Checks if custom secp256k1 with multiple signatures works fine', async () => {
    let signers = [CreateSigner(), CreateSigner()];
    let message = "test_custom_multiple";
    let signed = CreateMsgWithMulipleSigs(message, signers, 0);
    
    let secp_instr = new anchor.web3.TransactionInstruction({
      data: signed, 
      programId: anchor.web3.Secp256k1Program.programId,
      keys: []
    });

    let sbx_instr = new anchor.web3.TransactionInstruction({
      data: sbxInstrData(Buffer.from(message)),
      programId: programPk,
      keys: [
        { isSigner: 0, isWritable: 0, pubkey: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY },
      ],
    });

    let trans = new anchor.web3.Transaction()
    .add(secp_instr)
    .add(sbx_instr);

    let listener = null
    let [event, slot] = await new Promise((resolve, _reject) => {
      listener = program.addEventListener("Initialized", (event, slot) => {
        resolve([event, slot]);
      });
      
      program.provider.send(trans)
    });
    await program.removeEventListener(listener);
    console.log(event, slot);
  })

});
