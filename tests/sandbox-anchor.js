const anchor = require('@project-serum/anchor');
const secp256k1 = require('secp256k1');
const {
  keccak_256
} = require('js-sha3');
const {
  snakeCase
} = require('snake-case');
const {
  sha256
} = require("js-sha256");

const {
  struct,
  u8,
  u16,
  u32,
  blob
} = require("@solana/buffer-layout");
const {
  Buffer
} = require('buffer');

/*
@typedef {Object} SignedMessage
@property {string} msg
@property {Buffer} sig
@property {number} recid
@property {Buffer} ethPubkey
*/

/*
@typedef {Object} Keypair
@property {Uint8[]} publicKey
@property {Uint8[]} privateKey
*/

/*
Packs messages into secp256k1 instruction data
@param {SignedMessage[]} messages - list of signed messages that will be packed into instruction
@param {number} instructionIndex - index of the instruction within Transaction
@return {Buffer} packed instruction data
*/
function packMsgsToInstructionData(messages, instructionIndex) {

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

  let BUFFER_SIZE = START_OFFSET +
    secpStruct.span * messages.length +
    sigStruct.span * messages.length +
    messages.reduce((total, msg) => total + msg.msg.length, 0)

  let DATA_OFFSET = secpStruct.span * messages.length + START_OFFSET;
  let instruction = Buffer.alloc(BUFFER_SIZE)
  instruction[0] = messages.length

  let result = {
    offset: DATA_OFFSET,
    buffer: instruction
  }

  messages.reduce((acc, message, index) => {

    secpStruct.encode({
      secp_signature_offset: acc.offset,
      secp_instruction_index: instructionIndex,
      secp_pubkey_offset: acc.offset + 65,
      secp_pubkey_instruction_index: instructionIndex,
      secp_message_data_offset: acc.offset + sigStruct.span,
      secp_message_data_size: message.msg.length,
      secp_message_instruction_index: instructionIndex,
    }, acc.buffer, secpStruct.span * index + START_OFFSET);

    sigStruct.encode({
      signature: message.sig,
      recid: message.recid,
      pubkey: message.ethPubkey
    }, acc.buffer, acc.offset);
    acc.offset += sigStruct.span;

    blob(message.msg.length).encode(message.msg, acc.buffer, acc.offset);
    acc.offset += message.msg.length;

    return acc;
  }, result);

  return result.buffer
}

/*
Signs message with signers private key using secp256k1 algorithm
@param {string} message - message to sign
@param {Keypair} signer - signer who signs the message
@return {SignedMessage} signed message
*/
function createSignedMsg(message, signer) {
  let plaintext = Buffer.from(message);
  let plaintextHash = Buffer.from(keccak_256.update(plaintext).digest());
  let {
    signature,
    recid: recoveryId
  } = secp256k1.ecdsaSign(
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

/*
Signs message and packs it into instruction data
@param {string} message - message to sign
@param {Keypair[]} signers - list of signers
@param {number} instructionIndex - instruction index within Transaction
@return {Buffer} instruction data
*/
function createMsgWithMulipleSigs(message, signers, instructionIndex) {
  return packMsgsToInstructionData(
    Array.from(signers, signer => createSignedMsg(message, signer), instructionIndex)
  )
}

/*
Creates valid Keypair for secp256k1 usage 
@return {Keypair}
*/
function createSigner() {
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

/*
Prepares data for sandbox instruction
@param {string} message - message to pass to the on-chain programs method
@return {Buffer}
*/
function packSbxInstructionData(message) {

  let name = snakeCase('initialize');
  let method = Buffer.from(sha256.digest(`global:${name}`)).slice(0, 8)

  methStruct = struct([
    blob(8, 'meth_hash'),
    u32('size'),
    blob(message.length, 'message')
  ])

  let buffer = Buffer.alloc(12 + message.length)
  methStruct.encode({
    meth_hash: method,
    size: message.length,
    message: message
  }, buffer);

  return buffer
}

/*
Creates Transaction using Solana's default Secp256k1Program
@param {string} message - message to sign
@param {Keypair} signer - signer
@return {Transaction}
*/
function prepareDefaultSecp256(message, signer) {
  let plaintext = Buffer.from(message);
  let plaintextHash = Buffer.from(keccak_256.update(plaintext).digest());
  let {
    signature,
    recid: recoveryId
  } = secp256k1.ecdsaSign(
    plaintextHash,
    signer.privateKey
  );

  let ethPubkey = anchor.web3.Secp256k1Program.publicKeyToEthAddress(signer.publicKey).toString('hex');

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

  const provider = anchor.Provider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.SandboxAnchor;

  let programPK = new anchor.web3.PublicKey("9DxrDu7MwthUNerqq3VYKksSWugck2sa8y27q4y6nrAj");

  it('Checks if default secp256k1 works fine', async () => {
    let signer = createSigner();
    let message = "test_default";

    let sbxInstr = new anchor.web3.TransactionInstruction({
      data: packSbxInstructionData(Buffer.from(message)),
      programId: programPK,
      keys: [{
        isSigner: 0,
        isWritable: 0,
        pubkey: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY
      }, ],
    });

    let trans = prepareDefaultSecp256(message, signer)
      .add(sbxInstr);

    // TODO: fix event listener
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
    let signers = [createSigner()];
    let message = "test_custom_single";
    let signed = createMsgWithMulipleSigs(message, signers, 0);

    let secpInstr = new anchor.web3.TransactionInstruction({
      data: signed,
      programId: anchor.web3.Secp256k1Program.programId,
      keys: []
    });

    let sbxInstr = new anchor.web3.TransactionInstruction({
      data: packSbxInstructionData(Buffer.from(message)),
      programId: programPK,
      keys: [{
        isSigner: 0,
        isWritable: 0,
        pubkey: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY
      }, ],
    });

    let trans = new anchor.web3.Transaction()
      .add(secpInstr)
      .add(sbxInstr);

    // TODO: fix event listener
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
    let signers = [createSigner(), createSigner()];
    let message = "test_custom_multiple";
    let signed = createMsgWithMulipleSigs(message, signers, 0);

    let secpInstr = new anchor.web3.TransactionInstruction({
      data: signed,
      programId: anchor.web3.Secp256k1Program.programId,
      keys: []
    });

    let sbxInstr = new anchor.web3.TransactionInstruction({
      data: packSbxInstructionData(Buffer.from(message)),
      programId: programPK,
      keys: [{
        isSigner: 0,
        isWritable: 0,
        pubkey: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY
      }, ],
    });

    let trans = new anchor.web3.Transaction()
      .add(secpInstr)
      .add(sbxInstr);

    // TODO: fix event listener
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