const anchor = require('@project-serum/anchor');
const secp256k1 = require('secp256k1');
const {keccak_256 } = require('js-sha3');
const { snakeCase } = require('snake-case');
const { sha256 } = require("js-sha256");

const {struct, u8, u16, u32, blob} = require("@solana/buffer-layout");
const {Buffer} = require('buffer');

function hexdump(buffer, blockSize) {
	
	if(typeof buffer === 'string'){
		//do nothing
	}else if(buffer instanceof ArrayBuffer && buffer.byteLength !== undefined){
		buffer = String.fromCharCode.apply(String, [].slice.call(new Uint8Array(buffer)));
	}else if(Array.isArray(buffer)){
		buffer = String.fromCharCode.apply(String, buffer);
	}else if (buffer.constructor === Uint8Array) {
		buffer = String.fromCharCode.apply(String, [].slice.call(buffer));
	}else{
		console.log("Error: buffer is unknown...");
		return false;
	}
	
    
	blockSize = blockSize || 16;
    var lines = [];
    var hex = "0123456789ABCDEF";
    for (var b = 0; b < buffer.length; b += blockSize) {
        var block = buffer.slice(b, Math.min(b + blockSize, buffer.length));
        var addr = ("0000" + b.toString(16)).slice(-4);
        var codes = block.split('').map(function (ch) {
            var code = ch.charCodeAt(0);
            return " " + hex[(0xF0 & code) >> 4] + hex[0x0F & code];
        }).join("");
        codes += "   ".repeat(blockSize - block.length);
        var chars = block.replace(/[\x00-\x1F\x20]/g, '.');
        chars +=  " ".repeat(blockSize - block.length);
        lines.push(addr + " " + codes + "  " + chars);
    }
    return lines.join("\n");
}

function MsgsToInstructionData(messages) {
  // TODO: fix multiple messages broken offset
  
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
    blob(PUBKEY_SIZE, 'pubkey'),
    blob(64, 'signature'),
    u8('recid'),
  ]);

  let BUFFER_SIZE = 1 + // messages count
  secpStruct.span * messages.length + // headers * messages count
  sigStruct.span * messages.length + // signatures * messages count
  messages.reduce((total, msg) => total + msg.msg.length, 0) // messages total length

  console.log(`Allocating buffer of size: ${BUFFER_SIZE}`)

  let DATA_OFFSET = secpStruct.span * messages.length + START_OFFSET;
  console.log(`Data offset: ${START_OFFSET}`);

  let instruction = Buffer.alloc(BUFFER_SIZE)
  instruction[0] = messages.length

  let result = {offset: DATA_OFFSET, buffer: instruction}

  messages.reduce((acc, message, index) => {

    // fill header
    secpStruct.encode({
      secp_signature_offset: acc.offset + PUBKEY_SIZE,
      secp_instruction_index: index,
      secp_pubkey_offset: acc.offset,
      secp_pubkey_instruction_index: index,
      secp_message_data_offset: acc.offset + sigStruct.span,
      secp_message_data_size: message.msg.length,
      secp_message_instruction_index: index,
    }, acc.buffer, secpStruct.span*index+START_OFFSET);

    console.log(`[Filled header #${index}] Current offset: ${acc.offset}`)

    // fill signature
    sigStruct.encode({
      signature: message.sig,
      recid: message.recid,
      pubkey: message.ethPubkey
    }, acc.buffer, acc.offset);
    acc.offset += sigStruct.span;

    console.log(`[Filled signature #${index}, recid: ${message.recid}] Current offset: ${acc.offset}`)

    // fill message
    blob(message.msg.length).encode(message.msg, acc.buffer, acc.offset);
    acc.offset += message.msg.length;

    console.log(`[Filled message ${index}] Current offset: ${acc.offset}`)

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

function CreateMsgWithMulipleSigs(message, signers) {
  return MsgsToInstructionData(
    Array.from(signers, signer => CreateSignedMsg(message, signer))
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

    let name = snakeCase('init');
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
  console.log(`--------\nsignature: \n${hexdump(signature)}\n\neth pubkey: ${ethPubkey}\nrecid: ${recoveryId}--------`);

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
  anchor.setProvider(anchor.Provider.env());

  const provider = anchor.Provider.local();
  const program = anchor.workspace.SandboxAnchor;

  it('Is initialized!', async () => {
      // TODO Create a test that verifies that the instructions passed contain exactly what they should
    
    /*
      let result = await program.rpc.init(Buffer.from("test"), {
      accounts: {
        instruction: TOKEN_PROGRAM_ID,
      }
    });
    */


    let signers = [CreateSigner()];
    let message = "test6789679869876896";
    let signed = CreateMsgWithMulipleSigs(message, signers);
    let secp_instr = new anchor.web3.TransactionInstruction({
      data: signed, 
      programId: anchor.web3.Secp256k1Program.programId,
      keys: []
    });

    let sbx_instr = new anchor.web3.TransactionInstruction({
      data: sbxInstrData(Buffer.from(message)),
      programId: new anchor.web3.PublicKey("wSbxEEzm4nf96TjftqNYbxEzGvszuPM1qdrmU42S8QF"),
      keys: []
    });

    let def_trans = defaultSecp256(message, signers[0]);

    let trans = new anchor.web3.Transaction()
    .add(def_trans.instructions[0])
    .add(sbx_instr);

    console.log(hexdump(trans.instructions[0].data.toString()));
    console.log(hexdump(def_trans.instructions[0].data.toString()))

    console.log(trans)

    await anchor.web3.sendAndConfirmTransaction(provider.connection, trans, [provider.wallet.publicKey]);

    });
});
