use std::convert::TryInto;

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::Instruction;
use anchor_lang::solana_program::secp256k1_program::ID as Secp256k1_ID;
use anchor_lang::solana_program::sysvar::{instructions, instructions::ID as InstructionId};

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[event]
struct Initialized {
    addresses: Vec<[u8; 20]>,
}

#[program]
pub mod sandbox_anchor_ {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, msg: Vec<u8>) -> ProgramResult {
        msg!("SANDBOX");
        emit!(Initialized {
            addresses: ctx
                .accounts
                .get_eth_addresses_from_verification_instruction(msg.as_slice())?
        });
        Ok(())
    }
}

#[account]
struct Counter {
    index: u64,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(address = InstructionId)]
    instruction: AccountInfo<'info>,
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct SecpSignatureOffsets {
    pub signature_offset: u16, // offset to [signature,recovery_id] of 64+1 bytes
    pub signature_instruction_index: u8,
    pub eth_address_offset: u16, // offset to eth_address of 20 bytes
    pub eth_address_instruction_index: u8,
    pub message_data_offset: u16, // offset to start of message data
    pub message_data_size: u16,   // size of message data
    pub message_instruction_index: u8,
}

use std::ops::Range;
impl SecpSignatureOffsets {
    pub const ETH_ADDRESS_SIZE: usize = 20;
    pub const SIGNATURE_ADDRESS_SIZE: usize = 64;

    fn check_index(self, index: usize) -> Option<Self> {
        let index = index as u8;
        if index.eq(&self.signature_instruction_index)
            && index.eq(&self.eth_address_instruction_index)
            && index.eq(&self.message_instruction_index)
        {
            Some(self)
        } else {
            None
        }
    }

    fn get_signature_range(&self) -> Range<usize> {
        (self.signature_offset as usize)
            ..((self.signature_offset as usize).saturating_add(Self::SIGNATURE_ADDRESS_SIZE))
    }
    fn get_eth_address_range(&self) -> Range<usize> {
        (self.eth_address_offset as usize)
            ..(self.eth_address_offset as usize).saturating_add(Self::ETH_ADDRESS_SIZE)
    }
    fn get_message_range(&self) -> Range<usize> {
        (self.message_data_offset as usize)
            ..(self.message_data_offset as usize + self.message_data_size as usize)
    }
}

struct SignatureContext {
    address: [u8; SecpSignatureOffsets::ETH_ADDRESS_SIZE],
    msg: Vec<u8>,
    _signature: [u8; SecpSignatureOffsets::SIGNATURE_ADDRESS_SIZE],
}

impl SignatureContext {
    fn get_address(self, msg: &[u8]) -> Option<[u8; SecpSignatureOffsets::ETH_ADDRESS_SIZE]> {
        if self.msg.eq(&msg) {
            Some(self.address)
        } else {
            None
        }
    }
}

struct EcrecoverInstruction {
    signatures: Vec<SignatureContext>,
}

use std::io;
impl AnchorDeserialize for EcrecoverInstruction {
    fn deserialize(buf: &mut &[u8]) -> io::Result<Self> {
        let count = buf[0] as usize;
        let offsets: Vec<SecpSignatureOffsets> = {
            let buf: &[u8] = &buf[1..count * std::mem::size_of::<SecpSignatureOffsets>()];
            (0..count)
                .map(|n| {
                    Ok(bincode::deserialize::<SecpSignatureOffsets>(buf)
                        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?
                        .check_index(n)
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "Invalid index in offsets")
                        })?)
                })
                .take(count)
                .collect::<io::Result<Vec<_>>>()
        }?;
        Ok(EcrecoverInstruction {
            signatures: offsets
                .into_iter()
                .map(|offset| SignatureContext {
                    address: buf[offset.get_eth_address_range()].try_into().unwrap(),
                    _signature: buf[offset.get_signature_range()].try_into().unwrap(),
                    msg: buf[offset.get_message_range()].to_vec(),
                })
                .collect::<Vec<_>>(),
        })
    }
}

impl<'info> Initialize<'info> {
    fn get_previous_instruction(&self) -> Result<Instruction> {
        let instructions = self.instruction.try_borrow_mut_data()?;
        instructions::load_instruction_at(
            instructions::load_current_index(&instructions)
                .checked_sub(1)
                .ok_or(Errors::NoSignatureVerificationInstruction)? as usize,
            &instructions,
        )
        .map_err(|_| Errors::FailedToLoadSignatureVerificationInstruction.into())
    }

    fn get_signature_verificaion_instruction(&self) -> Result<Instruction> {
        match self.get_previous_instruction() {
            Ok(ix) if ix.program_id.eq(&Secp256k1_ID) => Ok(ix),
            Ok(_) => Err(Errors::SignatureVerificationInstructionWrongProgramId.into()),
            Err(err) => Err(err),
        }
    }

    pub fn get_eth_addresses_from_verification_instruction(
        &self,
        msg: &[u8],
    ) -> Result<Vec<[u8; 20]>> {
        Ok(EcrecoverInstruction::deserialize(
            &mut self
                .get_signature_verificaion_instruction()?
                .data
                .as_slice(),
        )
        .map_err(|err| {
            msg!("{:?}", err);
            Errors::FailedToLoadSignatureVerificationInstruction
        })?
        .signatures
        .into_iter()
        .map(|sc| {
            sc.get_address(msg)
                .ok_or(Errors::InvalidVerificationSignatureKey.into())
        })
        .collect::<Result<_>>()?)
    }
}

#[error]
pub enum Errors {
    #[msg("Deserialize error")]
    FailedToDeserialize,
    #[msg("Borrow error")]
    FailedToBorrow,
    #[msg("No signature verification instruction")]
    NoSignatureVerificationInstruction,
    #[msg("Failed to load signature verification instruction")]
    FailedToLoadSignatureVerificationInstruction,
    #[msg("Wrong signature verificaion instruction program id")]
    SignatureVerificationInstructionWrongProgramId,
    #[msg("Invalid msg in verificaion")]
    InvalidVerificationSignatureKey,
}
