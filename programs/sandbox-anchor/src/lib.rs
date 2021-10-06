use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[event]
struct Initialized {
    authority: Pubkey,
    signatures: Vec<[u8; 65]>,
}

#[program]
pub mod sandbox_anchor {
    use super::*;
    pub fn init(ctx: Context<Initialize>, signatures: Vec<[u8; 65]>) -> ProgramResult {
        emit!(Initialized {
            authority: ctx.accounts.authority.key(),
            signatures
        });
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(signer)]
    authority: AccountInfo<'info>,
}
