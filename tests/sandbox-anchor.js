const anchor = require('@project-serum/anchor');

describe('sandbox-anchor', () => {

  // Configure the client to use the local cluster.
  anchor.setProvider(anchor.Provider.env());

  const provider = anchor.Provider.local();

  it('Is initialized!', async () => {
    const program = anchor.workspace.SandboxAnchor;
    const tx = await program.rpc.init(Array.from([Buffer.from([1, 2, 1]), Buffer.from([1, 2, 2]), Buffer.from([1, 2, 3])]), { 
        accounts: {
            authority: provider.wallet.publicKey
        },
        signers: [ provider.wallet.payer ]
    });
    console.log("Your transaction signature", tx);
  });
});
