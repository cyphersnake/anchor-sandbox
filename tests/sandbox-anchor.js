const anchor = require('@project-serum/anchor');

describe('sandbox-anchor', () => {

  // Configure the client to use the local cluster.
  anchor.setProvider(anchor.Provider.env());

  const provider = anchor.Provider.local();
  const program = anchor.workspace.SandboxAnchor;

  it('Is initialized!', async () => {
      // TODO Create a test that verifies that the instructions passed contain exactly what they should
  });
});
