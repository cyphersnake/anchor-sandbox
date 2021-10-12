# Test Task

Solana has a separate instruction type that repeats the `ecrecover` function from Ethereum. 
This repository Solana program contains one function (`init`) that verifies that the previous instruction of transaction contains exactly this verification and verifies that the signed message and the argument passed to it are equivalent. If successful, then the program issues an event, with all the public addresses of the signers. 

The minimum task is to achieve a working test with one signature. 
The more advanced part of the challenge is to have multiple signers

Contact [me](https://t.me/sadsnake) for any questions

The program is not guaranteed to work correctly! The situation simulates a typical work task as much as possible
