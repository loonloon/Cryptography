# Cryptography

<b>Types of Cryptography</b>
1. Private key Encryption (Symmetric Encryption) <br />
https://en.wikipedia.org/wiki/Symmetric-key_algorithm
2. Public-key Encryption (Asymmetric Encryption)  <br />
https://en.wikipedia.org/wiki/Public-key_cryptography

<b>Intel Software Guard Extensions (Intel SGX) </b><br />
https://software.intel.com/sgx/code-samples

<b>On-Chain vs Off-Chain transactions</b>
1. On-Chain: transactions reflected on the public ledger, visible to all participants on the blockchain network.
2. Off-Chain: transactions that aren't processed on the main chain (usually achieved through state channels).

<b>Advantages to Off-Chain transactions:</b>
* Cheaper - they are usually free as there is no participant required to validate the transaction.
* Faster - transactions are recorded immediately without having to wait for network confirmations.
* More privacy - transfers are not visible on the public blockchain.

<b>Methods of Off-Chain transactions:</b>
* Payment chains - peer-to-peer transactions using <a href="https://goo.gl/oF7AYy">multi signature technology</a> such as <a href="https://goo.gl/PtfSyv">Bitcoin’s Lightning Network</a>.
* Sidechains - use two-way pegging systems to move coins between the main chain and the sidechain.
* Credit-based solutions - record debits and credits between two trusted parties such as Ripple.
* Trusted 3rd parties - record and guarantee the transaction, such as Blockbasis.

<b>Side-Chain</b><br />
A side-chain is a secondary blockchain layer designed to facilitate lower-cost and/or higher-speed transactions between two or more parties. 

One case in which they're often deployed is between parties who make many transactions amongst each other. Committing all of those transactions to the public blockchain would may undesirable for cost or other reasons, so the side-chain's job in this example would be to aggregate the activity into the least transactional activity necessary to reflect the final state of the side-chain's ledger.

For example, Banks A and B often settle thousands of transactions per day. It would be extremely expensive for all of those transactions to be committed to the main blockchain, so A and B set up a side-chain. At the end of each day, at most one transaction is committed to the main blockchain (the only possible outcomes are A and B's balances remain the same, or one of their balances decreases and the other's increases).

<b>State Channels</b> <br />
A State Channel is in essence a two-way discussion channel between users, or between a user and a service (a machine).

<b>InterPlanetary File System (IPFS)</b>
