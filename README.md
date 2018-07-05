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

The basic components of a state channel are very simple: (https://www.jeffcoleman.ca/state-channels/)
* Part of the blockchain state is locked via multisignature or some sort of smart contract, so that a specific set of participants must completely agree with each other to update it.
* Participants update the state amongst themselves by constructing and signing transactions that could be submitted to the blockchain, but instead are merely held onto for now. Each new update "trumps" previous updates.
* Finally, participants submit the state back to the blockchain, which closes the state channel and unlocks the state again (usually in a different configuration than it started with).

![statechannel](https://user-images.githubusercontent.com/5309726/42352030-ac42c046-80ea-11e8-80ce-c03bda55a704.png)

Example:<br />
<p>In order for state channels to work, participants have to be assured that they <em>could</em> publish the current state of the channel to the blockchain at any time.  This results in some important limitations, such as the fact that <strong>someone has to stay online</strong> to protect each individual party's interests until the channel is closed.</p>

<p>Imagine that when we initiated a payment channel I started with 100 bitcoins and you started with 10.  If we first sign an update that transfers 10 of those bitcoins to me, and then <em>later</em> sign an update that transfers 50 back to you, the later update is obviously more beneficial to you than the earlier one is.  If you were to <a href="http://www.slashgear.com/three-arrested-for-trying-to-cut-undersea-internet-cable-27275579/">unexpectedly lose internet access</a>, and I were to pretend the second update never happened, I might be able to publish the first update to the blockchain and effectively <em>steal 50 bitcoins from you</em>!  What you need is somebody to stay online with a copy of that later transaction so that they can "trump" the earlier one and make sure your bitcoins are protected.  <strong>It doesn't have to be you</strong>--you could send a copy to many random servers who agree via smart contract to publish it only if needed (for a small fee of course).  But however you do it, you need to be assured that the latest signed update to the state is available to trump all others.  Which leads us to our next subtle phrase:</p>

<blockquote>
  <p>Each new update "trumps" previous updates</p>
</blockquote>

<p>To make this part of the state channel work, <strong>the locking and unlocking mechanisms have to be properly designed</strong> so that old state updates submitted to the blockchain have a chance to be corrected by the newer state updates which replaced them.  <strong>The simplest way is to have any unlocking attempt start a timer</strong>, during which any <em>newer</em> update can replace the old update (restarting the timer as well).  When the timer completes, the channel is closed and the state adjusted to reflect the last update received.  The length of the timer would be chosen for each state channel, balancing the inconvenience of a long channel closing time with the increased safety it would provide against internet connection or <a href="https://bitcoin.org/en/alert/2015-07-04-spv-mining#list-of-forks">blockchain problems</a>.  Alternatively, you could structure the channel with a financial penalty so that anyone publishing an inaccurate update to the blockchain will lose more than they could gain by pretending later transactions didn't happen.</p>

<p>But the mechanism ends up not mattering very much, because (going back to the previous point) the game theory of this situation puts a twist on things.  <strong>As long as this mechanism is theoretically sound, it will probably never have to be used</strong>.  Actually going through the timer/penalty process may introduce extra fees, delays, or other inconveniences; given that <em>forcing</em> someone into the mechanism can't give you any advantage anyways, <strong>parties to a state channel will probably just close the channel out by mutually agreeing</strong> on a final channel state.  This final close-out operation needs to be fundamentally different from the normal "intermediate" updates (since it will bypass the "trumping" mechanism above), so <strong>participants will only sign a final close-out transaction once for each portion of the state locked within a particular channel</strong>.</p>

<p>The details of these "subtleties" aren't especially important.  What it all ultimately breaks down to is that <strong>participants open the channel by setting up a "judge"</strong> smart contract, <strong>sign promises to each other</strong> which the judge can enforce and adjudicate if necessary, and then <strong>close the channel by agreeing</strong> amongst themselves so that the judge's adjudication isn't needed.  As long as the "judge" mechanism can be assumed to be reliable, these promises can be counted as instant transfers, with the judge only appealed to in exceptional circumstances, such as when one party disappears.</p>

<b>InterPlanetary File System (IPFS)</b>
