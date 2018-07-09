# Cryptography

#### Types of Cryptography ####
1. Private key Encryption ([Symmetric Encryption](https://en.wikipedia.org/wiki/Symmetric-key_algorithm))
2. Public key Encryption ([Asymmetric Encryption](https://en.wikipedia.org/wiki/Public-key_cryptography)) 

#### Intel Software Guard Extensions ([Intel SGX](https://software.intel.com/sgx/code-samples))  

#### Hashing Algorithm ####
Cryptographic hashing, or more commonly referred to as "hashing" takes an input (or ***message***) and produces an output (called a ***digest***) with a fixed number of alphanumeric characters. 

For example, every time you input the word "Fox" into a hash function it produces the same digest. This process is ***deterministic*** because the output is the same every single time. Hashing is known as a ***one-way cryptographic function.*** This means that given any random digest, there is no feasible way to figure out the input. If we were only given the hashed digest of "Fox" it would be almost impossible to determine that the input was "Fox." You would have to randomly try different inputs until coming across the correct digest.

![hashing](https://user-images.githubusercontent.com/5309726/42371419-09ea2dae-8142-11e8-86c2-086b22c4ee9c.jpeg)

#### Secure Hashing Algorithm (SHA) ####
SHA-256 will take any given input of data, convert it into 256 bits (256 zeros and ones), and then output those 256 bits into the format of 64 hexadecimal characters. 

The hexadecimal system uses a combination of 16 different characters (0123456789ABCDEF). Each hexadecimal characters represents 4 bits, which means that 64 hexadecimal characters represent 256 bits. There are 8 bits per byte, which means that 256 bits is equal to 32 bytes.

Input: My name is Ben Stolman. Output in 256 Bits:
`1111110110111110110100100011000110001010101011111000111000101100111011001111100100110101100000100010101011011011101000111100010100010010110000100001100111011011101001000101010100101111111110100110101011101111111110001110010110110001110001100011101010100001`

Converted to hex format:
`FDBED2318AAF8E2CECF935822ADBA3C512C219DBA4552FFA6AEFF8E5B1C63AA1`

The output is 64 characters, but if you view it like this:
`(FD) (BE) (D2) (31) (8A) (AF) (8E) (2C) (EC) (F9) (35) (82) (2A) (DB) (A3) (C5) (12) (C2) (19) (DB) (A4) (55) (2F) (FA) (6A) (EF) (F8) (E5) (B1) (C6) (3A) (A1)`

32 separate hexadecimal numbers (or 32 bytes) each paired in parenthesis representing 8 bits in the hash.

#### Unspent Transaction Output (UTXO)and Account/Balance Model ####
Two types of record-keeping models are popular in today’s blockchain networks:
1. Unspent Transaction Output Model, is employed by Bitcoin.
2. Account/Balance Model, is employed by Ethereum.

#### UTXO Example ####
You create a brand new wallet and, in time, it receives three amounts of 0.01, 0.2 and 3 BTC as follows:
1. You send 3 BTC to an address associated with the wallet.
2. Two payments are made to another address by Alice.

![utox_01](https://user-images.githubusercontent.com/5309726/42434730-cbd6fe24-8386-11e8-8e55-9cf31fb95a63.png)

The wallet reports a balance of 3.21 BTC, yet if you were to virtually peek inside the wallet, you would see three distinct amounts still grouped together by their originating transactions: 0.01, 0.2 and 3 BTC.

![utox_02](https://user-images.githubusercontent.com/5309726/42434849-2a78140e-8387-11e8-9ef6-b0d61e81073d.png)

The received bitcoin amounts don’t mix but remain separated as the exact amounts sent to the wallet. The three amounts in the example above are called the outputs of their originating transactions. Bitcoin wallets always keep outputs separate and distinct.

So what’s this ***"unspent output"*** you are seeing? It means from the three transactions that were made, your addresses were the output addresses of the transactions and you have not used those bitcoins (or outputs) in other transactions.

After that, you send 0.15 BTC to Bob. The wallet selects a spend candidate from amongst the three existing "outputs" contained in the wallet. So, it chooses (for various reasons that are not important now) the 0.2 BTC output. The wallet will unlock the 0.2 BTC output and use the whole amount of 0.2 BTC as an ***input*** to your new 0.15 BTC transaction. The 0.2 BTC output is "spent" in the process.

![utox_03](https://user-images.githubusercontent.com/5309726/42436459-9459848e-838c-11e8-8015-f7ec35d59ebb.png)

The spend transaction your wallet creates will send 0.15 BTC to Bob’s address – where it will reside in his wallet as an output - waiting eventually to be spent.

The 0.05 BTC difference (0.2 BTC input minus 0.15 BTC output) is called ***"change"*** and the transaction will send this back to your wallet via a newly created address. The 0.05 BTC change amount will reside in your wallet as a new output – waiting eventually to be spent. So, now, a virtual peek inside your wallet reveals the following:

![utox_04](https://user-images.githubusercontent.com/5309726/42436160-a28748f8-838b-11e8-8448-2051135f9eb6.png)

Each of the three outputs that are "waiting to be spent", is locked to its receiving addresses until such time as one or more of them are selected as input(s) to a new spend transaction.

Behind the scenes, different wallet clients apply different logic rules when selecting UTXOs as inputs to new transactions.

#### On-Chain vs Off-Chain transactions ####
On-Chain      | Off-Chain
------------- | -------------
transactions reflected on the public ledger, visible to all participants on the blockchain network.  | transactions that aren't processed on the main chain (usually achieved through state channels).

#### Advantages to Off-Chain transactions: ####
* Cheaper - they are usually free as there is no participant required to validate the transaction.
* Faster - transactions are recorded immediately without having to wait for network confirmations.
* More privacy - transfers are not visible on the public blockchain.

#### Methods of Off-Chain transactions: ####
* Payment chains - peer-to-peer transactions using <a href="https://goo.gl/oF7AYy">multi signature technology</a> such as <a href="https://goo.gl/PtfSyv">Bitcoin’s Lightning Network</a>.
* Sidechains - use two-way pegging systems to move coins between the main chain and the sidechain.
* Credit-based solutions - record debits and credits between two trusted parties such as Ripple.
* Trusted 3rd parties - record and guarantee the transaction, such as Blockbasis.

#### Side-Chain ####
A side-chain is a secondary blockchain layer designed to facilitate lower-cost and/or higher-speed transactions between two or more parties. 

One case in which they're often deployed is between parties who make many transactions amongst each other. Committing all of those transactions to the public blockchain would may undesirable for cost or other reasons, so the side-chain's job in this example would be to aggregate the activity into the least transactional activity necessary to reflect the final state of the side-chain's ledger.

For example, Banks A and B often settle thousands of transactions per day. It would be extremely expensive for all of those transactions to be committed to the main blockchain, so A and B set up a side-chain. At the end of each day, at most one transaction is committed to the main blockchain (the only possible outcomes are A and B's balances remain the same, or one of their balances decreases and the other's increases).

#### State Channels ####
A State Channel is in essence a two-way discussion channel between users, or between a user and a service (a machine).

The basic components of a state channel are very simple: (https://www.jeffcoleman.ca/state-channels/)
* Part of the blockchain state is locked via multisignature or some sort of smart contract, so that a specific set of participants must completely agree with each other to update it.
* Participants update the state amongst themselves by constructing and signing transactions that could be submitted to the blockchain, but instead are merely held onto for now. Each new update "trumps" previous updates.
* Finally, participants submit the state back to the blockchain, which closes the state channel and unlocks the state again (usually in a different configuration than it started with).

![state_channel](https://user-images.githubusercontent.com/5309726/42436258-fd485cc8-838b-11e8-801d-eb7f1b61ad4d.png)

#### Example: ####
In order for state channels to work, participants have to be assured that they <em>could</em> publish the current state of the channel to the blockchain at any time.  This results in some important limitations, such as the fact that ***someone has to stay online*** to protect each individual party's interests until the channel is closed.

Imagine that when we initiated a payment channel I started with 100 bitcoins and you started with 10.  If we first sign an update that transfers 10 of those bitcoins to me, and then <em>later</em> sign an update that transfers 50 back to you, the later update is obviously more beneficial to you than the earlier one is.  If you were to <a href="http://www.slashgear.com/three-arrested-for-trying-to-cut-undersea-internet-cable-27275579/">unexpectedly lose internet access</a>, and I were to pretend the second update never happened, I might be able to publish the first update to the blockchain and effectively <em>steal 50 bitcoins from you</em>!  What you need is somebody to stay online with a copy of that later transaction so that they can "trump" the earlier one and make sure your bitcoins are protected. ***It doesn't have to be you***--you could send a copy to many random servers who agree via smart contract to publish it only if needed (for a small fee of course).  But however you do it, you need to be assured that the latest signed update to the state is available to trump all others.  Which leads us to our next subtle phrase:

>Each new update "trumps" previous updates

To make this part of the state channel work, ***the locking and unlocking mechanisms have to be properly designed*** so that old state updates submitted to the blockchain have a chance to be corrected by the newer state updates which replaced them. ***The simplest way is to have any unlocking attempt start a timer***, during which any <em>newer</em> update can replace the old update (restarting the timer as well).  When the timer completes, the channel is closed and the state adjusted to reflect the last update received.  The length of the timer would be chosen for each state channel, balancing the inconvenience of a long channel closing time with the increased safety it would provide against internet connection or <a href="https://bitcoin.org/en/alert/2015-07-04-spv-mining#list-of-forks">blockchain problems</a>.  Alternatively, you could structure the channel with a financial penalty so that anyone publishing an inaccurate update to the blockchain will lose more than they could gain by pretending later transactions didn't happen.

But the mechanism ends up not mattering very much, because (going back to the previous point) the game theory of this situation puts a twist on things. ***As long as this mechanism is theoretically sound, it will probably never have to be used***.  Actually going through the timer/penalty process may introduce extra fees, delays, or other inconveniences; given that <em>forcing</em> someone into the mechanism can't give you any advantage anyways, ***parties to a state channel will probably just close the channel out by mutually agreeing*** on a final channel state.  This final close-out operation needs to be fundamentally different from the normal "intermediate" updates (since it will bypass the "trumping" mechanism above), so ***participants will only sign a final close-out transaction once for each portion of the state locked within a particular channel***.

The details of these "subtleties" aren't especially important.  What it all ultimately breaks down to is that ***participants open the channel by setting up a "judge"*** smart contract, ***sign promises to each other*** which the judge can enforce and adjudicate if necessary, and then ***close the channel by agreeing*** amongst themselves so that the judge's adjudication isn't needed.  As long as the "judge" mechanism can be assumed to be reliable, these promises can be counted as instant transfers, with the judge only appealed to in exceptional circumstances, such as when one party disappears.

#### Plasma Chain (Blockchain inside Blockchain) ####
[Plasma](https://plasma.io/) is, in essence, blockchains built on top of blockchains. It is a series of contracts that run on top of the root chain (eg. the main ethereum blockchain).

If one were to envision the architecture and the structure, then think of the main blockchain and the plasma blockchains as a tree. The main blockchain is the root while the plasma chain aka child blockchains are the branches.

![plasma_01](https://user-images.githubusercontent.com/5309726/42416470-a40e293e-82a1-11e8-84ba-6846814f30a3.png)

The root chain is like the universal absolute ground truth, while the child chains work around it doing their own computations and periodically feeding state information to the root chain.

The root chain comes into play only when there is a dispute that needs to be settled in the child chain, otherwise, it doesn’t involve itself with anything going on in the child chain and this point is the core underlying philosophy behind it. If the root chain is going to be the ground truth, then it must remain as devoid of activity and calculations as possible.

The root chains and the child chains will form a set of “nested blockchains.” To understand how a “nested” system works, it may be useful to take the example of nested loops. The reader maybe familiar with the concept.

This is how nested loops work:
```
for (int i = 1; i < 5; i++)
{
   for (int j = 1; j < 5; j++)
   {
      //condition
   }
    //condition
}
````

Instead of using just one loop to execute the entire condition, we used another loop inside the main loop and split up the condition. The inner loop does a calculation and returns a value to the main loop. This makes computation a lot less complicated.

That is in essence how the nested blockchains operate. Another interesting way to understand this and especially to know how dispute resolution in plasma works, it may make sense to think of the court system.

Correlation with the court system. Let’s look at the court hierarchy in the UK.

![plasma_02](https://user-images.githubusercontent.com/5309726/42416511-106bb672-82a3-11e8-907e-80218bb59aee.jpg)

In this case, the Supreme Court is the root chain, it lays down the law of the land. The Supreme court has its child chains (Criminal and Civil) and each of them has their own child chains.

So, if one were to bring up a civil case to the court, they can’t directly go to the Supreme court (of course this depends on how high profile the case is).

The applicant will first deal with the county courts. If they are not happy with the decision, then they can go up in the chain one at a time before finally appealing in the supreme court.

That is pretty much how the idea of plasma and nested blockchains will work, with the root chain being the supreme court with multiple child chains under it.

#### Atomic Swap ####
Atomic swap is a smart contract technology that enables exchange of one cryptocurrency for another without using centralized intermediaries, such as exchanges. 

It can take place directly between blockchains of different cryptocurrencies or they can be conducted off-chain, away from the main blockchain. They first came into prominence in September 2017, when an atomic swap between Decred and Litecoin was conducted. 

#### Problem ####
Not all cryptocurrency exchanges support all coins. As such, a trader wishing to exchange her coin for another one that is not supported on the current exchange may need to migrate accounts or make several conversions between intermediate coins to accomplish her goal. There is also an associated counterparty risk, if the trader wishes to exchange her coins with another trader. Atomic swaps solve this problem through the use of ***Hash Timelock Contracts (HTLC)*** 

HTLC is a time-bound smart contract between parties that involves the generation of a cryptographic hash function, which can be verified between them

#### Example: ####
Molly and Steve wanted to swap currencies.  Molly has 57 LTC, but she wants to own 1 BTC to know how it feels.  Turns out, Steve has 1 BTC and he wants 57 LTC, so Molly and Steve decide to make the trade.  But neither wants to send the funds to the other first, out of fear that s/he might be cheated.  They also don’t want to go through an escrow service (another example of a trusted, third-party intermediary) to execute the trade for them.

Luckily, they can use atomic swaps for this.  With an atomic swap, Molly and Steve could conduct the transaction without having to go through a third party, like Binance or an escrow service, and without having to worry about being screwed over by the other.

Alice is a trader interested in converting 100 bitcoins to an equivalent litecoins with Bob. She submits her transaction to bitcoin’s blockchain. During this process, Alice generates a number for a cryptographic hash function to encrypt the transaction. Bob repeats the same process at his end by similarly submitting his transaction to litecoin’s blockchain.

Both Alice and Bob unlock their respective funds using their respective numbers. They have to do this within a specified timeframe or else the transfer will not take place

![atomic swap](https://user-images.githubusercontent.com/5309726/42407533-22ded7b0-81f1-11e8-8e12-be582eb70688.jpg)

#### InterPlanetary File System (IPFS) ####

#### Token Types ####
Payment       | Utility       | Asset
------------- | ------------- | -------------
Bitcoin, Ether | Pre-paid user fee | Equity tokens, deriviatives, etc.

#### Payment Tokens ####
* Means of payment, also according to AML.
  * No security.
  * No banking activity.
* Full AML, KYC, new requirement to become a member of a self regulatory organisation.

#### Utility Tokens ####
* No security, unless investment instrument.
* No means of payment, if
  * Payment is ancillary function to the utility.
  * Blockchain is not used for financial purposes.
* No AML provisions applicable for pure utility tokens.

#### Asset Tokens ####
* Security.
* Prosectus necessary.
  * No banking activity.
  * No means of payment.
* No AML provisions applicable in principle (except for shares of collective investment scheme and bearer shares)
