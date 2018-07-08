#### The Design Goals of Plasma ####
 
In order to implement plasma effectively, Joseph Poon and Vitalik Buterin had certain design goals. Let’s go through those goals and the significance of each.

#### 1. One Blockchain to rule them all ####
As stated earlier, the main blockchain will be the root blockchain and every other child chain will be derived directly or indirectly from it. The root chain will not interfere with any of the child chains except on the event of disputes.

#### 2. Minimization of Trust ####
The system needs to be as trustless as possible. None of the child chains can be completely dependent on the ethics of certain actors. There should be mechanisms for someone to exit from the child chains.

#### 3. Ledger Scalability ####
The blockchains should be able to hold a lot of data. The child chains should be able to take up the data that would normally go on the root chain.

#### 4. Should be Scalable ####
The child chain should be compatible with various scaling solutions. Basically, they should be capable of implementing solutions like sharding and lightning network as well.

#### 5. Localized Computations ####
Each child chain must be capable of doing their own calculations. On regular intervals, each chain should give their state updates to the parent chain.

#### 6. Fraud Proofs ####
On the event of a dispute, the bereaved party can send a proof of fraud to the root chain The root chain can then roll back the state of the child chain and penalize the signers of the block of the child chain. This is extremely important and will be explored later in detail.

#### 7. Every Chain is Unique ####
Every child chain can have its own governance rules. They can be their own unique entity as long as they are constantly reporting back to the main chain.

#### MapReduce Constructions ####
Plasma’s functionality depends on MapReduce. According to Wikipedia, MapReduce is a programming model and an associated implementation for processing and generating big data sets with a parallel, distributed algorithm on a cluster. What that basically means is, if you have a huge amount of data, you can simply delegate parts of it to smaller entities, who compute them in parallel and then return the result to you.

#### MapReduce is made of two parts: ####
1. Map: In this part, the data is divided and handed over to different entities to be solved in parallel.
2. Reduce: The entities solve the problem and execute a "summary" function which considerably lowers the data size and returns the summarized value.

TBC
https://blockgeeks.com/guides/what-is-omisego-the-plasma-protocol/
