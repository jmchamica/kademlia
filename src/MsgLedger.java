package fcup;

import auction.Auction;
import auction.Bid;
import blockchain.Block;
import blockchain.Chain;
import blockchain.Wallet;
import blockchain.WalletController;
import blockchain.errors.InsufficientFundsException;
import blockchain.errors.InsufficientTransactionsException;
import blockchain.errors.NullHashException;
import blockchain.transactions.Transaction;
import blockchain.transactions.errors.InsufficientTransactionValueException;
import crypto.errors.UnsupportedHashException;
import fcup.server.Functionalities;
import fcup.utils.BucketRoutingTree;
import settings.Settings;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

public class MsgLedger {

    public static void main(String[] args) {

        // Setting up environment options...
        Address bootstrap_address = new Address(Settings.getSetting("kademlia_bootstrap"));
        Address my_address = new Address(System.getenv("SSD_ADDRESS"));

        KademliaNode.logLevel = Settings.getInt("kademlia_log_level");
        KademliaNode.puzzleDifficulty = Settings.getInt("kademlia_difficulty");
        BucketRoutingTree.k = Settings.getInt("kademlia_k");
        BucketRoutingTree.alpha = Settings.getInt("kademlia_alpha");

        // Kademlia usage
        try (KademliaNode node = new KademliaNode(
                my_address.ip,
                my_address.port,
                bootstrap_address.ip,
                bootstrap_address.port)) {

            if (!node.isBootstrap) {
                try {
                    Wallet w = new Wallet();
                    Functionalities.run(node, w);
//                    test(node);

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

//            node.listBlocks().forEach(b -> System.out.println("FOUND BLOCK : " + b.toString()));
//            System.out.println();
//            node.listBids().forEach(b -> System.out.println("FOUND BID : " + b.toString()));
//            System.out.println();
//            node.listAuctions().forEach(b -> System.out.println("FOUND AUCTION : " + b.toString()));
//            System.out.println();
//            node.listTransactions().forEach(b -> System.out.println("FOUND TRANSACTION : " + b.toString()));

            // will reach the end of the try-catch block and wait for SIGTERM
            // until then, it will still listen to requests of other nodes...
            //
            // call node.shutdown() to manually close node inside this try block
            // or Ctrl+C
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void test(KademliaNode node) throws UnsupportedHashException, InsufficientFundsException, IOException, NullHashException, InsufficientTransactionValueException, InsufficientTransactionsException {
        // System wallet
        Wallet miner = new Wallet();
        Wallet baseWallet = new Wallet();
        WalletController.setBaseWallet(baseWallet);
        baseWallet.addFunds(500); // Genesis Transaction
        System.out.println("Created Base Wallet!");
        System.out.println("Base wallet balance: " + baseWallet.getBalance());

        // Test wallets
        Wallet wallet1 = new Wallet();
        System.out.println("Created Wallet 1!");
        System.out.println("Wallet 1 balance: " + wallet1.getBalance());

        Wallet wallet2 = new Wallet();
        System.out.println("Created Wallet 2!");
        System.out.println("Wallet 2 balance: " + wallet2.getBalance());

        Wallet wallet3 = new Wallet();
        System.out.println("Created Wallet 3!");
        System.out.println("Wallet 3 balance: " + wallet3.getBalance());

        // Genesis block
        byte[] genesisData = "Genesis Data".getBytes(StandardCharsets.UTF_8);
        Block genesis = new Block(Chain.getLastBlockHash(), genesisData);
        System.out.println("Genesis block created");
        Transaction t0 = baseWallet.send(50, wallet1.getPublicKey());
        genesis.addTransaction(t0);
        Block mined = Chain.mineBlock(genesis, miner);
        boolean added = Chain.addBlock(mined);
        System.out.println("Block mined added: " + added);
        System.out.println("Added transaction to genesis! Base send 50 to W1.");
        System.out.println("Base wallet balance: " + baseWallet.getBalance());
        System.out.println("Wallet 1 balance: " + wallet1.getBalance());
        System.out.println("Genesis block id: " + genesis.getStringHash());
        System.out.println("Miner wallet balance: " + miner.getBalance());
        System.out.println("Chain size: " + Chain.getLength());
        boolean isChainValid = Chain.validate();
        System.out.println("Chain is valid: " + isChainValid);

        // Transaction test
        byte[] block1Data = "Block1 Data".getBytes(StandardCharsets.UTF_8);
        Block block1 = new Block(Chain.getLastBlockHash(), block1Data);

        System.out.println("BLOCK 1 LOCAL COPY PRINT");
        block1.print();
        System.out.println();

        // Index to the hash table
        BucketRoutingTree.Id b1Id = BucketRoutingTree.Id.randomId();
        BucketRoutingTree.Id t1Id = BucketRoutingTree.Id.randomId();
        BucketRoutingTree.Id bidId = BucketRoutingTree.Id.randomId();
        BucketRoutingTree.Id tId = BucketRoutingTree.Id.randomId();

        node.store(b1Id, block1);
        System.out.println("BLOCK 1 REMOTE PRINT");
        node.findValue(b1Id).print();
        System.out.println();

        System.out.println("Created block 1!");
        Transaction t1 = wallet1.send(10, wallet2.getPublicKey());

        System.out.println("TRANSACTION 1 LOCAL");
        t1.print();
        System.out.println();
        node.storeTransaction(t1Id, t1);

        System.out.println("TRANSACTION 1 REMOTE");
        node.findTransactionValue(t1Id).print();
        System.out.println();

        ArrayList<Bid> l = new ArrayList<Bid>();
        Auction a = new Auction("demoItem", "some demo item", 100, wallet1.getPublicKey(),
                0, wallet1.sign(t1), l, false, null, 0, 10000, false);

        // testing bid sending
        System.out.println("BID 1 LOCAL");
        Bid bid = new Bid(
                t0,
                a.getId(),
                wallet2.getPublicKey(),
                0,
                wallet1.sign(t0)
        );
        bid.print();
        node.storeBid(bidId, bid);

        System.out.println("BID 1 REMOTE");
        node.findBidValue(bidId);

        System.out.println("BID 1 MODIFY");
        bid = new Bid(
                t1,
                a.getId(),
                wallet2.getPublicKey(),
                0,
                wallet1.sign(t1)
        );
        bid.print();
        node.storeBid(bidId, bid);
        System.out.println("BID 1 REMOTE");
        node.findBidValue(bidId);

        System.out.println();
        System.out.println("IDDDD");
        System.out.println(bidId.toString());
        System.out.println();

        System.out.println("ID REVERT");
        System.out.println(BucketRoutingTree.Id.fromString(bidId.toString()));
        assert BucketRoutingTree.Id.fromString(bidId.toString()).equals(bidId);

        l.add(bid);
        BucketRoutingTree.Id aId = new BucketRoutingTree.Id(a.getItem().getHash());

        System.out.println("AUCTION LOCAL");
        a.print();
        node.storeAuction(aId, a);
        System.out.println("AUCTION REMOTE");
        node.findAuctionValue(aId).print();

        block1.addTransaction(t1);
        Block mined2 = Chain.mineBlock(block1, miner);

        System.out.println("BLOCK 1 MINED LOCAL COPY PRINT");
        mined2.print();
        System.out.println();

        node.store(b1Id, mined2);
        System.out.println("BLOCK 1 MINED REMOTE PRINT");
        node.findValue(b1Id).print();
        System.out.println();

        added = Chain.addBlock(mined2);
        System.out.println("Block mined added: " + added);
        System.out.println("Added transaction to block 1! W1 send 10 to W2");
        System.out.println("Wallet 1 balance: " + wallet1.getBalance());
        System.out.println("Wallet 2 balance: " + wallet2.getBalance());
        System.out.println("Miner wallet balance: " + miner.getBalance());
        System.out.println("Block 1 id: " + block1.getStringHash());
        System.out.println("Chain size: " + Chain.getLength());
        isChainValid = Chain.validate();
        System.out.println("Chain is valid: " + isChainValid);

        // Transaction test
        byte[] block2Data = "Block1 Data".getBytes(StandardCharsets.UTF_8);
        Block block2 = new Block(Chain.getLastBlockHash(), block2Data);
        System.out.println("Created block 1!");
        Transaction t2 = wallet1.send(20, wallet3.getPublicKey());
        block2.addTransaction(t2);
        System.out.println("Added transaction to block 2! W1 send 20 to W3.");
        Transaction t3 = wallet2.send(5, wallet3.getPublicKey());
        block2.addTransaction(t3);
        Block mined3 = Chain.mineBlock(block2, miner);
        added = Chain.addBlock(mined3);
        System.out.println("Block mined added: " + added);
        System.out.println("Added transaction to block 2! W2 send 5 to W3");
        System.out.println("Wallet 1 balance: " + wallet1.getBalance());
        System.out.println("Wallet 2 balance: " + wallet2.getBalance());
        System.out.println("Wallet 3 balance: " + wallet3.getBalance());
        System.out.println("Miner wallet balance: " + miner.getBalance());
        System.out.println("Block 2 id: " + block1.getStringHash());
        System.out.println("Chain size: " + Chain.getLength());
        isChainValid = Chain.validate();
        System.out.println("Chain is valid: " + isChainValid);
    }

    private static class Address {
        private final String ip;
        private final short port;

        Address(String add) {
            if (add == null || add.isEmpty()) {
                System.err.println("Address not provided.");
                System.exit(1);
            }

            String[] address = add.split(":");
            if (address.length < 2) {
                System.err.println("Address not provided.");
                System.exit(1);
            }
            String ip = address[0];
            short port = Short.parseShort(address[1]);
            this.ip = ip;
            this.port = port;
        }

        @Override
        public String toString() {
            return ip + ":" + port;
        }
    }
}

