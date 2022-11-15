package fcup.server;

import auction.House;
import auction.Item;
import auction.PaymentManager;
import auction.errors.ExistentAuctionException;
import blockchain.*;
import blockchain.transactions.Transaction;
import com.sun.tools.javac.util.Pair;
import crypto.errors.UnsupportedHashException;
import fcup.KademliaNode;
import fcup.utils.BucketRoutingTree;
import settings.Settings;

import java.util.ArrayList;
import java.util.Scanner;

public class Functionalities {

    private static boolean miner = Settings.getBoolean("miner");

    public static void run(KademliaNode node, Wallet wallet) {
        BlockReceiver receiver = new BlockReceiver(node);
        if (!miner) {
            Functionalities.displayMenu(node, wallet);
        } else {
            System.out.println("Welcome to the mining agent!");
            Functionalities.miningAgent(node, wallet);
        }
        receiver.kill();
    }

    public static void displayMenu(KademliaNode node, Wallet wallet) {
        PaymentManager paymentManager = new PaymentManager(node);
        Scanner scanner = new Scanner(System.in);
        boolean running = true;
        System.out.println("Welcome to the Auctions system!");
        while (running) {
            System.out.print("\nWhich operation do you want to perform?\n" +
                    "\t1 - Auction a Item\n\t2 - Bid on a Auction\n\t3 - Add Funds\n\t4 - List Funds\n\t5 - Leave\n\t> ");
            try{
                int operation = scanner.nextInt();
                switch (operation) {
                    case 1:
                        Functionalities.auctionItem(node, wallet);
                        break;
                    case 2:
                        Functionalities.bidOnAuction(node, wallet);
                        break;
                    case 3:
                        Functionalities.addFunds(wallet);
                        break;
                    case 4:
                        Functionalities.listFunds(wallet);
                        break;
                    case 5:
                        System.out.println("\nLeaving!");
                        running = false;
                        break;
                    default:
                        System.out.println("\nInvalid option. Please select again!");
                        break;
                }
            }
            catch (Exception ignored) {
                ignored.printStackTrace();
                System.out.println("\nInvalid option. Exiting system!");
                running = false;
            }
        }
        paymentManager.kill();
    }

    private static void listFunds(Wallet wallet) {
        Chain.crawlBlocks();
        double funds = wallet.getBalance();
        if (Chain.getLength() > 0) {
            funds = funds /2; // big big hammer here
        }
        System.out.println("Wallet funds: " + funds);
    }

    private static void addFunds(Wallet wallet) throws UnsupportedHashException {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Please insert the funds you want to add:\n\t> ");
        double funds = scanner.nextDouble();
        wallet.addFunds(funds);
        System.out.println("Funds added!");
    }

    private static void auctionItem(KademliaNode node, Wallet wallet) throws UnsupportedHashException, ExistentAuctionException {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Please insert the Item's name:\n\t> ");
        String name = scanner.nextLine();
        System.out.print("Please insert the Item's description:\n\t> ");
        String description = scanner.nextLine();
        System.out.print("Please insert the Item's base price:\n\t> ");
        double basePrice = scanner.nextDouble();
        System.out.print("Please insert for how long is the auction valid (minutes):\n\t> ");
        int ttl = scanner.nextInt();

        Item item = new Item(name, description, basePrice, wallet.getPublicKey());
        House.addAuction(node, item, ttl);

        System.out.println("Item successfully listed!");
    }

    private static void bidOnAuction(KademliaNode node, Wallet wallet) {
        Scanner scanner = new Scanner(System.in);
        ArrayList<Pair<byte[], String>> auctions = House.listAuctions();
        int size = auctions.size();

        if (size == 0) {
            System.out.println("Currently there are no Auctions happening!");
            return;
        }

        System.out.println("Please select which item do you want to bid on:\n");
        for (int i = 0; i < size; i++) {
            String name = auctions.get(i).snd;
            int productNumber = i + 1;
            System.out.println("\t" + productNumber + " - Product: " + name);
        }
        System.out.print("\n> ");
        try {
            int itemNumber = scanner.nextInt();
            if (itemNumber <= auctions.size()) {
                byte[] itemHash = auctions.get(itemNumber - 1).fst;

                double currentValue = House.getAuctionValue(itemHash);
                System.out.print("\nPlease insert how much do you want to bid (current min - " + currentValue + "):\n\t> ");
                int amount = scanner.nextInt();
                House.bid(node, itemHash, wallet, amount);
            } else {
                System.out.println("Invalid option!");
            }
        } catch (Exception ignored) {
            ignored.printStackTrace();
            System.out.println("Invalid option!");
        }
    }

    private static void miningAgent(KademliaNode node, Wallet wallet) {
        Miner miner = new Miner(wallet);
        MinerAgent agent = new MinerAgent(node, miner);
        boolean run = true;
        while (run) {
            try {
                // LOAD TRANSACTIONS, CHECK IF NEW ONE EXISTS, ADD NEW ONES
                ArrayList<BucketRoutingTree.Id> transactionIds = node.listTransactions();
                for(BucketRoutingTree.Id id : transactionIds) {
                    Transaction transaction = node.findTransactionValue(id);
                    if(!miner.transactionExists(transaction)) {
                        miner.addTransaction(transaction);
                    }
                };
            } catch (Exception ignored) {
                ignored.printStackTrace();
                run = false;
            }
        }
        agent.kill();
    }
}
