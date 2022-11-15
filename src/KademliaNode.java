package fcup;

import auction.Auction;
import auction.Bid;
import blockchain.Block;
import blockchain.errors.NullHashException;
import blockchain.transactions.Transaction;
import blockchain.transactions.TransactionInput;
import blockchain.transactions.TransactionOutput;
import com.google.protobuf.ByteString;
import crypto.Certificate;
import crypto.Keys;
import fcup.utils.BucketRoutingTree;
import io.grpc.*;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NettyChannelBuilder;
import io.grpc.stub.StreamObserver;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.bouncycastle.operator.OperatorCreationException;

import javax.net.ssl.SSLException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import java.util.stream.Collectors;

public class KademliaNode implements AutoCloseable {
    // Environment options
    //
    // level 0 -> all logs
    // level 1 -> only stderr
    // level >1 -> no log
    public static int logLevel = 0;
    public static int puzzleDifficulty = 3;
    private final AtomicBoolean terminated = new AtomicBoolean(false);
    private final HashMap<String, Block> storage = new HashMap<>();
    private final HashMap<String, Transaction> transactionStorage = new HashMap<>();
    private final HashMap<String, Bid> bidStorage = new HashMap<>();
    private final HashMap<String, Auction> auctionStorage = new HashMap<>();
    private final ConcurrentLinkedQueue<String> myBlocks = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<String> myAuctions = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<String> myTransactions = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<String> myBids = new ConcurrentLinkedQueue<>();
    // Node
    public BucketRoutingTree.Id id;
    public String ip; // IPv4
    public int port; // UDP
    // what others use for communication with @this node
    public ManagedChannel channel;
    public KademliaGrpc.KademliaBlockingStub stub;
    public boolean isBootstrap = false;

    // what @this node uses to listen to and handle incoming requests
    private Server server;
    private X509Certificate cert;
    private byte[] certBytes;
    private byte[] xBytes;
    private KeyPair keys;
    public MessageDigest hashFunction;
    private KademliaGrpc.KademliaImplBase handler;

    private BucketRoutingTree router;
    private KademliaNode owner;

    public KademliaNode(BucketRoutingTree.Id id, String ip, int port, KademliaNode owner, byte[] certB, byte[] x) {
        this.id = id;
        this.ip = ip;
        this.port = port;
        this.owner = owner;
        this.certBytes = certB;
        this.xBytes = x;
    }

    public KademliaNode(String ip,
                        int port,
                        String bootstrapIp,
                        int bootstrapPort) throws IOException, InterruptedException, NoSuchAlgorithmException, CertificateEncodingException {
        this.ip = ip;
        this.port = port;
        this.hashFunction = MessageDigest.getInstance("SHA-256");
        this.router = new BucketRoutingTree(this);
        this.handler = new KademliaServiceImpl(this);

        Runtime.getRuntime().addShutdownHook(new ShutdownThread(this));
        Thread rep = new RepublishThread(this);
        rep.setDaemon(true);
        rep.start();

        join(bootstrapIp, bootstrapPort);
    }

    private static String toAddress(String ip, int port) {
        return ip + ":" + port;
    }

    private static String toPEM(byte[] key) {
        final String ls = System.getProperty("line.separator");
        final Base64.Encoder encoder = Base64.getMimeEncoder(64, ls.getBytes());
        final String encodedCertText = new String(encoder.encode(key));
        return "-----BEGIN PRIVATE KEY-----"
                + ls
                + encodedCertText
                + ls
                + "-----END PRIVATE KEY-----";
    }

    private static String toPEM(X509Certificate certificate) throws CertificateEncodingException {
        final String ls = System.getProperty("line.separator");
        final Base64.Encoder encoder = Base64.getMimeEncoder(64, ls.getBytes());
        final byte[] rawCrtText = certificate.getEncoded();
        final String encodedCertText = new String(encoder.encode(rawCrtText));
        return "-----BEGIN CERTIFICATE-----"
                + ls
                + encodedCertText
                + ls
                + "-----END CERTIFICATE-----";
    }

    private static boolean hasTrailingZeros(int trailingBytesZero, byte[] digest) {
        if (trailingBytesZero > digest.length) {
            return hasTrailingZeros(digest.length, digest);
        }

        for (int i = 0; i < trailingBytesZero; i++) {
            if (digest[i] != 0) {
                return false;
            }
        }
        return true;
    }

    public static void log(Object message) {
        if (logLevel > 0) {
            return;
        }

        System.out.println("[KADEMLIA]: " + message);
    }

    public static void err(Object message) {
        if (logLevel > 1) {
            return;
        }

        System.err.println("[KADEMLIA]: " + message);
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof KademliaNode) {
            return ((KademliaNode) o).id.equals(id);
        }
        return false;
    }

    @Override
    public void close() {
        try {
            server.awaitTermination();

        } catch (InterruptedException ie) {
            err("Node interrupted before it could shutdown gracefully.");
            Thread.currentThread().interrupt();
        }

        if (router == null) {
            return;
        }
        router.buckets.forEach(l -> l.forEach(KademliaNode::disconnect));
    }

    public void shutdown() {
        if (terminated.getAndSet(true)) {
            return;
        }

        if (server == null) {
            return;
        }

        log("Destroying node...");
        try {
            server.shutdown().awaitTermination(20000, TimeUnit.MILLISECONDS);

        } catch (InterruptedException ie) {
            err("Node interrupted before it could shutdown gracefully.");
            Thread.currentThread().interrupt();
        }
    }

    // arg0:arg1 -> bootstrap node's address
    public void join(String ip, int port) throws IOException, InterruptedException, CertificateEncodingException {
        String bootAddr = toAddress(ip, port);
        String myAddr = toAddress(this.ip, this.port);
        log("My address: <" + myAddr + ">");
        log("Bootstrap address: <" + bootAddr + ">");

        // difficulty of puzzles
        // c * bytes
        int j = 0;

        log("Attempting crypto puzzle against Eclipse attacks...");
        while (true) {
            j++;

            try {
                keys = Keys.generateRSAKeyPair(2048);
                cert = Certificate.generate(keys, "CN=test");

                byte[] hash = hashFunction.digest(hashFunction.digest(cert.getEncoded()));
                if (hasTrailingZeros(puzzleDifficulty, hash)) {
                    break;
                }

            } catch (NoSuchAlgorithmException | OperatorCreationException | CertificateException e) {
                e.printStackTrace();
                System.exit(1);
            }
        }
        log("Eclipse crypto puzzle solved. In " + j);

        // mitigate eclipse attacks
        server = ServerBuilder
                .forPort(this.port)
                .useTransportSecurity(
                        new ByteArrayInputStream(toPEM(cert).getBytes()),
                        new ByteArrayInputStream(toPEM(keys.getPrivate().getEncoded()).getBytes()))
                .addService(handler)
                .build();

        if (ip.equals(this.ip) && port == this.port) {
            log("I am the bootstrap node.");
            id = BucketRoutingTree.Id.rootId();
            isBootstrap = true;

            // listening for requests is only really worth it after
            // joining the network
            server.start();

            err("Node ready. Listening to requests...");
            return;
        }

        KademliaNode bootstrap = new KademliaNode(BucketRoutingTree.Id.rootId(), ip, port, this, new byte[]{}, new byte[]{});

        // temporary, only for ping
        id = BucketRoutingTree.Id.rootId();

        log("Attempting to connect to bootstrap.");
        if (!tryConnectBootstrap(bootstrap)) {
            log("Bootstrap node <" + bootAddr + "> is offline. Exiting...");
            shutdown();
            return;
        }
        log("Connected to bootstrap.");

        // joining the network
        byte[] certHash = hashFunction.digest(cert.getEncoded());
        byte[] x = new byte[certHash.length];
        byte[] xored = new byte[certHash.length];
        j = 0;

        log("Generating ID...");
        log("Attempting crypto puzzle against Sybil attacks...");
        while (true) {
            j++;

            Random rand = new Random();
            rand.nextBytes(x);

            for (int i = 0; i < certHash.length; i++) {
                xored[i] = (byte) (x[i] ^ certHash[i]);
            }
            byte[] res = hashFunction.digest(xored);
            if (hasTrailingZeros(puzzleDifficulty, res)) {
                break;
            }
        }
        log("Sybil crypto puzzle solved. In " + j);

        xBytes = x;
        certBytes = cert.getEncoded();

        id = new BucketRoutingTree.Id(certHash);
        router = new BucketRoutingTree(this);
        router.put(bootstrap);
        log("My ID is " + id + ". Checking if anyone already owns it.");

        List<KademliaNode> closest = router.lookup(id);

        closest.forEach(n -> log(n.id + " RECEIVED"));

        if (closest.contains(this)) {
            throw new IOException("Some other node is using my ID.");
        }

        closest.forEach(node -> router.put(node));

        log("Committed. My ID is " + id + ".");

        server.start();
        log("Node ready. Listening to requests...");
    }


    // ////////////////////////////////////////////
    // Kademlia RPC protocol

    private boolean tryConnectBootstrap(KademliaNode bootstrap) throws InterruptedException {
        String bootAddr = toAddress(bootstrap.ip, bootstrap.port);

        // we will be retrying a couple of times before giving up
        // this makes it easier to automate tests
        // some nodes might spawn before the bootstrap is prepared
        int max_retry_count = 20;
        int retry_interval = 500;
        for (int retry = 0; retry < max_retry_count; retry++) {

            if (bootstrap.ping()) { // ping bootstrap
                return true;
            }
            err("Could not contact bootstrap node (try "
                    + retry
                    + "/"
                    + max_retry_count
                    + "): <" + bootAddr + ">");

            Thread.sleep(retry_interval);
        }
        return false;
    }

    // i.e. is_alive(id) = yes/no?
    public boolean ping(BucketRoutingTree.Id targetId) {
        if (server != null) {
            // host node code
            return router
                    .lookup(targetId)
                    .stream()
                    .anyMatch(n -> n.ping(targetId));
        }

        Boolean b = connect((connectionInfo -> {
            NodeReq request = NodeReq
                    .newBuilder()
                    .addAllRpcId(connectionInfo.rpcId)
                    .addAllTargetId(targetId)
                    .addAllRequesterId(owner.id)
                    .setRequesterIp(owner.ip)
                    .setRequesterPort(owner.port)
                    .build();

            Bool res = stub.ping(request);
            return new ConnectionResult<>(res.getValue(), res.getRpcIdList());
        }));

        if (b == null) {
            return false;
        }

        return b;
    }

    public boolean ping() {
        return ping(this.id);
    }

    private static Bid serializeBid(GrpcBid b) {
        return new Bid(
                serializeTransaction(b.getTransaction()),
                b.getAuction().toByteArray(),
                b.getBuyer().toByteArray(),
                b.getTimestamp(),
                b.getSignature().toByteArray()
        );
    }

    private static GrpcBid serializeBid(Bid b) {
        GrpcBid.Builder builder = GrpcBid.newBuilder();

        if (b.getTransaction() != null) {
            builder.setTransaction(serializeTransaction(b.getTransaction()));
        }

        return builder
                .setAuction(ByteString.copyFrom(b.getAuction()))
                .setBuyer(ByteString.copyFrom(b.getBuyer()))
                .setSignature(ByteString.copyFrom(b.getSignature()))
                .setTimestamp(b.getTimestamp())
                .build();
    }

    private static GrpcAuction serializeAuction(Auction a) {
        GrpcAuction.Builder builder = GrpcAuction.newBuilder();

        if (a.getItem() != null) {
            builder = builder.setItemHash(ByteString.copyFrom(a.getItem().getHash()));
            builder = builder.setItemName(a.getItem().getName());
            builder = builder.setDescription(a.getItem().getDescription());
            builder = builder.setBasePrice(a.getItem().getBasePrice());
            builder = builder.setTime(a.getItem().getTime());
            builder = builder.setSeller(ByteString.copyFrom(a.getItem().getSeller()));
        }

        ArrayList<GrpcBid> l = new ArrayList<GrpcBid>();
        if (a.getBids() != null) {
            for (Bid b : a.getBids()) {
                l.add(serializeBid(b));
            }
            builder = builder.addAllBids(l);
        }
        if (a.getHB() != null) {
            builder = builder.setHighestBid(serializeBid(a.getHB()));
        }

        return builder
                .setClosed(a.getClosed())
                .setCreationDate(a.getCreationDate())
                .setCloseDate(a.getCloseDate())
                .setPaid(a.getPaid())
                .build();
    }

    private static Auction serializeAuction(GrpcAuction a) {
        ArrayList<Bid> l = new ArrayList<>();

        for (GrpcBid b : a.getBidsList()) {
            if (b == null) continue;
            l.add(serializeBid(b));
        }

        return new Auction(
                a.getItemName(),
                a.getDescription(),
                a.getBasePrice(),
                a.getSeller().toByteArray(),
                a.getTime(),
                a.getItemHash().toByteArray(),
                l,
                a.getClosed(),
                serializeBid(a.getHighestBid()),
                a.getCreationDate(),
                a.getCloseDate(),
                a.getPaid()
        );
    }

    private static GrpcTransaction serializeTransaction(Transaction t) {
        GrpcTransaction transaction;

        ArrayList<GrpcTransactionInput> in = new ArrayList<GrpcTransactionInput>();
        ArrayList<GrpcTransactionOutput> out = new ArrayList<GrpcTransactionOutput>();
        for (TransactionInput ti : t.getInputs()) {
            GrpcTransactionInput i;
            GrpcTransactionOutput.Builder o = GrpcTransactionOutput
                    .newBuilder()
                    .setHash(ByteString.copyFrom(ti.getOutputHash()));

            if (ti.getUnspentTransaction() != null) {
                o.setTransaction(ByteString.copyFrom(ti.getUnspentTransaction().getTransaction()))
                        .setOwner(ByteString.copyFrom(ti.getUnspentTransaction().getOwner()))
                        .setValue(ti.getUnspentTransaction().getValue());

            }
            i = GrpcTransactionInput
                    .newBuilder()
                    .setTransactionOutputHash(ByteString.copyFrom(ti.getOutputHash()))
                    .setTransactionOutput(o.build())
                    .build();
            in.add(i);
        }

        for (TransactionOutput to : t.getOutputs()) {
            GrpcTransactionOutput o;

            o = GrpcTransactionOutput
                    .newBuilder()
                    .setHash(ByteString.copyFrom(to.getHash()))
                    .setTransaction(ByteString.copyFrom(to.getTransaction()))
                    .setOwner(ByteString.copyFrom(to.getOwner()))
                    .setValue(to.getValue())
                    .build();

            out.add(o);
        }

        GrpcTransaction.Builder b = GrpcTransaction.newBuilder()
                .setSender(ByteString.copyFrom(t.getSender()))
                .setReceiver(ByteString.copyFrom(t.getReceiver()))
                .setId(ByteString.copyFrom(t.getId()))
                .addAllTransactionInputs(in)
                .addAllTransactionOutputs(out)
                .setValue(t.getValue())
                .setTime(t.getTime());

        if (t.getSignature() != null) {
            b = b.setSignature(ByteString.copyFrom(t.getSignature()));
        }
        return b.build();
    }

    private static Transaction serializeTransaction(GrpcTransaction t) {
        ArrayList<TransactionInput> in = new ArrayList<>();
        ArrayList<TransactionOutput> out = new ArrayList<>();

        for (GrpcTransactionInput ti : t.getTransactionInputsList()) {
            in.add(
                    new TransactionInput(
                            ti.getTransactionOutputHash().toByteArray(),
                            new TransactionOutput(
                                    ti.getTransactionOutput().getHash().toByteArray(),
                                    ti.getTransactionOutput().getTransaction().toByteArray(),
                                    ti.getTransactionOutput().getOwner().toByteArray(),
                                    ti.getTransactionOutput().getValue()
                            )
                    )
            );
        }

        for (GrpcTransactionOutput to : t.getTransactionOutputsList()) {
            out.add(
                    new TransactionOutput(
                            to.getHash().toByteArray(),
                            to.getTransaction().toByteArray(),
                            to.getOwner().toByteArray(),
                            to.getValue()
                    )
            );
        }

        return new Transaction(t.getSender().toByteArray(),
                t.getReceiver().toByteArray(),
                in,
                out,
                t.getValue(),
                t.getId().toByteArray(),
                t.getSignature().toByteArray(),
                t.getTime());
    }

    private static Block serializeBlock(GrpcBlock b) {
        ArrayList<Transaction> l = new ArrayList<>();

        for (GrpcTransaction t : b.getTransactionsList()) {
            ArrayList<TransactionInput> in = new ArrayList<>();
            ArrayList<TransactionOutput> out = new ArrayList<>();

            for (GrpcTransactionInput ti : t.getTransactionInputsList()) {
                in.add(
                        new TransactionInput(
                                ti.getTransactionOutputHash().toByteArray(),
                                new TransactionOutput(
                                        ti.getTransactionOutput().getHash().toByteArray(),
                                        ti.getTransactionOutput().getTransaction().toByteArray(),
                                        ti.getTransactionOutput().getOwner().toByteArray(),
                                        ti.getTransactionOutput().getValue()
                                )
                        )
                );
            }

            for (GrpcTransactionOutput to : t.getTransactionOutputsList()) {
                out.add(
                        new TransactionOutput(
                                to.getHash().toByteArray(),
                                to.getTransaction().toByteArray(),
                                to.getOwner().toByteArray(),
                                to.getValue()
                        )
                );
            }

            Transaction transaction = new Transaction(t.getSender().toByteArray(),
                    t.getReceiver().toByteArray(),
                    in,
                    out,
                    t.getValue(),
                    t.getId().toByteArray(),
                    t.getSignature().toByteArray(),
                    t.getTime());
            l.add(transaction);
        }

        return new Block(
                b.getHash().toByteArray(),
                b.getSalt().toByteArray(),
                b.getPreviousHash().toByteArray(),
                b.getInformation().toByteArray(),
                b.getMerkleRoot().toByteArray(),
                b.getTime(),
                l
        );
    }

    private static GrpcBlock serializeBlock(Block b) throws NullHashException {

        ArrayList<GrpcTransaction> l = new ArrayList<GrpcTransaction>();
        for (Transaction t : b.getTransactions()) {
            GrpcTransaction transaction;

            ArrayList<GrpcTransactionInput> in = new ArrayList<GrpcTransactionInput>();
            ArrayList<GrpcTransactionOutput> out = new ArrayList<GrpcTransactionOutput>();
            for (TransactionInput ti : t.getInputs()) {
                GrpcTransactionInput i;
                GrpcTransactionOutput o;

                o = GrpcTransactionOutput
                        .newBuilder()
                        .setHash(ByteString.copyFrom(ti.getOutputHash()))
                        .setTransaction(ByteString.copyFrom(ti.getUnspentTransaction().getTransaction()))
                        .setOwner(ByteString.copyFrom(ti.getUnspentTransaction().getOwner()))
                        .setValue(ti.getUnspentTransaction().getValue())
                        .build();
                i = GrpcTransactionInput
                        .newBuilder()
                        .setTransactionOutputHash(ByteString.copyFrom(ti.getOutputHash()))
                        .setTransactionOutput(o)
                        .build();
                in.add(i);
            }

            for (TransactionOutput to : t.getOutputs()) {
                GrpcTransactionOutput o;

                o = GrpcTransactionOutput
                        .newBuilder()
                        .setHash(ByteString.copyFrom(to.getHash()))
                        .setTransaction(ByteString.copyFrom(to.getTransaction()))
                        .setOwner(ByteString.copyFrom(to.getOwner()))
                        .setValue(to.getValue())
                        .build();

                out.add(o);
            }

            transaction = GrpcTransaction
                    .newBuilder()
                    .setSender(ByteString.copyFrom(t.getSender()))
                    .setReceiver(ByteString.copyFrom(t.getReceiver()))
                    .setId(ByteString.copyFrom(t.getId()))
                    .addAllTransactionInputs(in)
                    .addAllTransactionOutputs(out)
                    .setSignature(ByteString.copyFrom(t.getSignature()))
                    .setValue(t.getValue())
                    .setTime(t.getTime())
                    .build();
            l.add(transaction);
        }

        GrpcBlock.Builder block = GrpcBlock
                .newBuilder()
                .setPreviousHash(ByteString.copyFrom(b.getPreviousHash()))
                .setInformation(ByteString.copyFrom(b.getInformation()))
                .setTime(b.getTime())
                .addAllTransactions(l)
                .setNonce(b.getNonce());

        if (b.hash != null) {
            block = block.setHash(ByteString.copyFrom(b.getHash()));
            block = block.setSalt(ByteString.copyFrom(b.getSalt()));
        }

        if (b.getMerkleRoot() != null) {
            block = block.setMerkleRoot(ByteString.copyFrom(b.getMerkleRoot()));
        }

        return block.build();
    }

    public boolean storeAuction(BucketRoutingTree.Id key, Auction value) {
        GrpcAuction auction = serializeAuction(value);

        if (server != null) {
            auctionStorage.put(key.toString(), value);

            AtomicBoolean any = new AtomicBoolean(false);
            router
                    .lookup(key)
                    .parallelStream()
                    .forEach(n -> {
                        if (n.storeAuction(key, value)) any.set(true);
                    });
            return any.get();
        }

        Boolean b = connect((connectionInfo -> {
            StoreAuctionReq req = StoreAuctionReq
                    .newBuilder()
                    .addAllRpcId(connectionInfo.rpcId)
                    .addAllTargetId(key)
                    .addAllRequesterId(owner.id)
                    .setValue(auction)
                    .setCert(ByteString.copyFrom(owner.certBytes))
                    .setX(ByteString.copyFrom(owner.xBytes))
                    .build();

            Bool res = stub.storeAuction(req);
            return new ConnectionResult<>(res.getValue(), res.getRpcIdList());
        }));

        if (b == null) {
            return false;
        }

        return b;

    }

    public boolean storeBid(BucketRoutingTree.Id key, Bid value) {
        GrpcBid bid = serializeBid(value);

        if (server != null) {
            bidStorage.put(key.toString(), value);

            AtomicBoolean any = new AtomicBoolean(false);
            List<KademliaNode> found = router.lookup(key);

            found.parallelStream()
                    .forEach(n -> {
                        if (n.ping() && n.storeBid(key, value)) any.set(true);
                    });
            //Thread thread = new Thread(() -> tasks.parallelStream().forEach(Runnable::run));
            return any.get();
        }

        Boolean b = connect((connectionInfo -> {
            StoreBidReq req = StoreBidReq
                    .newBuilder()
                    .addAllRpcId(connectionInfo.rpcId)
                    .addAllTargetId(key)
                    .addAllRequesterId(owner.id)
                    .setValue(bid)
                    .setCert(ByteString.copyFrom(owner.certBytes))
                    .setX(ByteString.copyFrom(owner.xBytes))
                    .build();

            Bool res = stub.storeBid(req);
            return new ConnectionResult<>(res.getValue(), res.getRpcIdList());
        }));

        if (b == null) {
            return false;
        }

        return b;

    }

    public boolean storeTransaction(BucketRoutingTree.Id key, Transaction value) {
        GrpcTransaction transaction = serializeTransaction(value);

        if (server != null) {
            transactionStorage.put(key.toString(), value);

            AtomicBoolean any = new AtomicBoolean(false);
            List<KademliaNode> found = router.lookup(key);

            found.forEach(n -> {
                if (n.ping() && n.storeTransaction(key, value)) any.set(true);
            });
            return any.get();
        }

        Boolean b = connect((connectionInfo -> {
            StoreTransactionReq req = StoreTransactionReq
                    .newBuilder()
                    .addAllRpcId(connectionInfo.rpcId)
                    .addAllTargetId(key)
                    .addAllRequesterId(owner.id)
                    .setValue(transaction)
                    .setCert(ByteString.copyFrom(owner.certBytes))
                    .setX(ByteString.copyFrom(owner.xBytes))
                    .build();

            Bool res = stub.storeTransaction(req);
            return new ConnectionResult<>(res.getValue(), res.getRpcIdList());
        }));

        if (b == null) {
            return false;
        }

        return b;

    }

    public boolean store(BucketRoutingTree.Id key, Block value) throws NullHashException {
        GrpcBlock block = serializeBlock(value);

        if (server != null) {
            storage.put(key.toString(), value);

            AtomicBoolean any = new AtomicBoolean(false);
            router
                    .lookup(key)
                    .parallelStream()
                    .forEach(n -> {
                        try {
                            if (n.store(key, value)) any.set(true);
                        } catch (NullHashException e) {
                            e.printStackTrace();
                        }
                    });
            return any.get();
        }

        Boolean b = connect((connectionInfo -> {
            StoreReq req = StoreReq
                    .newBuilder()
                    .addAllRpcId(connectionInfo.rpcId)
                    .addAllTargetId(key)
                    .addAllRequesterId(owner.id)
                    .setValue(block)
                    .setCert(ByteString.copyFrom(owner.certBytes))
                    .setX(ByteString.copyFrom(owner.xBytes))
                    .build();

            Bool res = stub.store(req);
            return new ConnectionResult<>(res.getValue(), res.getRpcIdList());
        }));

        if (b == null) {
            return false;
        }

        return b;
    }

    public List<KademliaNode> findNode(BucketRoutingTree.Id targetId) {
        if (server != null) {
            return router.lookup(targetId);
        }

        return connect((connectionInfo -> {
            NodeReq request = NodeReq
                    .newBuilder()
                    .addAllRpcId(connectionInfo.rpcId)
                    .addAllTargetId(targetId)
                    .addAllRequesterId(owner.id)
                    .setRequesterIp(owner.ip)
                    .setRequesterPort(owner.port)
                    .setCert(ByteString.copyFrom(owner.certBytes))
                    .setX(ByteString.copyFrom(owner.xBytes))
                    .build();

            List<KademliaNode> l = new ArrayList<>();

            List<Integer> rid = null;
            for (Iterator<FindNodeResponse> it = stub.findNode(request); it.hasNext(); ) {
                FindNodeResponse resp = it.next();

                if (rid == null) {
                    rid = resp.getRpcIdList();
                }

                if (!resp.getIsPresent()) {
                    break;
                }

                BucketRoutingTree.Id tid = new BucketRoutingTree.Id(resp.getTargetIdList());
                l.add(new KademliaNode(tid, resp.getIp(), resp.getPort(), owner, resp.getCert() != null ? resp.getCert().toByteArray() : new byte[]{}, resp.getX() != null ? resp.getX().toByteArray() : new byte[]{}));
            }
            return new ConnectionResult<>(l, rid);
        }));

    }

    public Auction findAuctionValue(BucketRoutingTree.Id key) {
        if (server != null) {
            if (auctionStorage.containsKey(key.toString())) {
                return auctionStorage.get(key.toString());
            }

            Optional<Auction> res = router
                    .lookup(key)
                    .parallelStream()
                    .map(n -> n.findAuctionValue(key))
                    .filter(Objects::nonNull)
                    .findAny();

            return res.orElse(null);
        }

        return connect((connectionInfo) -> {
            NodeReq request = NodeReq
                    .newBuilder()
                    .addAllRpcId(connectionInfo.rpcId)
                    .addAllTargetId(key)
                    .addAllRequesterId(owner.id)
                    .setRequesterIp(owner.ip)
                    .setRequesterPort(owner.port)
                    .setCert(ByteString.copyFrom(owner.certBytes))
                    .setX(ByteString.copyFrom(owner.xBytes))
                    .build();

            List<Integer> rid = null;
            for (Iterator<FindAuctionValueResponse> it = stub.findAuctionValue(request); it.hasNext(); ) {
                FindAuctionValueResponse resp = it.next();

                if (rid == null) {
                    rid = resp.getRpcIdList();
                }

                if (resp.getIsPresent()) {
                    return new ConnectionResult<>(serializeAuction(resp.getValue()), resp.getRpcIdList());
                }
            }
            return new ConnectionResult<>(null, rid);
        });
    }

    public ArrayList<BucketRoutingTree.Id> listBids() {
        if (server != null) {
            List<ArrayList<BucketRoutingTree.Id>> res = router
                    .loop()
                    .parallelStream()
                    .map(KademliaNode::listBids)
                    .collect(Collectors.toList());

            ArrayList<BucketRoutingTree.Id> r = new ArrayList<>();
            for (ArrayList<BucketRoutingTree.Id> rr : res) {
                if (rr == null) continue;
                r.addAll(rr);
            }

            bidStorage.keySet().forEach(k -> r.add(BucketRoutingTree.Id.fromString(k)));
            ArrayList<BucketRoutingTree.Id> uniq = new ArrayList<>();
            for (BucketRoutingTree.Id id : r) {
                boolean e = false;
                for (BucketRoutingTree.Id i : uniq) {
                    if (i.equals(id)) {
                        e = true;
                        break;
                    }
                }
                if (e) continue;
                uniq.add(id);
            }
            return uniq;
        }

        return connect((connectionInfo) -> {
            ListReq request = ListReq
                    .newBuilder()
                    .addAllRpcId(connectionInfo.rpcId)
                    .addAllRequesterId(owner.id)
                    .setRequesterIp(owner.ip)
                    .setRequesterPort(owner.port)
                    .setCert(ByteString.copyFrom(owner.certBytes))
                    .setX(ByteString.copyFrom(owner.xBytes))
                    .build();

            List<Integer> rid = null;
            ArrayList<BucketRoutingTree.Id> l = new ArrayList<>();
            for (Iterator<ListResponse> it = stub.listBids(request); it.hasNext(); ) {
                ListResponse resp = it.next();

                if (rid == null) {
                    rid = resp.getRpcIdList();
                }

                if (resp.getIsPresent()) {
                    l.add(BucketRoutingTree.Id.fromString(resp.getKey()));
                }
            }
            return new ConnectionResult<>(l, rid);
        });
    }

    public ArrayList<BucketRoutingTree.Id> listTransactions() {
        if (server != null) {
            List<ArrayList<BucketRoutingTree.Id>> res = router
                    .loop()
                    .parallelStream()
                    .map(KademliaNode::listTransactions)
                    .collect(Collectors.toList());

            ArrayList<BucketRoutingTree.Id> r = new ArrayList<>();
            for (ArrayList<BucketRoutingTree.Id> rr : res) {
                if (rr == null) continue;
                r.addAll(rr);
            }

            transactionStorage.keySet().forEach(k -> r.add(BucketRoutingTree.Id.fromString(k)));
            ArrayList<BucketRoutingTree.Id> uniq = new ArrayList<>();
            for (BucketRoutingTree.Id id : r) {
                boolean e = false;
                for (BucketRoutingTree.Id i : uniq) {
                    if (i.equals(id)) {
                        e = true;
                        break;
                    }
                }
                if (e) continue;
                uniq.add(id);
            }
            return uniq;
        }

        return connect((connectionInfo) -> {
            ListReq request = ListReq
                    .newBuilder()
                    .addAllRpcId(connectionInfo.rpcId)
                    .addAllRequesterId(owner.id)
                    .setRequesterIp(owner.ip)
                    .setRequesterPort(owner.port)
                    .setCert(ByteString.copyFrom(owner.certBytes))
                    .setX(ByteString.copyFrom(owner.xBytes))
                    .build();

            List<Integer> rid = null;
            ArrayList<BucketRoutingTree.Id> l = new ArrayList<>();
            for (Iterator<ListResponse> it = stub.listTransactions(request); it.hasNext(); ) {
                ListResponse resp = it.next();

                if (rid == null) {
                    rid = resp.getRpcIdList();
                }

                if (resp.getIsPresent()) {
                    l.add(BucketRoutingTree.Id.fromString(resp.getKey()));
                }
            }
            return new ConnectionResult<>(l, rid);
        });
    }

    public ArrayList<BucketRoutingTree.Id> listAuctions() {
        if (server != null) {
            List<ArrayList<BucketRoutingTree.Id>> res = router
                    .loop()
                    .parallelStream()
                    .map(KademliaNode::listAuctions)
                    .collect(Collectors.toList());

            ArrayList<BucketRoutingTree.Id> r = new ArrayList<>();
            for (ArrayList<BucketRoutingTree.Id> rr : res) {
                if (rr == null) continue;
                r.addAll(rr);
            }

            auctionStorage.keySet().forEach(k -> r.add(BucketRoutingTree.Id.fromString(k)));
            ArrayList<BucketRoutingTree.Id> uniq = new ArrayList<>();
            for (BucketRoutingTree.Id id : r) {
                boolean e = false;
                for (BucketRoutingTree.Id i : uniq) {
                    if (i.equals(id)) {
                        e = true;
                        break;
                    }
                }
                if (e) continue;
                uniq.add(id);
            }
            return uniq;
        }

        return connect((connectionInfo) -> {
            ListReq request = ListReq
                    .newBuilder()
                    .addAllRpcId(connectionInfo.rpcId)
                    .addAllRequesterId(owner.id)
                    .setRequesterIp(owner.ip)
                    .setRequesterPort(owner.port)
                    .setCert(ByteString.copyFrom(owner.certBytes))
                    .setX(ByteString.copyFrom(owner.xBytes))
                    .build();

            List<Integer> rid = null;
            ArrayList<BucketRoutingTree.Id> l = new ArrayList<>();
            for (Iterator<ListResponse> it = stub.listAuctions(request); it.hasNext(); ) {
                ListResponse resp = it.next();

                if (rid == null) {
                    rid = resp.getRpcIdList();
                }

                if (resp.getIsPresent()) {
                    l.add(BucketRoutingTree.Id.fromString(resp.getKey()));
                }
            }
            return new ConnectionResult<>(l, rid);
        });
    }

    public ArrayList<BucketRoutingTree.Id> listBlocks() {
        if (server != null) {
            List<ArrayList<BucketRoutingTree.Id>> res = router
                    .loop()
                    .parallelStream()
                    .map(KademliaNode::listBlocks)
                    .collect(Collectors.toList());

            ArrayList<BucketRoutingTree.Id> r = new ArrayList<>();
            for (ArrayList<BucketRoutingTree.Id> rr : res) {
                if (rr == null || rr.isEmpty()) continue;
                r.addAll(rr);
            }

            storage.keySet().forEach(k -> r.add(BucketRoutingTree.Id.fromString(k)));
            ArrayList<BucketRoutingTree.Id> uniq = new ArrayList<>();
            for (BucketRoutingTree.Id id : r) {
                boolean e = false;
                for (BucketRoutingTree.Id i : uniq) {
                    if (i.equals(id)) {
                        e = true;
                        break;
                    }
                }
                if (e) continue;
                uniq.add(id);
            }
            return uniq;
        }

        return connect((connectionInfo) -> {
            ListReq request = ListReq
                    .newBuilder()
                    .addAllRpcId(connectionInfo.rpcId)
                    .addAllRequesterId(owner.id)
                    .setRequesterIp(owner.ip)
                    .setRequesterPort(owner.port)
                    .setCert(ByteString.copyFrom(owner.certBytes))
                    .setX(ByteString.copyFrom(owner.xBytes))
                    .build();

            List<Integer> rid = null;
            ArrayList<BucketRoutingTree.Id> l = new ArrayList<>();
            for (Iterator<ListResponse> it = stub.listBlocks(request); it.hasNext(); ) {
                ListResponse resp = it.next();

                if (rid == null) {
                    rid = resp.getRpcIdList();
                }

                if (resp.getIsPresent()) {
                    l.add(BucketRoutingTree.Id.fromString(resp.getKey()));
                }
            }
            return new ConnectionResult<>(l, rid);
        });
    }

    public Bid findBidValue(BucketRoutingTree.Id key) {
        if (server != null) {
            if (bidStorage.containsKey(key.toString())) {
                return bidStorage.get(key.toString());
            }

            Optional<Bid> res = router
                    .lookup(key)
                    .parallelStream()
                    .map(n -> n.findBidValue(key))
                    .filter(Objects::nonNull)
                    .findAny();

            return res.orElse(null);
        }

        return connect((connectionInfo) -> {
            NodeReq request = NodeReq
                    .newBuilder()
                    .addAllRpcId(connectionInfo.rpcId)
                    .addAllTargetId(key)
                    .addAllRequesterId(owner.id)
                    .setRequesterIp(owner.ip)
                    .setRequesterPort(owner.port)
                    .setCert(ByteString.copyFrom(owner.certBytes))
                    .setX(ByteString.copyFrom(owner.xBytes))
                    .build();

            List<Integer> rid = null;
            for (Iterator<FindBidValueResponse> it = stub.findBidValue(request); it.hasNext(); ) {
                FindBidValueResponse resp = it.next();

                if (rid == null) {
                    rid = resp.getRpcIdList();
                }

                if (resp.getIsPresent()) {
                    return new ConnectionResult<>(serializeBid(resp.getValue()), resp.getRpcIdList());
                }
            }
            return new ConnectionResult<>(null, rid);
        });
    }

    public Transaction findTransactionValue(BucketRoutingTree.Id key) {
        if (server != null) {
            if (transactionStorage.containsKey(key.toString())) {
                return transactionStorage.get(key.toString());
            }

            Optional<Transaction> res = router
                    .lookup(key)
                    .parallelStream()
                    .map(n -> n.findTransactionValue(key))
                    .filter(Objects::nonNull)
                    .findAny();

            return res.orElse(null);
        }

        return connect((connectionInfo) -> {
            NodeReq request = NodeReq
                    .newBuilder()
                    .addAllRpcId(connectionInfo.rpcId)
                    .addAllTargetId(key)
                    .addAllRequesterId(owner.id)
                    .setRequesterIp(owner.ip)
                    .setRequesterPort(owner.port)
                    .setCert(ByteString.copyFrom(owner.certBytes))
                    .setX(ByteString.copyFrom(owner.xBytes))
                    .build();

            List<Integer> rid = null;
            for (Iterator<FindTransactionValueResponse> it = stub.findTransactionValue(request); it.hasNext(); ) {
                FindTransactionValueResponse resp = it.next();

                if (rid == null) {
                    rid = resp.getRpcIdList();
                }

                if (resp.getIsPresent()) {
                    return new ConnectionResult<>(serializeTransaction(resp.getValue()), resp.getRpcIdList());
                }
            }
            return new ConnectionResult<>(null, rid);
        });
    }


    // ////////////////////////////////////////////
    // GRPC outgoing requests

    public Block findValue(BucketRoutingTree.Id key) {
        if (server != null) {
            if (storage.containsKey(key.toString())) {
                return storage.get(key.toString());
            }

            Optional<Block> res = router
                    .lookup(key)
                    .parallelStream()
                    .map(n -> n.findValue(key))
                    .filter(Objects::nonNull)
                    .findAny();

            return res.orElse(null);
        }

        return connect((connectionInfo) -> {
            NodeReq request = NodeReq
                    .newBuilder()
                    .addAllRpcId(connectionInfo.rpcId)
                    .addAllTargetId(key)
                    .addAllRequesterId(owner.id)
                    .setRequesterIp(owner.ip)
                    .setRequesterPort(owner.port)
                    .setCert(ByteString.copyFrom(owner.certBytes))
                    .setX(ByteString.copyFrom(owner.xBytes))
                    .build();

            List<Integer> rid = null;
            for (Iterator<FindValueResponse> it = stub.findValue(request); it.hasNext(); ) {
                FindValueResponse resp = it.next();

                if (rid == null) {
                    rid = resp.getRpcIdList();
                }

                if (resp.getIsPresent()) {
                    return new ConnectionResult<>(serializeBlock(resp.getValue()), resp.getRpcIdList());
                }
            }
            return new ConnectionResult<>(null, rid);
        });
    }

    public Lock l = new ReentrantLock();

    private void deleteChannel() {
        if (channel != null) {
            channel.shutdown();
            channel = null;
        }
    }

    public long time = System.currentTimeMillis();

    public <T> T connect(Function<ConnectionInfo, ConnectionResult<T>> rpc) {
        ManagedChannel ch = null;
        try {
            time = System.currentTimeMillis();

            try {
                ch = NettyChannelBuilder
                        .forAddress(ip, port)
                        .sslContext(GrpcSslContexts
                                .forClient()
                                .trustManager(InsecureTrustManagerFactory.INSTANCE)
                                .build())
                        .build();

            } catch (SSLException se) {
                err("SSL EXCEPTION: " + se.getMessage());
            }
            stub = KademliaGrpc.newBlockingStub(ch);

            ConnectionInfo con = new ConnectionInfo(stub);
            try {
                ConnectionResult<T> res = rpc.apply(con);
                BucketRoutingTree.Id rpcId = res.rpcId;

                if (!rpcId.equals(con.rpcId)) {
                    err("Address forgery detected. Received RPC ID is different.");
                    return null;
                }
                return res.result;

            } catch (StatusRuntimeException sr) {
                err("RPC call error... Discard node.");
                owner.router.remove(this);
                //err(sr.getMessage());
                //sr.printStackTrace();
            } catch (Exception e) {
                //e.printStackTrace();
                err(e.getMessage());
                //e.printStackTrace();
            }
            return null;
        } finally {
            //deleteChannel();
            if (ch != null) {
                ch.shutdown();
            }
            //l.unlock();
            time = System.currentTimeMillis();
        }

    }

    public KademliaNode disconnect() {
        if (channel == null) {
            return this;
        }
        channel.shutdown();

        return this;
    }

    private static class
    RepublishThread extends Thread {
        private final KademliaNode node;

        public RepublishThread(KademliaNode node) {
            this.node = node;
        }

        @Override
        public void run() {
            try {
                while (true) {
                    Thread.sleep(3600000);
                    log("Republishing values...");

                    node.storage.keySet().forEach(k -> {
                        if (!node.myBlocks.contains(k)) {
                            node.storage.remove(k);
                        }
                    });
                    node.bidStorage.keySet().forEach(k -> {
                        if (!node.myBids.contains(k)) {
                            node.bidStorage.remove(k);
                        }
                    });
                    node.auctionStorage.keySet().forEach(k -> {
                        if (!node.myAuctions.contains(k)) {
                            node.auctionStorage.remove(k);
                        }
                    });
                    node.transactionStorage.keySet().forEach(k -> {
                        if (!node.myTransactions.contains(k)) {
                            node.transactionStorage.remove(k);
                        }
                    });

                    node.storage.keySet().forEach(k -> {
                        try {
                            node.store(BucketRoutingTree.Id.fromString(k), node.storage.get(k));
                        } catch (NullHashException e) {
                            e.printStackTrace();
                        }
                    });
                    node.bidStorage.keySet().forEach(k -> {
                        node.storeBid(BucketRoutingTree.Id.fromString(k), node.bidStorage.get(k));
                    });
                    node.auctionStorage.keySet().forEach(k -> {
                        node.storeTransaction(BucketRoutingTree.Id.fromString(k), node.transactionStorage.get(k));
                    });
                    node.transactionStorage.keySet().forEach(k -> {
                        node.storeAuction(BucketRoutingTree.Id.fromString(k), node.auctionStorage.get(k));
                    });
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    private static class
    DeadlockThread extends Thread {
        private final KademliaNode node;

        public DeadlockThread(KademliaNode node) {
            this.node = node;
        }

        @Override
        public void run() {
            try {
                while (true) {
                    Thread.sleep(1000);
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    private static class
    ShutdownThread extends Thread {
        private final KademliaNode node;

        public ShutdownThread(KademliaNode node) {
            this.node = node;
        }

        @Override
        public void run() {
            log("SIGTERM called.");
            node.shutdown();
        }
    }

    // ////////////////////////////////////////////
    // GRPC incoming requests handler

    private static class
    ConnectionInfo {
        KademliaGrpc.KademliaBlockingStub stub;
        BucketRoutingTree.Id rpcId;

        public ConnectionInfo(KademliaGrpc.KademliaBlockingStub stub) {
            this.stub = stub;
            this.rpcId = BucketRoutingTree.Id.randomId();
        }
    }

    private static class
    ConnectionResult<T> {
        T result;
        BucketRoutingTree.Id rpcId;

        public ConnectionResult(T result, List<Integer> rid) {
            this.result = result;
            this.rpcId = new BucketRoutingTree.Id(rid);
        }
    }

    private static class KademliaServiceImpl extends KademliaGrpc.KademliaImplBase {
        // the node which is exposing server capabilities
        // this host process' node
        private final KademliaNode node;

        public KademliaServiceImpl(KademliaNode node) {
            this.node = node;
        }

        private boolean ver(byte[] c, byte[] x) {
            byte[] hash = node.hashFunction.digest(node.hashFunction.digest(c));
            if (!hasTrailingZeros(puzzleDifficulty, hash)) {
                err("Ilegitimate node fails resistance against Eclipse");
                return false;
            }

            byte[] xored = new byte[hash.length];
            for (int i = 0; i < hash.length; i++) {
                xored[i] = (byte) (x[i] ^ hash[i]);
            }
            byte[] res = node.hashFunction.digest(xored);
            if (!hasTrailingZeros(puzzleDifficulty, res)) {
                err("Ilegitimate node fails resistance against Sybil");
                return false;
            }

            return true;
        }

        private void verify(StoreTransactionReq req) {
            BucketRoutingTree.Id requesterId = new BucketRoutingTree.Id(req.getRequesterIdList());
            if (requesterId.isRoot()) {
                return;
            }
            if (req.getCert() == null || req.getX() == null) {
                err("Null cert or X");
                throw new StatusRuntimeException(Status.PERMISSION_DENIED);
            }
            byte[] c = req.getCert().toByteArray();
            byte[] x = req.getX().toByteArray();
            if (!ver(c, x)) {
                err("Illegitimate node detected with ID " + requesterId);
                throw new StatusRuntimeException(Status.PERMISSION_DENIED);
            }
        }

        private void verify(StoreReq req) {
            BucketRoutingTree.Id requesterId = new BucketRoutingTree.Id(req.getRequesterIdList());
            if (requesterId.isRoot()) {
                return;
            }
            if (req.getCert() == null || req.getX() == null) {
                err("Null cert or X");
                throw new StatusRuntimeException(Status.PERMISSION_DENIED);
            }
            byte[] c = req.getCert().toByteArray();
            byte[] x = req.getX().toByteArray();
            if (!ver(c, x)) {
                err("Illegitimate node detected with ID " + requesterId);
                throw new StatusRuntimeException(Status.PERMISSION_DENIED);
            }
        }

        private void verify(StoreBidReq req) {
            BucketRoutingTree.Id requesterId = new BucketRoutingTree.Id(req.getRequesterIdList());
            if (requesterId.isRoot()) {
                return;
            }
            if (req.getCert() == null || req.getX() == null) {
                err("Null cert or X");
                throw new StatusRuntimeException(Status.PERMISSION_DENIED);
            }
            byte[] c = req.getCert().toByteArray();
            byte[] x = req.getX().toByteArray();
            if (!ver(c, x)) {
                err("Illegitimate node detected with ID " + requesterId);
                throw new StatusRuntimeException(Status.PERMISSION_DENIED);
            }
        }

        private void verify(StoreAuctionReq req) {
            BucketRoutingTree.Id requesterId = new BucketRoutingTree.Id(req.getRequesterIdList());
            if (requesterId.isRoot()) {
                return;
            }
            if (req.getCert() == null || req.getX() == null) {
                err("Null cert or X");
                throw new StatusRuntimeException(Status.PERMISSION_DENIED);
            }
            byte[] c = req.getCert().toByteArray();
            byte[] x = req.getX().toByteArray();
            if (!ver(c, x)) {
                err("Illegitimate node detected with ID " + requesterId);
                throw new StatusRuntimeException(Status.PERMISSION_DENIED);
            }
        }

        private void verify(NodeReq req) {
            BucketRoutingTree.Id requesterId = new BucketRoutingTree.Id(req.getRequesterIdList());
            if (requesterId.isRoot()) {
                return;
            }
            if (req.getCert() == null || req.getX() == null) {
                err("Null cert or X");
                throw new StatusRuntimeException(Status.PERMISSION_DENIED);
            }
            byte[] c = req.getCert().toByteArray();
            byte[] x = req.getX().toByteArray();
            if (!ver(c, x)) {
                err("Illegitimate node detected with ID " + requesterId);
                throw new StatusRuntimeException(Status.PERMISSION_DENIED);
            }
        }

        private void verify(ListReq req) {
            BucketRoutingTree.Id requesterId = new BucketRoutingTree.Id(req.getRequesterIdList());
            if (requesterId.isRoot()) {
                return;
            }
            if (req.getCert() == null || req.getX() == null) {
                err("Null cert or X");
                throw new StatusRuntimeException(Status.PERMISSION_DENIED);
            }
            byte[] c = req.getCert().toByteArray();
            byte[] x = req.getX().toByteArray();
            if (!ver(c, x)) {
                err("Illegitimate node detected with ID " + requesterId);
                throw new StatusRuntimeException(Status.PERMISSION_DENIED);
            }
        }

        private void storeRequesterNode(NodeReq req) {
            BucketRoutingTree.Id requesterId = new BucketRoutingTree.Id(req.getRequesterIdList());
            node.router.put(new KademliaNode(requesterId, req.getRequesterIp(), req.getRequesterPort(), node, req.getCert().toByteArray(), req.getX().toByteArray()));
            log(node.router);
        }

        @Override
        public void listBlocks(ListReq req, StreamObserver<ListResponse> res) {
            verify(req);
            if (node.storage.keySet().isEmpty()) {
                ListResponse r = ListResponse
                        .newBuilder()
                        .addAllRpcId(req.getRpcIdList())
                        .setIsPresent(false)
                        .build();
                res.onNext(r);
                res.onCompleted();
                return;
            }

            node.storage.keySet().forEach(s -> {
                ListResponse r = ListResponse
                        .newBuilder()
                        .addAllRpcId(req.getRpcIdList())
                        .setKey(s)
                        .setIsPresent(true)
                        .build();
                res.onNext(r);
            });
            res.onCompleted();
        }

        @Override
        public void listAuctions(ListReq req, StreamObserver<ListResponse> res) {
            verify(req);
            if (node.auctionStorage.keySet().isEmpty()) {
                ListResponse r = ListResponse
                        .newBuilder()
                        .addAllRpcId(req.getRpcIdList())
                        .setIsPresent(false)
                        .build();
                res.onNext(r);
                res.onCompleted();
                return;
            }

            node.auctionStorage.keySet().forEach(s -> {
                ListResponse r = ListResponse
                        .newBuilder()
                        .addAllRpcId(req.getRpcIdList())
                        .setKey(s)
                        .setIsPresent(true)
                        .build();
                res.onNext(r);
            });
            res.onCompleted();
        }

        @Override
        public void listTransactions(ListReq req, StreamObserver<ListResponse> res) {
            verify(req);
            if (node.transactionStorage.keySet().isEmpty()) {
                ListResponse r = ListResponse
                        .newBuilder()
                        .addAllRpcId(req.getRpcIdList())
                        .setIsPresent(false)
                        .build();
                res.onNext(r);
                res.onCompleted();
                return;
            }

            node.transactionStorage.keySet().forEach(s -> {
                ListResponse r = ListResponse
                        .newBuilder()
                        .addAllRpcId(req.getRpcIdList())
                        .setKey(s)
                        .setIsPresent(true)
                        .build();
                res.onNext(r);
            });
            res.onCompleted();
        }

        @Override
        public void listBids(ListReq req, StreamObserver<ListResponse> res) {
            verify(req);
            if (node.bidStorage.keySet().isEmpty()) {
                ListResponse r = ListResponse
                        .newBuilder()
                        .addAllRpcId(req.getRpcIdList())
                        .setIsPresent(false)
                        .build();
                res.onNext(r);
                res.onCompleted();
                return;
            }

            node.bidStorage.keySet().forEach(s -> {
                ListResponse r = ListResponse
                        .newBuilder()
                        .addAllRpcId(req.getRpcIdList())
                        .setKey(s)
                        .setIsPresent(true)
                        .build();
                res.onNext(r);
            });
            res.onCompleted();
        }

        @Override
        public void ping(NodeReq req, StreamObserver<Bool> res) {
            BucketRoutingTree.Id targetId = new BucketRoutingTree.Id(req.getTargetIdList());

            log("(IN) Ping " + targetId);

            if (targetId.equals(node.id)) {
                // I am the target
                Bool echoReply = Bool.newBuilder()
                        .addAllRpcId(req.getRpcIdList())
                        .setValue(true)
                        .build();
                res.onNext(echoReply);
                res.onCompleted();

                return;
            }

            boolean isAlive = node
                    .findNode(targetId)
                    .parallelStream()
                    .filter(n -> n.id.equals(targetId))
                    .limit(1)
                    .anyMatch(KademliaNode::ping);

            Bool echoReply = Bool.newBuilder()
                    .addAllRpcId(req.getRpcIdList())
                    .setValue(isAlive)
                    .build();
            res.onNext(echoReply);
            res.onCompleted();
        }

        @Override
        public void storeBid(StoreBidReq req, StreamObserver<Bool> res) {
            BucketRoutingTree.Id targetId = new BucketRoutingTree.Id(req.getTargetIdList());
            verify(req);

            GrpcBid val = req.getValue();
            Bid bid = serializeBid(val);
            node.bidStorage.put(targetId.toString(), bid);
            node.myBids.add(targetId.toString());
            //bid.print();

            Bool echoReply = Bool.newBuilder()
                    .addAllRpcId(req.getRpcIdList())
                    .setValue(true)
                    .build();
            res.onNext(echoReply);
            res.onCompleted();
        }

        @Override
        public void storeAuction(StoreAuctionReq req, StreamObserver<Bool> res) {
            BucketRoutingTree.Id targetId = new BucketRoutingTree.Id(req.getTargetIdList());
            verify(req);

            GrpcAuction val = req.getValue();
            Auction auction = serializeAuction(val);
            node.auctionStorage.put(targetId.toString(), auction);
            node.myAuctions.add(targetId.toString());
            //auction.print();

            Bool echoReply = Bool.newBuilder()
                    .addAllRpcId(req.getRpcIdList())
                    .setValue(true)
                    .build();
            res.onNext(echoReply);
            res.onCompleted();
        }

        @Override
        public void storeTransaction(StoreTransactionReq req, StreamObserver<Bool> res) {
            BucketRoutingTree.Id targetId = new BucketRoutingTree.Id(req.getTargetIdList());
            verify(req);

            log("storing transaction");
            GrpcTransaction val = req.getValue();
            Transaction transaction = serializeTransaction(val);
            log("serialized");
            node.transactionStorage.put(targetId.toString(), transaction);
            node.myTransactions.add(targetId.toString());
            //transaction.print();

            log("send bool");
            Bool echoReply = Bool.newBuilder()
                    .addAllRpcId(req.getRpcIdList())
                    .setValue(true)
                    .build();
            res.onNext(echoReply);
            res.onCompleted();
        }

        @Override
        public void store(StoreReq req, StreamObserver<Bool> res) {
            BucketRoutingTree.Id targetId = new BucketRoutingTree.Id(req.getTargetIdList());
            verify(req);

            GrpcBlock val = req.getValue();
            Block block = serializeBlock(val);
            node.storage.put(targetId.toString(), block);
            node.myBlocks.add(targetId.toString());
            //block.print();

            Bool echoReply = Bool.newBuilder()
                    .addAllRpcId(req.getRpcIdList())
                    .setValue(true)
                    .build();
            res.onNext(echoReply);
            res.onCompleted();
        }

        @Override
        public void findNode(NodeReq req, StreamObserver<FindNodeResponse> res) {
            BucketRoutingTree.Id targetId = new BucketRoutingTree.Id(req.getTargetIdList());
            log("(IN) FindNode " + targetId);
            verify(req);

            List<KademliaNode> l = node.router.getKClosest(targetId);

            boolean anyMatch = false;
            for (KademliaNode n : l) {
                if (!n.ping()) {
                    log("(IN) FindNode " + n.id + " is dead. Discarding...");
                    node.router.remove(n);
                    continue;
                }
                anyMatch = true;

                FindNodeResponse r = FindNodeResponse
                        .newBuilder()
                        .addAllRpcId(req.getRpcIdList())
                        .addAllTargetId(n.id)
                        .setIp(n.ip)
                        .setPort(n.port)
                        .setIsPresent(true)
                        .build();
                res.onNext(r);
            }

            if (!anyMatch) {
                FindNodeResponse r = FindNodeResponse
                        .newBuilder()
                        .addAllRpcId(req.getRpcIdList())
                        .setIsPresent(false)
                        .build();
                res.onNext(r);
            }

            res.onCompleted();
            log("(IN) FindNode lookup finished");

            storeRequesterNode(req);
        }

        @Override
        public void findAuctionValue(NodeReq req, StreamObserver<FindAuctionValueResponse> res) {
            log("(IN) Received findValue request...");
            verify(req);
            BucketRoutingTree.Id targetId = new BucketRoutingTree.Id(req.getTargetIdList());

            if (!node.auctionStorage.containsKey(targetId.toString())) {
                FindAuctionValueResponse r = FindAuctionValueResponse
                        .newBuilder()
                        .addAllRpcId(req.getRpcIdList())
                        .addAllTargetId(targetId)
                        .setIsPresent(false)
                        .setIp(node.ip)
                        .setPort(node.port)
                        .build();
                res.onNext(r);
                res.onCompleted();
                return;
            }

            FindAuctionValueResponse r = FindAuctionValueResponse
                    .newBuilder()
                    .addAllRpcId(req.getRpcIdList())
                    .addAllTargetId(targetId)
                    .setIsPresent(true)
                    .setValue(serializeAuction(node.auctionStorage.getOrDefault(targetId.toString(), null)))
                    .setIp(node.ip)
                    .setPort(node.port)
                    .build();
            res.onNext(r);
            res.onCompleted();
            log("(IN) FindValue finished");

            storeRequesterNode(req);
        }

        @Override
        public void findBidValue(NodeReq req, StreamObserver<FindBidValueResponse> res) {
            log("(IN) Received findValue request...");
            verify(req);
            BucketRoutingTree.Id targetId = new BucketRoutingTree.Id(req.getTargetIdList());

            if (!node.bidStorage.containsKey(targetId.toString())) {
                FindBidValueResponse r = FindBidValueResponse
                        .newBuilder()
                        .addAllRpcId(req.getRpcIdList())
                        .addAllTargetId(targetId)
                        .setIsPresent(false)
                        .setIp(node.ip)
                        .setPort(node.port)
                        .build();
                res.onNext(r);
                res.onCompleted();
                return;
            }

            FindBidValueResponse r = FindBidValueResponse
                    .newBuilder()
                    .addAllRpcId(req.getRpcIdList())
                    .addAllTargetId(targetId)
                    .setIsPresent(true)
                    .setValue(serializeBid(node.bidStorage.getOrDefault(targetId.toString(), null)))
                    .setIp(node.ip)
                    .setPort(node.port)
                    .build();
            res.onNext(r);
            res.onCompleted();
            log("(IN) FindValue finished");

            storeRequesterNode(req);
        }

        @Override
        public void findTransactionValue(NodeReq req, StreamObserver<FindTransactionValueResponse> res) {
            log("(IN) Received findValue request...");
            verify(req);
            BucketRoutingTree.Id targetId = new BucketRoutingTree.Id(req.getTargetIdList());

            if (!node.transactionStorage.containsKey(targetId.toString())) {
                FindTransactionValueResponse r = FindTransactionValueResponse
                        .newBuilder()
                        .addAllRpcId(req.getRpcIdList())
                        .addAllTargetId(targetId)
                        .setIsPresent(false)
                        .setIp(node.ip)
                        .setPort(node.port)
                        .build();
                res.onNext(r);
                res.onCompleted();
                return;
            }

            FindTransactionValueResponse r = FindTransactionValueResponse
                    .newBuilder()
                    .addAllRpcId(req.getRpcIdList())
                    .addAllTargetId(targetId)
                    .setIsPresent(true)
                    .setValue(serializeTransaction(node.transactionStorage.getOrDefault(targetId.toString(), null)))
                    .setIp(node.ip)
                    .setPort(node.port)
                    .build();
            res.onNext(r);
            res.onCompleted();
            log("(IN) FindValue finished");

            storeRequesterNode(req);
        }

        @Override
        public void findValue(NodeReq req, StreamObserver<FindValueResponse> res) {
            log("(IN) Received findValue request...");
            verify(req);
            BucketRoutingTree.Id targetId = new BucketRoutingTree.Id(req.getTargetIdList());

            if (!node.storage.containsKey(targetId.toString())) {
                FindValueResponse r = FindValueResponse
                        .newBuilder()
                        .addAllRpcId(req.getRpcIdList())
                        .addAllTargetId(targetId)
                        .setIsPresent(false)
                        .setIp(node.ip)
                        .setPort(node.port)
                        .build();
                res.onNext(r);
                res.onCompleted();
                return;
            }

            FindValueResponse r = null;
            try {
                r = FindValueResponse
                        .newBuilder()
                        .addAllRpcId(req.getRpcIdList())
                        .addAllTargetId(targetId)
                        .setIsPresent(true)
                        .setValue(serializeBlock(node.storage.getOrDefault(targetId.toString(), null)))
                        .setIp(node.ip)
                        .setPort(node.port)
                        .build();
            } catch (NullHashException e) {
                e.printStackTrace();
            }
            res.onNext(r);
            res.onCompleted();
            log("(IN) FindValue finished");

            storeRequesterNode(req);
        }

    }

}
