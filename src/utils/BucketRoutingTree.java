package fcup.utils;

import fcup.KademliaNode;
import io.grpc.StatusRuntimeException;

import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;

public class BucketRoutingTree {
    // Environment options
    public static int k = 20;
    public static int alpha = 3;
    public final ArrayList<ConcurrentLinkedQueue<KademliaNode>> buckets;
    private final KademliaNode owner;
    public BucketRoutingTree(KademliaNode owner) {

        int bitLength = Integer.BYTES * 8 * Id.maxChunkCount;
        buckets = new ArrayList<>(bitLength);

        for (int i = 0; i < bitLength; i++) {
            buckets.add(new ConcurrentLinkedQueue<>());
        }

        this.owner = owner;
    }

    public static Id distance(Id node1, Id node2) {
        node1.extend(node2.chunkCount());
        node2.extend(node1.chunkCount());

        ArrayList<Integer> distance = new ArrayList<>(node1.chunkCount());
        for (int i = 0; i < node1.chunkCount(); i++) {
            distance.add(node1.getChunk(i) ^ node2.getChunk(i));
        }
        return new Id(distance);
    }

    public int size() {
        int counter = 0;
        for (ConcurrentLinkedQueue<KademliaNode> b : buckets) {
            counter += b.size();
        }
        return counter;
    }

    public boolean isEmpty() {
        return size() <= 0;
    }

    public void remove(KademliaNode n) {
        int i = distance(n.id, owner.id).toPowerOfTwo();
        ConcurrentLinkedQueue<KademliaNode> b = buckets.get(i);
        LinkedList<KademliaNode> res = new LinkedList<>();
        for (KademliaNode kademliaNode : b) {
            if (!kademliaNode.equals(n)) {
                res.add(kademliaNode);
            }
        }
        buckets.set(i, new ConcurrentLinkedQueue<>(res));
    }

    public KademliaNode put(int i, KademliaNode n) {

        ConcurrentLinkedQueue<KademliaNode> bucket = buckets.get(i);

        for (KademliaNode bn : bucket) {

            if (!bn.equals(n)) {
                continue;
            }

            bucket.remove(bn);
            bucket.add(bn);

            return bn;
        }

        if (bucket.size() < k) {
            bucket.add(n);
            return n;
        }

        KademliaNode first = bucket.poll();
        if (first != null && first.ping()) {
            bucket.add(first);
            return n;
        }

        bucket.add(n);
        return n;
    }

    private List<KademliaNode> quickSort(BucketRoutingTree.Id target, List<KademliaNode> to, int l, int r) {
        int right = r;
        while (l < right) {
            // partition
            KademliaNode pivot = to.get(right);
            Id distanceFromPivot = distance(pivot.id, target);
            int j = l;
            for (int i = l; i < right; i++) {
                if (distanceFromPivot.compare(distance(to.get(i).id, target)) > 0) {
                    continue;
                }
                KademliaNode n1 = to.get(i);
                to.set(i, to.get(j));
                to.set(j, n1);
                j++;
            }
            KademliaNode n1 = to.get(to.size() - 1);
            to.set(to.size() - 1, to.get(j));
            to.set(j, n1);

            quickSort(target, to, j + 1, right);
            right = j - 1;
        }

        return to;
    }

    private List<KademliaNode> quickSort(BucketRoutingTree.Id target, List<KademliaNode> to) {
        return quickSort(target, to, 0, to.size() - 1);
    }

    public List<KademliaNode> getKClosest(BucketRoutingTree.Id target) {
        ArrayList<KademliaNode> buffer = new ArrayList<>();
        for (ConcurrentLinkedQueue<KademliaNode> l : buckets) {
            buffer.addAll(l);
        }
        quickSort(target, buffer);

        return buffer.stream()
                .distinct()
                .limit(k)
                .collect(Collectors.toList());
    }
    public List<KademliaNode> loop() {
        ArrayList<KademliaNode> all = new ArrayList<>();
        for (ConcurrentLinkedQueue<KademliaNode> l : buckets) {
            all.addAll(l);
        }
        return all;
    }

    public List<KademliaNode> lookup(BucketRoutingTree.Id target) {

        List<KademliaNode> queried = new LinkedList<>();
        queried.add(owner);

        List<KademliaNode> bucket = getKClosest(target);

        bucket = bucket.stream()
                .limit(alpha)
                .collect(Collectors.toList());

        // ROUND 1
        ConcurrentLinkedQueue<KademliaNode> result = new ConcurrentLinkedQueue<>(bucket);
        bucket.parallelStream().forEach(n -> {
            queried.add(n);

            List<KademliaNode> current;
            try {
                current = n.findNode(target);
                if (current != null) {
                    result.addAll(current);
                }

            } catch (StatusRuntimeException e) {
                KademliaNode.log("Node " + n.id + " is dead. Discarding...");
                remove(n);
            }

        });

        // ROUND 2
        List<KademliaNode> sort = new ArrayList<>(result);
        quickSort(target, sort);

        List<KademliaNode> round2 = sort
                .stream()
                .distinct()
                .limit(k)
                .collect(Collectors.toList());

        round2.parallelStream().forEach(n -> {
            if (!queried.contains(n)) {
                queried.add(n);

                List<KademliaNode> current;
                try {
                    current = n.findNode(target);
                    if (current != null) {
                        result.addAll(current);
                    }

                } catch (StatusRuntimeException e) {
                    KademliaNode.log("Node " + n.id + " is dead. Discarding...");
                    remove(n);
                }
            }
        });

        sort = new ArrayList<>(result);
        quickSort(target, sort);

//        System.out.println("LOOKUP LOOP");
        return sort
                .stream()
                .filter(n -> !n.equals(owner))
                .distinct()
                .limit(k)
                .collect(Collectors.toList());
    }

    public KademliaNode put(KademliaNode kademliaNode) {
        int i = distance(kademliaNode.id, owner.id).toPowerOfTwo();
        return put(i, kademliaNode);
    }

    @Override
    public String toString() {
        StringBuilder bd = new StringBuilder();
        for (int i = 0; i < buckets.size(); i++) {
            if (buckets.get(i).size() <= 0) {
                continue;
            }
            bd.append(i).append(": ");
            for (KademliaNode n : buckets.get(i)) {
                bd.append(n.id).append(" ");
            }
            bd.append("\n");
        }
        return bd.deleteCharAt(bd.length() - 1).toString();
    }

    public static class Id implements Iterable<Integer> {
        // using 160 bits, as is written in the paper
        public static final int maxChunkCount = 8;
        private ArrayList<Integer> chunks = new ArrayList<>(maxChunkCount);

        public Id(Collection<Integer> c) {
            chunks.addAll(c);
        }

        public Id(byte[] bytes) {
//            if (bytes.length % 4 != 0) {
//                KademliaNode.err("Byte array not divisible by 4");
//                return;
//            }

            ArrayList<Integer> converted = new ArrayList<>();
            if (bytes.length > maxChunkCount * Integer.BYTES) {
                for (int i = 0; i < maxChunkCount * Integer.BYTES; i += 4) {
                    converted.add(bytes[i] << 24 |
                            (bytes[i + 1] & 0xFF) << 16 |
                            (bytes[i + 2] & 0xFF) << 8 |
                            (bytes[i + 3] & 0xFF));
                }

                chunks.addAll(converted);
                return;
            }

            for (int i = 0; i < bytes.length; i += 4) {
                if (bytes.length < i + 4) {
                    break;
                }
                converted.add(bytes[i] << 24 |
                        (bytes[i + 1] & 0xFF) << 16 |
                        (bytes[i + 2] & 0xFF) << 8 |
                        (bytes[i + 3] & 0xFF));
            }
            chunks.addAll(converted);
        }

        // using 160 bit length IDs
        public static Id rootId() {
            ArrayList<Integer> acc = new ArrayList<>(maxChunkCount);
            for (int i = 0; i < maxChunkCount; i++) {
                acc.add(0);
            }
            return new Id(acc);
        }

        public boolean isRoot() {
            return rootId().equals(this);
        }

        public static Id randomId() {
            ArrayList<Integer> acc = new ArrayList<>(maxChunkCount);
            for (int i = 0; i < maxChunkCount; i++) {
                int chunk = ThreadLocalRandom.current().nextInt();
                acc.add(chunk);
            }
            return new Id(acc);
        }

        public boolean equalsToList(List<Integer> l) {
            return new Id(l).equals(this);
        }

        public int chunkCount() {
            return chunks.size();
        }

        public void extend(int newChunkSize) {
            if (newChunkSize <= chunkCount()) {
                return;
            }

            ArrayList<Integer> newChunks = new ArrayList<>();
            for (int i = 0; i < newChunkSize - chunkCount(); i++) {
                // zero fill
                newChunks.add(0);
            }
            newChunks.addAll(chunks);
            chunks = newChunks;
        }

        public int getChunk(int i) {
            return chunks.get(i);
        }

        public int bitLength() {
            return Integer.BYTES * 8 * chunkCount();
        }

        public boolean equals(Id otherId) {
            if (otherId.chunkCount() != chunkCount()) {
                return false;
            }

            for (int i = 0; i < chunkCount(); i++) {
                if (otherId.getChunk(i) != getChunk(i)) {
                    return false;
                }
            }
            return true;
        }

        public int compare(Id target) {
            if (target.chunkCount() == chunkCount()) {
                for (int i = 0; i < chunkCount(); i++) {
                    if (target.getChunk(i) == getChunk(i)) {
                        continue;
                    }
                    return target.getChunk(i) - getChunk(i);
                }
                return 0;
            }

            return chunkCount() - target.chunkCount();
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            for (int c : chunks) {
                sb.append(Integer.toUnsignedLong(c));
                sb.append(",");
            }
            return sb.toString();
        }

        public static Id fromString(String s) {
            ArrayList<Integer> l = new ArrayList<>();
            for (String ss : s.split(",")) {
                if (ss.isEmpty() || ss.equals(",")) continue;
                l.add(Integer.parseUnsignedInt(ss));
            }
            return new Id(l);
        }

        public int toPowerOfTwo() {
            for (int i = 0; i < chunkCount(); i++) {
                int chunk = getChunk(i);
                if (chunk == 0) {
                    continue;
                }

                int intBitLen = Integer.BYTES * 8;
                int chunkSignificance = chunkCount() - i;
                for (int j = 0; j < intBitLen; j++) {
                    if (chunk >>> j == 0) {
                        return j + (intBitLen - 1) * (chunkSignificance - 1);
                    }
                }
                return (intBitLen - 1) * chunkSignificance;
            }
            return 1;
        }

        @Override
        public Iterator<Integer> iterator() {
            return chunks.iterator();
        }
    }

}
