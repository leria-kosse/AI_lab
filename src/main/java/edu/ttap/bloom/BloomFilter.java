package edu.ttap.bloom;

import java.util.BitSet;
import java.util.List;
import java.util.function.Function;

/**
 * A Bloom Filter is a probabilistic data structure that efficiently tests
 * set membership with the possibility of false positives.
 */
public class BloomFilter<T> {

    private BitSet bits;

    private int size;

    private List<Function<T, Integer>> hashFunctions;

    /**
     * @param size the number of bits in the filter
     * @param hashFunctions the list of hash functions to use
     */
    public BloomFilter(int size, List<Function<T, Integer>> hashFunctions) {
        this.size = size;
        this.bits = new BitSet(size);
        this.hashFunctions = hashFunctions;
    }

    /** @param item the item to add to the Bloom Filter */
    public void add(T item) {
        for (Function<T, Integer> hashFunction : hashFunctions) {
            int hash = hashFunction.apply(item);
            int index = Math.floorMod(hash, size);
            bits.set(index);
        }
    }

    /**
     * @param item the item to check for membership in the Bloom filter
     * @return true if the item is (possibly) in the Bloom filter and false if
     *     it is definitely not in the filter.
     */
    public boolean contains(T item) {
        for (Function<T, Integer> hashFunction : hashFunctions) {
            int hash = hashFunction.apply(item);
            int index = Math.floorMod(hash, size);
            if (!bits.get(index)) {
                return false;
            }
        }
        return true;
    }
}