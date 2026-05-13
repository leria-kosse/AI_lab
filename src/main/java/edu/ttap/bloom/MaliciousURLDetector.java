package edu.ttap.bloom;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Function;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;

/**
 * A simple malicious URL detector program that utilizes a Bloom Filter and a
 * dataset of known malicious URLs to efficiently check whether a URL is
 * potentially malicious.
 */
public class MaliciousURLDetector {

    // From: https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset
    public static final String DATA_PATH = "data/malicious_phish.csv";

    /**
     * Creates a list of <code>num</code> string hash functions utilizing the
     * Murmur3 hashing algorithm.
     * @param num the number of hash functions
     * @return a list of <code>num</code> string hash functions
     */
    public static List<Function<String, Integer>> makeStringHashFunctions(int num) {
        List<Function<String, Integer>> functions = new ArrayList<>();
        for (int i = 0; i < num; i++) {
            int seed = ThreadLocalRandom.current().nextInt();
            HashFunction hashFunction = Hashing.murmur3_128(seed);
            Function<String, Integer> f = input ->
                    hashFunction.hashString(input, Charset.defaultCharset()).asInt();
            functions.add(f);
        }
        return functions;
    }

    /**
     * @param filename the path to the CSV file
     * @param bitSetSize the number of bits dedicated to the filter
     * @param numHashFunctions the number of hash functions to use
     * @return a Bloom filter for detecting malicious URLs.
     * @throws IOException if the file cannot be read
     */
    public static BloomFilter<String> makeURLFilter(
            String filename, int bitSetSize, int numHashFunctions)
            throws IOException {
        List<Function<String, Integer>> hashFunctions = makeStringHashFunctions(numHashFunctions);
        BloomFilter<String> filter = new BloomFilter<>(bitSetSize, hashFunctions);
        List<String> lines = Files.readAllLines(Path.of(filename));
        for (String line : lines) {
            if (line.equals("url,type")) {
                continue;
            }
            String[] parts = line.split(",");
            if (parts.length >= 2) {
                String url = parts[0];
                String type = parts[1];
                if (!type.equals("benign")) {
                    filter.add(url);
                }
            }
        }
        return filter;
    }

    /**
     * The main method for the program.
     * @param args the arguments to the program
     * @throws IOException if the data file cannot be read
     */
    public static void main(String[] args) throws IOException {
        if (args.length != 2) {
            System.out.println(
                "Usage: mvn compile exec:java -Dexec.args=\"<bitset size> <# hash functions>\"");
            return;
        }
        int bitSetSize = Integer.parseInt(args[0]);
        int numHashFunctions = Integer.parseInt(args[1]);
        BloomFilter<String> filter =
                makeURLFilter("data/malicious_phish.csv", bitSetSize, numHashFunctions);
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.println("Enter a URL to check (or \"exit\" to quit):");
            System.out.print("> ");
            String input = scanner.nextLine();
            if (input.equals("exit")) {
                break;
            }
            if (filter.contains(input)) {
                System.out.println("The URL is possibly malicious!!!");
            } else {
                System.out.println("The URL is not known to be malicious...");
            }
        }
        scanner.close();
    }
}