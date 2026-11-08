package com.secretscanner.rules;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;
import java.util.Queue;

/**
 * Finds, in one pass over a response, which rules' keywords occur in it (Aho-Corasick).
 *
 * Rules are identified by index. A rule with no keywords is always reported as present, as is
 * any rule with a non-ASCII keyword (the automaton is ASCII-only; such a rule simply always runs).
 * Matching is case-insensitive: keywords are lowercase and each input char is lowercased as it is
 * read, so no lowercase copy of the body is allocated.
 *
 * Immutable and thread-safe after construction.
 */
public final class KeywordPrefilter {

    private static final int ALPHABET = 128;

    private final int ruleCount;
    private final BitSet alwaysOn;     // rules that run regardless of the text
    private final int[][] delta;       // full DFA: delta[state][ascii char] -> next state
    private final int[][] outputs;     // outputs[state] = rule indices whose keyword ends here

    /** @param keywordsPerRule keywords for rule i at index i (empty list = always run) */
    public KeywordPrefilter(List<List<String>> keywordsPerRule) {
        this.ruleCount = keywordsPerRule.size();
        this.alwaysOn = new BitSet(ruleCount);

        // 1. trie
        List<int[]> next = new ArrayList<>();
        List<BitSet> out = new ArrayList<>();
        next.add(newRow());
        out.add(new BitSet());
        for (int rule = 0; rule < ruleCount; rule++) {
            List<String> kws = keywordsPerRule.get(rule);
            if (kws.isEmpty() || kws.stream().anyMatch(k -> k.isEmpty() || !isAscii(k))) {
                alwaysOn.set(rule);
                continue;
            }
            for (String kw : kws) {
                int s = 0;
                for (int i = 0; i < kw.length(); i++) {
                    int c = Character.toLowerCase(kw.charAt(i));
                    if (next.get(s)[c] < 0) {
                        next.get(s)[c] = next.size();
                        next.add(newRow());
                        out.add(new BitSet());
                    }
                    s = next.get(s)[c];
                }
                out.get(s).set(rule);
            }
        }

        // 2. failure links (BFS) folded into a complete transition table
        int n = next.size();
        int[] fail = new int[n];
        delta = new int[n][];
        delta[0] = new int[ALPHABET];
        Queue<Integer> queue = new ArrayDeque<>();
        for (int c = 0; c < ALPHABET; c++) {
            int t = next.get(0)[c];
            if (t > 0) { delta[0][c] = t; fail[t] = 0; queue.add(t); }
            else delta[0][c] = 0;
        }
        while (!queue.isEmpty()) {
            int s = queue.poll();
            out.get(s).or(out.get(fail[s]));
            delta[s] = new int[ALPHABET];
            for (int c = 0; c < ALPHABET; c++) {
                int t = next.get(s)[c];
                if (t > 0) {
                    delta[s][c] = t;
                    fail[t] = delta[fail[s]][c];
                    queue.add(t);
                } else {
                    delta[s][c] = delta[fail[s]][c];
                }
            }
        }

        outputs = new int[n][];
        for (int s = 0; s < n; s++) outputs[s] = out.get(s).stream().toArray();
    }

    /** Rules that may match {@code text}: every always-on rule plus every rule whose keyword occurs. */
    public BitSet candidates(CharSequence text) {
        BitSet hit = (BitSet) alwaysOn.clone();
        int remaining = ruleCount - hit.cardinality();
        int s = 0;
        for (int i = 0, len = text.length(); i < len && remaining > 0; i++) {
            char ch = text.charAt(i);
            if (ch >= ALPHABET) { s = 0; continue; }
            s = delta[s][Character.toLowerCase(ch)];
            for (int rule : outputs[s]) {
                if (!hit.get(rule)) { hit.set(rule); remaining--; }
            }
        }
        return hit;
    }

    public int ruleCount() { return ruleCount; }

    private static int[] newRow() {
        int[] row = new int[ALPHABET];
        Arrays.fill(row, -1);
        return row;
    }

    private static boolean isAscii(String s) {
        for (int i = 0; i < s.length(); i++) if (s.charAt(i) >= ALPHABET) return false;
        return true;
    }
}
