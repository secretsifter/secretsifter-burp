package com.secretscanner.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/**
 * One secret value and every place it was seen.
 *
 * A finding is one occurrence (rule, value, URL, line, offset). Reports and the UI usually want
 * one row per secret with its locations listed, so occurrences are grouped by the fingerprint of
 * their value. Generic over the finding type so it has no dependency on the Burp-facing record.
 *
 * @param <F> finding type
 */
public record SecretGroup<F>(
        String  fingerprint,   // IssueRegistry.fingerprint(value): keyed, normalized
        F       representative,// first occurrence seen (stable order)
        List<F> occurrences,   // all occurrences, in input order
        Set<String> locations  // distinct source URLs, in input order
) {
    public SecretGroup {
        occurrences = List.copyOf(occurrences);
        locations   = java.util.Collections.unmodifiableSet(new LinkedHashSet<>(locations));
    }

    public int count() { return occurrences.size(); }

    /**
     * Groups occurrences by the fingerprint of their value, keeping first-seen order.
     *
     * @param value    extracts the secret value from a finding
     * @param location extracts the source URL from a finding
     */
    public static <F> List<SecretGroup<F>> group(List<F> findings,
                                                Function<F, String> value,
                                                Function<F, String> location) {
        Map<String, List<F>> byFp = new LinkedHashMap<>();
        for (F f : findings) byFp.computeIfAbsent(IssueRegistry.fingerprint(value.apply(f)), k -> new ArrayList<>()).add(f);

        List<SecretGroup<F>> out = new ArrayList<>(byFp.size());
        for (Map.Entry<String, List<F>> e : byFp.entrySet()) {
            Set<String> locs = new LinkedHashSet<>();
            for (F f : e.getValue()) {
                String loc = location.apply(f);
                if (loc != null && !loc.isEmpty()) locs.add(loc);
            }
            out.add(new SecretGroup<>(e.getKey(), e.getValue().get(0), e.getValue(), locs));
        }
        return out;
    }
}
