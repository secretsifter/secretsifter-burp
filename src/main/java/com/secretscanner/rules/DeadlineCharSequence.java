package com.secretscanner.rules;

/**
 * CharSequence wrapper that aborts a regex match once a deadline passes.
 *
 * java.util.regex has no timeout, but every step of a match reads the input through charAt(),
 * so checking the clock there bounds the time any single pattern can spend on hostile input
 * (catastrophic backtracking). The clock is read every {@value #CHECK_EVERY} reads to keep the
 * overhead negligible.
 */
public final class DeadlineCharSequence implements CharSequence {

    private static final int CHECK_EVERY = 1024;

    private final CharSequence inner;
    private final long deadlineNanos;
    private int reads;

    private DeadlineCharSequence(CharSequence inner, long deadlineNanos) {
        this.inner = inner;
        this.deadlineNanos = deadlineNanos;
    }

    /** Wraps {@code text} so matching it throws {@link RegexTimeoutException} after {@code millis}. */
    public static DeadlineCharSequence of(CharSequence text, long millis) {
        return new DeadlineCharSequence(text, System.nanoTime() + millis * 1_000_000L);
    }

    /** Wraps {@code text} with an absolute deadline in {@link System#nanoTime()} units. */
    public static DeadlineCharSequence until(CharSequence text, long deadlineNanos) {
        return new DeadlineCharSequence(text, deadlineNanos);
    }

    @Override
    public char charAt(int index) {
        if (++reads % CHECK_EVERY == 0 && System.nanoTime() > deadlineNanos) {
            throw new RegexTimeoutException();
        }
        return inner.charAt(index);
    }

    @Override public int length() { return inner.length(); }

    @Override
    public CharSequence subSequence(int start, int end) {
        return new DeadlineCharSequence(inner.subSequence(start, end), deadlineNanos);
    }

    @Override public String toString() { return inner.toString(); }

    /** Thrown when a match runs past its deadline. */
    public static final class RegexTimeoutException extends RuntimeException {
        public RegexTimeoutException() { super("regex match exceeded its time budget", null, false, false); }
    }
}
