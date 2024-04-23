package net.bplearning.ntag424.util;

public interface ThrowableFunction <T, R, E extends Throwable> {
    public R apply(T input) throws E;
}