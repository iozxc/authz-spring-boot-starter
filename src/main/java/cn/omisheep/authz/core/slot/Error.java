package cn.omisheep.authz.core.slot;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.1.0
 */
@FunctionalInterface
public interface Error {
    void error(Object... error);

    default void stop() {}
}
