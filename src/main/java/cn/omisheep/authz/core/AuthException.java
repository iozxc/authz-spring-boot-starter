package cn.omisheep.authz.core;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public class AuthException extends RuntimeException {
    public AuthException(String message) {
        super(message);
    }
}
