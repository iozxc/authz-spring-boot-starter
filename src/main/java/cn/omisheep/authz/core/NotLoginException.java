package cn.omisheep.authz.core;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.5
 */
@SuppressWarnings("serial")
public class NotLoginException extends AuthzException {
    public NotLoginException() {
        super(ExceptionStatus.REQUIRE_LOGIN);
    }
}
