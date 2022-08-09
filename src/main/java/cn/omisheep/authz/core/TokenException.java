package cn.omisheep.authz.core;

/**
 * @author zhouxinchen
 * @since 1.2.1
 */
public class TokenException extends AuthzException {
    private static final long serialVersionUID = -7305238945386097964L;

    public TokenException() {
        super(ExceptionStatus.TOKEN_EXCEPTION);
    }
}
