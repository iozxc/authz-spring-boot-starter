package cn.omisheep.authz.core;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.10
 */
@SuppressWarnings("serial")
public class RefreshTokenExpiredException extends AuthzException {
    public RefreshTokenExpiredException() {
        super(ExceptionStatus.REFRESH_TOKEN_EXPIRED_EXCEPTION);
    }
}
