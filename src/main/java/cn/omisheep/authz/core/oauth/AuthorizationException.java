package cn.omisheep.authz.core.oauth;

import cn.omisheep.authz.core.AuthzException;
import cn.omisheep.authz.core.ExceptionStatus;

/**
 * 用户未登录或客户端id不存在
 *
 * @author zhouxinchen
 * @since 1.2.0
 */
@SuppressWarnings("serial")
public class AuthorizationException extends AuthzException {

    public AuthorizationException(ExceptionStatus exceptionStatus) {
        super(exceptionStatus);
    }

    public static AuthorizationException privilegeGrantFailed() {
        return new AuthorizationException(ExceptionStatus.PRIVILEGE_GRANT_FAILED);
    }

    public static AuthorizationException clientSecretError() {
        return new AuthorizationException(ExceptionStatus.CLIENT_SECRET_ERROR);
    }

    public static AuthorizationException clientNotExist() {
        return new AuthorizationException(ExceptionStatus.CLIENT_NOT_EXIST);
    }

    public static AuthorizationException authorizationCodeExpiredOrNotExist() {
        return new AuthorizationException(ExceptionStatus.AUTHORIZATION_CODE_EXPIRED_OR_NOT_EXIST);
    }

}
