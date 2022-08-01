package cn.omisheep.authz.core;

import org.springframework.http.HttpStatus;

import static org.springframework.http.HttpStatus.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public enum ExceptionStatus {
    UNKNOWN(-99999, "unknown", false, INTERNAL_SERVER_ERROR),

    MISMATCHED_URL(-100, "URL matching failed", false, NOT_FOUND),

    REQUIRE_LOGIN(-101, "Require login", true, NETWORK_AUTHENTICATION_REQUIRED),
    PERM_EXCEPTION(-102, "Insufficient permissions", false, NETWORK_AUTHENTICATION_REQUIRED),
    ACCESS_TOKEN_OVERDUE(-103, "AccessToken overdue", true, NETWORK_AUTHENTICATION_REQUIRED),
    REFRESH_TOKEN_EXPIRED_EXCEPTION(-104, "RefreshToken expired", true, NETWORK_AUTHENTICATION_REQUIRED),
    TOKEN_EXCEPTION(-104, "Token exception", true, FORBIDDEN),

    REQUEST_REPEAT(-202, "Request repeat error", false, TOO_MANY_REQUESTS),
    LOGIN_EXCEPTION(-203, "You are offline, or you may have logged in elsewhere", true, FORBIDDEN),
    /**
     * @since 1.1.0
     */
    REQUEST_EXCEPTION(-204, "Request error", false, FORBIDDEN),

    CONTENT_TYPE_ERROR(-301, "Content type not supported, must be json", false, INTERNAL_SERVER_ERROR),
    PAGE_NOT_SUPPORT(-302, "Page not support, check database type, only mysql and oracle", false,
                     INTERNAL_SERVER_ERROR),

    WEB_ENVIRONMENT(-401, "The current thread is in a non Web Environment", false, INTERNAL_SERVER_ERROR),

    PRIVILEGE_GRANT_FAILED(-500, "Grant failed, not login or client id does not exist", false, OK), // 授权失败
    CLIENT_SECRET_ERROR(-501, "Client secret error or client id not match", false, OK), // 客户端密钥错误
    CLIENT_NOT_EXIST(-502, "Client not exist", false, OK),//客户端不存在
    AUTHORIZATION_CODE_EXPIRED_OR_NOT_EXIST(-503, "Authorization code does not exist or expires",
                                            false, OK), // 授权码过期或无效
    SCOPE_EXCEPTION(-504, "Insufficient scope of authorization", false, NETWORK_AUTHENTICATION_REQUIRED);


    private final int        code;
    private final String     message;
    private final boolean    clearToken;
    private final HttpStatus httpStatus;

    ExceptionStatus(int code, String message, boolean clearToken, HttpStatus httpStatus) {
        this.code       = code;
        this.message    = message;
        this.clearToken = clearToken;
        this.httpStatus = httpStatus;
    }

    ExceptionStatus(int code, String message, HttpStatus httpStatus) {
        this.code       = code;
        this.message    = message;
        this.clearToken = false;
        this.httpStatus = httpStatus;
    }

    ExceptionStatus(HttpStatus httpStatus) {
        this.code       = httpStatus.value();
        this.message    = httpStatus.getReasonPhrase();
        this.clearToken = false;
        this.httpStatus = httpStatus;
    }

    public int getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }

    public boolean isClearToken() {
        return clearToken;
    }
}
