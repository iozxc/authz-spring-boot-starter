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
    ACCESS_TOKEN_OVERDUE(-102, "AccessToken overdue", true, NETWORK_AUTHENTICATION_REQUIRED),
    PERM_EXCEPTION(-103, "Insufficient permissions", false, NETWORK_AUTHENTICATION_REQUIRED),

    TOKEN_EXCEPTION(-201, "Token exception", true, FORBIDDEN),
    REQUEST_REPEAT(-202, "Request repeat error", false, TOO_MANY_REQUESTS),
    LOGIN_EXCEPTION(-203, "You are offline, or you may have logged in elsewhere", true, FORBIDDEN),

    CONTENT_TYPE_ERROR(-301, "Content type not supported, must be json", false, INTERNAL_SERVER_ERROR),
    PAGE_NOT_SUPPORT(-302, "Page not support, check database type, only mysql and oracle", false, INTERNAL_SERVER_ERROR);

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
