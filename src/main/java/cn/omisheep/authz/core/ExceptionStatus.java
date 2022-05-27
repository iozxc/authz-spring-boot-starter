package cn.omisheep.authz.core;

import org.springframework.http.HttpStatus;

import static org.springframework.http.HttpStatus.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public enum ExceptionStatus {
    UNKNOWN(100, "unknown", false, INTERNAL_SERVER_ERROR),

    MISMATCHED_URL(200, "URL matching failed", false, NOT_FOUND),

    ACCESS_TOKEN_OVERDUE(300, "AccessToken overdue", true, NETWORK_AUTHENTICATION_REQUIRED),
    REQUIRE_LOGIN(301, "Require login", true, NETWORK_AUTHENTICATION_REQUIRED),
    PERM_EXCEPTION(302, "Insufficient permissions", false, NETWORK_AUTHENTICATION_REQUIRED),

    TOKEN_EXCEPTION(400, "Token exception", true, FORBIDDEN),
    REQUEST_REPEAT(401, "Request repeat error", false, TOO_MANY_REQUESTS),
    LOGIN_EXCEPTION(402, "You are offline, or you may have logged in elsewhere", true, FORBIDDEN),

    CONTENT_TYPE_ERROR(500, "Content type not supported, must be json", false, INTERNAL_SERVER_ERROR),
    PAGE_NOT_SUPPORT(501, "Page not support, check database type, only mysql and oracle", false, INTERNAL_SERVER_ERROR);

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
