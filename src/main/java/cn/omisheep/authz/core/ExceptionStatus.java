package cn.omisheep.authz.core;

import org.springframework.http.HttpStatus;

import static org.springframework.http.HttpStatus.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public enum ExceptionStatus {
    UNKNOWN(100, "unknown", INTERNAL_SERVER_ERROR),

    MISMATCHED_URL(200, "URL matching failed", NOT_FOUND),

    ACCESS_TOKEN_OVERDUE(300, "AccessToken overdue", NETWORK_AUTHENTICATION_REQUIRED),
    REQUIRE_LOGIN(301, "Require login", NETWORK_AUTHENTICATION_REQUIRED),
    PERM_EXCEPTION(302, "Insufficient permissions", NETWORK_AUTHENTICATION_REQUIRED),

    TOKEN_EXCEPTION(400, "Token exception", FORBIDDEN),
    REQUEST_REPEAT(401, "Request repeat error", TOO_MANY_REQUESTS),
    LOGIN_EXCEPTION(402, "You are offline, or you may have logged in elsewhere", FORBIDDEN),

    CONTENT_TYPE_ERROR(500, "Content type not supported, must be json", INTERNAL_SERVER_ERROR),
    PAGE_NOT_SUPPORT(501, "Page not support, check database type, only mysql and oracle", INTERNAL_SERVER_ERROR);

    private final int code;
    private final String message;
    private final HttpStatus httpStatus;

    ExceptionStatus(int code, String message, HttpStatus httpStatus) {
        this.code = code;
        this.message = message;
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
}
