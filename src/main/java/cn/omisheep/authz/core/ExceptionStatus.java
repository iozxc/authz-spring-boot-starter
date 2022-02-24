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

    MISMATCHED_URL(201, "URL matching failed", NOT_FOUND),

    ACCESS_TOKEN_OVERDUE(301, "AccessToken overdue", NETWORK_AUTHENTICATION_REQUIRED),
    REQUIRE_LOGIN(302, "Require login", NETWORK_AUTHENTICATION_REQUIRED),
    PERM_EXCEPTION(303, "Insufficient permissions", NETWORK_AUTHENTICATION_REQUIRED),

    TOKEN_EXCEPTION(401, "Token exception", FORBIDDEN),
    REQUEST_REPEAT(402, "Request repeat error", FORBIDDEN),
    LOGIN_EXCEPTION(403, "You are offline, or you may have logged in elsewhere", FORBIDDEN),

    CONTENT_TYPE_ERROR(501, "Content type not supported, must be json", INTERNAL_SERVER_ERROR);

    private final int code;
    private final String message;
    private final HttpStatus httpStatus;

    ExceptionStatus(int code, String message) {
        this(code, message, INTERNAL_SERVER_ERROR);
    }

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
