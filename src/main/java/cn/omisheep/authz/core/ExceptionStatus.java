package cn.omisheep.authz.core;

import org.springframework.http.HttpStatus;

import static org.springframework.http.HttpStatus.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public enum ExceptionStatus {
    UNKNOWN(-1, "unknown", INTERNAL_SERVER_ERROR),

    MISMATCHED_URL(-2, "URL matching failed", NOT_FOUND),

    ACCESS_TOKEN_OVERDUE(2, "AccessToken overdue"),
    REQUIRE_LOGIN(-1, "Require login"),
    PERM_EXCEPTION(-2, "Insufficient permissions"),
    REQUEST_REPEAT(-3, "Request repeat error"),
    TOKEN_EXCEPTION(-6, "Token exception"),
    LOGIN_EXCEPTION(-7, "You are offline, or you may have logged in elsewhere"),

    CONTENT_TYPE_ERROR(-10, "Content type not supported, must be json", INTERNAL_SERVER_ERROR);

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
