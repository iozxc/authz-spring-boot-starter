package cn.omisheep.authz.core;

import lombok.Getter;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
@Getter
public enum RequestExceptionStatus {
    ACCESS_TOKEN_OVERDUE(2, "AccessToken overdue"),

    REQUIRE_LOGIN(-1, "Require login"),
    PERM_EXCEPTION(-2, "Insufficient permissions"),
    REQUEST_REPEAT(-3, "Request repeat error"),
    EXPIRED_JWT_EXCEPTION(-4, "Token Expired exception"),
    TOKEN_EXCEPTION(-6, "Token exception"),
    LOGIN_EXCEPTION(-7, "You are offline, or you may have logged in elsewhere"),
    LOGIN_ERROR(-8, "Login error"),
    PATH_ERROR(-9, "Path error"),
    CONTENT_TYPE_ERROR(-10, "Content type not supported, must be json");

    private final int code;
    private final String msg;

    RequestExceptionStatus(int code, String msg) {
        this.code = code;
        this.msg = msg;
    }
}
