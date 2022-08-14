package cn.omisheep.authz.core;

import cn.omisheep.web.entity.IResponseResult;
import org.springframework.http.HttpStatus;

import static org.springframework.http.HttpStatus.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public enum ExceptionStatus implements IResponseResult {

    /**
     * 未登录
     */
    REQUIRE_LOGIN(-101, "Require login", true, NETWORK_AUTHENTICATION_REQUIRED),

    /**
     * 权限不足
     */
    PERM_EXCEPTION(-102, "Insufficient permissions", false, NETWORK_AUTHENTICATION_REQUIRED),

    /**
     * AccessToken过期
     */
    ACCESS_TOKEN_OVERDUE(-103, "AccessToken overdue", true, NETWORK_AUTHENTICATION_REQUIRED),

    /**
     * RefreshToken过期
     */
    REFRESH_TOKEN_EXPIRED_EXCEPTION(-104, "RefreshToken expired", false, NETWORK_AUTHENTICATION_REQUIRED),

    /**
     * token解析异常
     */
    TOKEN_EXCEPTION(-104, "Token exception", true, FORBIDDEN),

    /**
     * 请求重复
     */
    REQUEST_REPEAT(-202, "Request repeat error", false, TOO_MANY_REQUESTS),

    /**
     * 账号在别处登录
     */
    LOGIN_EXCEPTION(-203, "You are offline, or you may have logged in elsewhere", true, FORBIDDEN),

    /**
     * 请求错误（拒绝）
     */
    REQUEST_EXCEPTION(-204, "Request error", false, FORBIDDEN),

    /**
     * contentType不支持
     */
    CONTENT_TYPE_ERROR(-301, "Content type not supported, must be json", false, INTERNAL_SERVER_ERROR),

    /**
     * 数据库不支持
     */
    PAGE_NOT_SUPPORT(-302, "Page not support, check database type, only mysql and oracle",
                     false, INTERNAL_SERVER_ERROR),

    /**
     * 当前线程未绑定request
     */
    WEB_ENVIRONMENT(-401, "The current thread is in a non Web Environment", false, INTERNAL_SERVER_ERROR),

    /**
     * 授权失败
     */
    PRIVILEGE_GRANT_FAILED(-500, "Grant failed, not login or client id does not exist", false, OK),

    /**
     * 客户端密钥错误
     */
    CLIENT_SECRET_ERROR(-501, "Client secret error or client id not match", false, OK),

    /**
     * 客户端不存在
     */
    CLIENT_NOT_EXIST(-502, "Client not exist", false, OK),

    /**
     * 授权码过期或无效
     */
    AUTHORIZATION_CODE_EXPIRED_OR_NOT_EXIST(-503, "Authorization code does not exist or expires", false, OK),

    /**
     * 授权范围不足或授权类型错误
     */
    SCOPE_EXCEPTION_OR_TYPE_ERROR(-504, "Insufficient scope of authorization or GrantType error", false,
                                  NETWORK_AUTHENTICATION_REQUIRED),

    /**
     * url匹配错误
     */
    MISMATCHED_URL(-88888, "URL matching failed", false, NOT_FOUND),

    /**
     * 未知异常
     */
    UNKNOWN(-99999, "unknown", false, INTERNAL_SERVER_ERROR);

    private final int        code;
    private final String     message;
    private final boolean    clearToken;
    private final HttpStatus httpStatus;

    ExceptionStatus(int code,
                    String message,
                    boolean clearToken,
                    HttpStatus httpStatus) {
        this.code       = code;
        this.message    = message;
        this.clearToken = clearToken;
        this.httpStatus = httpStatus;
    }

    @Override
    public int getCode() {
        return code;
    }

    @Override
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
