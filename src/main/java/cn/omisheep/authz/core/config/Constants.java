package cn.omisheep.authz.core.config;

import java.util.function.Supplier;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public interface Constants {
    String SEPARATOR = ":";
    String COMMA     = ",";
    String BLANK     = " ";
    String WILDCARD  = "*";
    String CRLF      = "\n";
    String EMPTY     = "";

    String HTTP_META    = "AU_HTTP_META";
    String DEBUG_PREFIX = "[DEBUG]  ";
    String WARN_PREFIX  = "[WARN]  ";
    String OPTIONS      = "OPTIONS";

    Supplier<String> ACCESS_INFO_KEY_PREFIX         = () -> InfoVersion.values.get("ACCESS_INFO_KEY_PREFIX");
    Supplier<String> REFRESH_INFO_KEY_PREFIX        = () -> InfoVersion.values.get("REFRESH_INFO_KEY_PREFIX");
    Supplier<String> DEVICE_REQUEST_INFO_KEY_PREFIX = () -> InfoVersion.values.get("DEVICE_REQUEST_INFO_KEY_PREFIX");
    Supplier<String> PERMISSIONS_BY_ROLE_KEY_PREFIX = () -> InfoVersion.values.get("PERMISSIONS_BY_ROLE_KEY_PREFIX");
    Supplier<String> USER_ROLES_KEY_PREFIX          = () -> InfoVersion.values.get("USER_ROLES_KEY_PREFIX");

    String[] METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"};
}
