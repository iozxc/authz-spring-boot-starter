package cn.omisheep.authz.core.config;

import java.util.function.Supplier;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public interface Constants {
    String SCOPE             = "cop";
    String ID                = "tid";
    String ACCESS_TOKEN_ID   = "aid";
    String USER_ID           = "uid";
    String CLIENT_ID         = "cid";
    String DEVICE_ID         = "did";
    String DEVICE_TYPE       = "dtp";
    String LAST_REQUEST_TIME = "lrt";
    String IP                = "ip";
    String GRANT_TYPE        = "gtp";
    String AUTHORIZED_TIME   = "aut";
    String EXPIRES_TIME      = "ext";

    String SEPARATOR = ":";
    String COMMA     = ",";
    String BLANK     = " ";
    String WILDCARD  = "*";
    String CRLF      = "\n";
    String EMPTY     = "";
    String SLASH     = "/";

    String   DASHBOARD_STATIC_PREFIX = "/authz-dashboard-static";
    String   DASHBOARD_API_PREFIX    = "/authz-api";
    String   DASHBOARD_STATIC        = DASHBOARD_STATIC_PREFIX + "/*";
    String   DASHBOARD_API           = DASHBOARD_API_PREFIX + "/*";
    String   DASHBOARD_HTML          = "/authz.html";
    String   DASHBOARD_LOGO          = "/authz-dashboard-favicon.ico";
    String[] DASHBOARD               = new String[]{DASHBOARD_STATIC, DASHBOARD_API, DASHBOARD_LOGO, DASHBOARD_HTML};

    String HTTP_META = "AU_HTTP_META";
    String OPTIONS   = "OPTIONS";

    Supplier<String> USER_DEVICE_KEY_PREFIX       = () -> AuthzAppVersion.values.get(
            "USER_DEVICE_KEY_PREFIX");
    Supplier<String> OAUTH_USER_DEVICE_KEY_PREFIX = () -> AuthzAppVersion.values.get(
            "OAUTH_USER_DEVICE_KEY_PREFIX");

    Supplier<String> USER_REQUEST_KEY_PREFIX       = () -> AuthzAppVersion.values.get(
            "USER_REQUEST_KEY_PREFIX");
    Supplier<String> OAUTH_USER_REQUEST_KEY_PREFIX = () -> AuthzAppVersion.values.get(
            "OAUTH_USER_REQUEST_KEY_PREFIX");

    Supplier<String> ROLES_BY_USER_KEY_PREFIX       = () -> AuthzAppVersion.values.get(
            "ROLES_BY_USER_KEY_PREFIX");
    Supplier<String> PERMISSIONS_BY_ROLE_KEY_PREFIX = () -> AuthzAppVersion.values.get(
            "PERMISSIONS_BY_ROLE_KEY_PREFIX");

    Supplier<String> CLINT_PREFIX          = () -> AuthzAppVersion.values.get(
            "CLINT_PREFIX");
    Supplier<String> AUTHORIZE_CODE_PREFIX = () -> AuthzAppVersion.values.get(
            "AUTHORIZE_CODE_PREFIX");

    Supplier<String> DASHBOARD_KEY_PREFIX = () -> AuthzAppVersion.values.get(
            "DASHBOARD_KEY_PREFIX");

    String USER_REQUEST   = "USER_REQUEST";
    String CONNECT_PREFIX = "authz:connect:";

    String[] METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"};
    String[] SUFFIX = {".css", ".js", ".html", ".png", ".jpg", ".gif", ".svg", ".ico"};
}
