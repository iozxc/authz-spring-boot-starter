package cn.omisheep.authz.core;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public interface Constants {
    String SEPARATOR = ":";
    String COMMA     = ",";
    String BLANK     = " ";
    String WILDCARD  = "*";
    String CRLF      = "\n";
    String EMPTY     = "";

    String HTTP_META                      = "AU_HTTP_META";
    String DEBUG_PREFIX                   = "[DEBUG]  ";
    String WARN_PREFIX                    = "[WARN]  ";
    String OPTIONS                        = "OPTIONS";
    String ACCESS_INFO_KEY_PREFIX         = "au:usersAccessInfo:";
    String REFRESH_INFO_KEY_PREFIX        = "au:usersRefreshInfo:";
    String DEVICE_REQUEST_INFO_KEY_PREFIX = "au:requestInfo:";
    String PERMISSIONS_BY_ROLE_KEY_PREFIX = "au:permissionsByRole:";
    String USER_ROLES_KEY_PREFIX          = "au:userRoles:";

    String[] METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"};
}
