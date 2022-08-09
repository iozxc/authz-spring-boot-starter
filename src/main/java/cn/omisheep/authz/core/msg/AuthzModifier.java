package cn.omisheep.authz.core.msg;

import cn.omisheep.authz.annotation.RateLimit;
import cn.omisheep.authz.core.auth.rpd.PermRolesMeta;
import cn.omisheep.authz.core.auth.rpd.Rule;
import cn.omisheep.authz.core.oauth.OpenAuthDict;
import cn.omisheep.commons.util.NamingUtils;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.experimental.Accessors;

import java.util.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Data
@Accessors(chain = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthzModifier {

    // 通用
    private Operate    operate;
    private Target     target;
    private String     method;
    private String     api;
    private Object     value;
    private Integer    index;
    private Role       role;
    private String     controller;
    private Permission permission;

    // param
    private Set<String> range;
    private Set<String> resources;

    // data
    private String                    className;
    private String                    fieldName;
    private String                    condition;
    private Rule                      rule;
    private Map<String, List<String>> argsMap;

    // rateLimit
    private RateLimitInfo rateLimit;

    private BlacklistInfo          blacklistInfo;
    private OpenAuthDict.OAuthInfo oauth;

    @Data
    public static class Role {
        private Set<Set<String>> require;
        private Set<Set<String>> exclude;
    }

    @Data
    public static class Permission {
        private Set<Set<String>> require;
        private Set<Set<String>> exclude;
    }

    @Data
    public static class RateLimitInfo {
        private long                window;
        private int                 maxRequests;
        private List<String>        punishmentTime     = new ArrayList<>();
        private long                minInterval;
        private List<String>        associatedPatterns = new ArrayList<>();
        private RateLimit.CheckType checkType;
    }

    @Data
    public static class BlacklistInfo {
        private TYPE   type;
        private OP     op;
        private String ip;
        private String ipRange;
        private Object userId;
        private String deviceType;
        private String deviceId;
        private long   time;
        private String date;

        public enum OP {
            UPDATE, REMOVE, READ, NON;

            @JsonCreator
            public static OP create(String op) {
                try {
                    return valueOf(op.toUpperCase(Locale.ROOT));
                } catch (Exception e) {
                    return NON;
                }
            }
        }

        public enum TYPE {
            IP, USER, DEVICE, IP_RANGE, NON;

            @JsonCreator
            public static TYPE create(String type) {
                try {
                    return valueOf(type.toUpperCase(Locale.ROOT));
                } catch (Exception e) {
                    return NON;
                }
            }
        }

    }

    public enum Target {
        API,
        PARAMETER,
        DATA_COL,
        DATA_ROW,
        RATE,
        BLACKLIST,
        OPEN_AUTH,
        LOGIN,
        NON;

        @JsonCreator
        public static Target create(String target) {
            try {
                return valueOf(NamingUtils.humpToUnderline(target).toUpperCase(Locale.ROOT));
            } catch (Exception e) {
                return NON;
            }
        }

    }

    public enum Operate {
        ADD,
        DELETE, DEL,
        MODIFY, UPDATE,
        GET, READ,
        EMPTY, NON;

        @JsonCreator
        public static Operate create(String type) {
            try {
                return valueOf(type.toUpperCase(Locale.ROOT));
            } catch (Exception e) {
                return EMPTY;
            }
        }
    }

    public AuthzModifier setMethod(String method) {
        try {
            this.method = method.toUpperCase(Locale.ROOT);
        } catch (Exception ignored) {
        }
        return this;
    }

    public AuthzModifier setParamName(String paramName) {
        this.value = paramName;
        return this;
    }

    public PermRolesMeta build() {
        PermRolesMeta permRolesMeta = new PermRolesMeta();
        if (role != null) {
            permRolesMeta.setRoles(role.require, role.exclude);
        }
        if (permission != null) {
            permRolesMeta.setPermissions(permission.require, permission.exclude);
        }
        if (permRolesMeta.non()) {
            return null;
        }
        return permRolesMeta;
    }

    public void setRequireRoles(Set<Set<String>> requireRoles) {
        if (this.role == null) this.role = new Role();
        this.role.require = requireRoles;
    }

    public void setExcludeRoles(Set<Set<String>> excludeRoles) {
        if (this.role == null) this.role = new Role();
        this.role.exclude = excludeRoles;
    }

    public void setRequirePermissions(Set<Set<String>> requirePermissions) {
        if (this.permission == null) this.permission = new Permission();
        this.permission.require = requirePermissions;
    }


    public void setExcludePermissions(Set<Set<String>> excludePermissions) {
        if (this.permission == null) this.permission = new Permission();
        this.permission.exclude = excludePermissions;
    }

}
