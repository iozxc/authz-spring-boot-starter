package cn.omisheep.authz.core.msg;

import cn.omisheep.authz.annotation.RateLimit;
import cn.omisheep.authz.core.auth.rpd.PermRolesMeta;
import cn.omisheep.authz.core.auth.rpd.Rule;
import cn.omisheep.authz.core.oauth.OpenAuthDict;
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

    private Operate                   operate;
    private Target                    target;
    private String                    method;
    private String                    api;
    private Object                    value;
    private Integer                   index;
    private List<String>              range;
    private List<String>              resources;
    private String                    className;
    private String                    fieldName;
    private String                    condition;
    private Rule                      rule;
    private Map<String, List<String>> argsMap;
    private Role                      role;
    private Permission                permission;
    private RateLimitInfo             rateLimit;
    private BlacklistInfo             blacklistInfo;
    private OpenAuthDict.OAuthInfo    oauth;

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
        private Long   start;
        private String ip;
        private String ipRange;
        private Object userId;
        private String deviceType;
        private String deviceId;
        private String time;

        public enum OP {
            ADD, CHANGE, REMOVE, READ, NON;

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
            IP, USER, IP_RANGE, NON;

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

    /**
     * API
     * PATH_VARIABLE_ROLE(PATH_VARIABLE_ROLE)
     * PATH_VARIABLE_PERMISSION(PATH_VAR_PERMISSION)
     * REQUEST_PARAM_ROLE(PARAM_ROLE)
     * REQUEST_PARAM_PERMISSION(PARAM_PERMISSION)
     * DATA_ROW
     * DATA_COL
     */
    public enum Target {
        API(1, "role", "permission"),
        PATH_VARIABLE_ROLE(2, "role"), PATH_VAR_ROLE(2, "role"),
        PATH_VARIABLE_PERMISSION(3, "permission"), PATH_VAR_PERMISSION(3, "permission"),
        REQUEST_PARAM_ROLE(4, "role"), PARAM_ROLE(4, "role"),
        REQUEST_PARAM_PERMISSION(5, "permission"), PARAM_PERMISSION(5, "permission"),
        DATA_ROW(6, "role", "permission"),
        DATA_COL(7, "role", "permission"),
        PATH(8, "role", "permission"),
        PARAM(9, "role", "permission"),
        RATE(10),
        BLACKLIST(11),
        OPEN_AUTH(12),
        LOGIN(13),
        NON(0);

        public final int      i;
        final        String[] with;

        Target(int i,
               String... with) {
            this.i    = i;
            this.with = with;
        }

        @JsonCreator
        public static Target create(String target) {
            try {
                return valueOf(target.toUpperCase(Locale.ROOT));
            } catch (Exception e) {
                return NON;
            }
        }

        public boolean contains(String... with) {
            return Arrays.asList(this.with).containsAll(Arrays.asList(with));
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

}
