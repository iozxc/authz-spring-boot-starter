package cn.omisheep.authz.core.auth;

import cn.omisheep.authz.annotation.BannedType;
import cn.omisheep.authz.core.auth.rpd.PermRolesMeta;
import cn.omisheep.authz.core.auth.rpd.Rule;
import lombok.Data;
import lombok.experimental.Accessors;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Data
@Accessors(chain = true)
public class AuthzModifier {

    private Operate operate;
    private Target  target;
    private String  method;
    private String  api;

    private String value;

    private Integer index;

    private List<String> range;
    private List<String> resources;

    private String                    className;
    private String                    condition;
    private Rule                      rule;
    private Map<String, List<String>> argsMap;

    private Role       role;
    private Permission permission;

    private RateLimitInfo rateLimit;

    @Data
    public static class Role {
        private List<String> require;
        private List<String> exclude;
    }

    @Data
    public static class Permission {
        private List<String> require;
        private List<String> exclude;
    }

    @Data
    public static class RateLimitInfo {
        private String       window;
        private int          maxRequests;
        private List<String> punishmentTime;
        private String       minInterval;
        private List<String> associatedPatterns;
        private BannedType   bannedType;
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
        RATE(8),
        NON(0);

        public final int      i;
        final        String[] with;

        Target(int i, String... with) {
            this.i    = i;
            this.with = with;
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
        EMPTY, NON
    }

    public AuthzModifier setTarget(Target target) {
        this.target = target;
        return this;
    }

    public AuthzModifier setTarget(String target) {
        try {
            this.target = Target.valueOf(target.toUpperCase(Locale.ROOT));
        } catch (Exception e) {
            this.target = Target.NON;
        }
        return this;
    }


    public AuthzModifier setOp(Operate operate) {
        this.operate = operate;
        return this;
    }

    public AuthzModifier setOp(String operate) {
        try {
            this.operate = Operate.valueOf(operate.toUpperCase(Locale.ROOT));
        } catch (Exception e) {
            this.operate = Operate.EMPTY;
        }
        return this;
    }


    public AuthzModifier setOperate(Operate operate) {
        this.operate = operate;
        return this;
    }

    public AuthzModifier setOperate(String operate) {
        try {
            this.operate = Operate.valueOf(operate.toUpperCase(Locale.ROOT));
        } catch (Exception e) {
            this.operate = Operate.EMPTY;
        }
        return this;
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
        try {
            permRolesMeta.setRequireRoles(role.require);
            permRolesMeta.setExcludeRoles(role.exclude);
        } catch (Exception ignored) {
        }
        try {
            permRolesMeta.setRequirePermissions(permission.require);
            permRolesMeta.setExcludePermissions(permission.exclude);
        } catch (Exception ignored) {
        }
        return permRolesMeta;
    }

    public static PermRolesMeta build(List<String> requireRoles,
                                      List<String> excludeRoles,
                                      List<String> requirePermissions,
                                      List<String> excludePermissions) {
        PermRolesMeta permRolesMeta = new PermRolesMeta();
        permRolesMeta.setRequireRoles(requireRoles);
        permRolesMeta.setExcludeRoles(excludeRoles);
        permRolesMeta.setRequirePermissions(requirePermissions);
        permRolesMeta.setExcludePermissions(excludePermissions);
        return permRolesMeta;
    }
}
