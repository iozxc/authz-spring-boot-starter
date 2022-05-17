package cn.omisheep.authz.core.auth.rpd;

import lombok.Data;
import lombok.experimental.Accessors;

import java.util.List;
import java.util.Locale;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Data
@Accessors(chain = true)
public class AuthzModifier {

    private Operate operate;
    private Target target;
    private String method;
    private String api;
    private String value;
    private Integer index;

    private List<String> range;
    private List<String> resources;

    private Role role;
    private Permission permission;

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


    /**
     * API
     * PATH_VARIABLE_ROLE(PATH_VARIABLE_ROLE)
     * PATH_VARIABLE_PERMISSION(PATH_VAR_PERMISSION)
     * REQUEST_PARAM_ROLE(PARAM_ROLE)
     * REQUEST_PARAM_PERMISSION(PARAM_PERMISSION)
     */
    public enum Target {
        API(1, "role", "permission"),
        PATH_VARIABLE_ROLE(2, "role"), PATH_VAR_ROLE(2, "role"),
        PATH_VARIABLE_PERMISSION(3, "permission"), PATH_VAR_PERMISSION(3, "permission"),
        REQUEST_PARAM_ROLE(4, "role"), PARAM_ROLE(4, "role"),
        REQUEST_PARAM_PERMISSION(5, "permission"), PARAM_PERMISSION(5, "permission"),
        NON(0);

        final int i;
        final String[] with;

        Target(int i, String... with) {
            this.i = i;
            this.with = with;
        }
    }

    public enum Operate {
        ADD, OVERRIDE,
        DELETE, DEL,
        MODIFY, UPDATE,
        GET, READ,
        EMPTY, NON,
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
        if (method != null) {
            this.method = method.toUpperCase(Locale.ROOT);
        } else {
            this.method = null;
        }
        return this;
    }

    public PermRolesMeta build() {
        PermRolesMeta permRolesMeta = new PermRolesMeta();
        if (role != null) {
            permRolesMeta.setRequireRoles(role.require);
            permRolesMeta.setExcludeRoles(role.exclude);
        }
        if (permission != null) {
            permRolesMeta.setRequirePermissions(permission.require);
            permRolesMeta.setExcludePermissions(permission.exclude);
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
