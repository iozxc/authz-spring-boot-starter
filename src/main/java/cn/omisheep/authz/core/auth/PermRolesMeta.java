package cn.omisheep.authz.core.auth;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import java.util.Set;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
@Data
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class PermRolesMeta {
    private Set<Set<String>> requireRoles;
    private Set<Set<String>> excludeRoles;
    private Set<Set<String>> requirePermissions;
    private Set<Set<String>> excludePermissions;

    @Override
    public String toString() {
        return "requireRoles: " + requireRoles +
                "\t, excludeRoles: " + excludeRoles +
                "\t, requirePermissions: " + requirePermissions +
                "\t, excludePermissions: " + excludePermissions;
    }
}
