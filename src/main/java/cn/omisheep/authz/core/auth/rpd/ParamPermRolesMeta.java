package cn.omisheep.authz.core.auth.rpd;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;

import java.util.Set;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@EqualsAndHashCode(callSuper = true)
@Data
@Accessors(chain = true)
public class ParamPermRolesMeta extends PermRolesMeta {
    private Set<String> range; // scope of access
    private Set<String> resources; // required protect resources

    public Set<String> getRange() {
        return range;
    }

    public Set<String> getResources() {
        return resources;
    }

    @Override
    public Set<Set<String>> getRequireRoles() {
        return super.getRequireRoles();
    }

    @Override
    public Set<Set<String>> getExcludeRoles() {
        return super.getExcludeRoles();
    }

    @Override
    public Set<Set<String>> getRequirePermissions() {
        return super.getRequirePermissions();
    }

    @Override
    public Set<Set<String>> getExcludePermissions() {
        return super.getExcludePermissions();
    }

    @Override
    public ParamPermRolesMeta clear() {
        super.clear();
        range     = null;
        resources = null;
        return this;
    }

    @Override
    public boolean non() {
        return super.non() || (range == null || range.isEmpty()) && (resources == null || resources.isEmpty());
    }
}
