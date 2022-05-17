package cn.omisheep.authz.core.auth.rpd;

import cn.omisheep.commons.util.CollectionUtils;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.experimental.Accessors;

import java.util.*;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@JsonInclude(NON_NULL)
public class PermRolesMeta {

    Meta role;
    Meta permissions;

    @JsonInclude(NON_NULL)
    private Map<ParamMetadata.ParamType, Map<String, ParamMetadata>> paramPermissionsMetadata;

    @Data
    @Accessors(chain = true)
    @JsonInclude(NON_NULL)
    public static class Meta {
        private Set<Set<String>> require;
        private Set<Set<String>> exclude;
        private Set<String> range; // scope of access
        private Set<String> resources; // required protect resources

        public boolean non() {
            return (require == null || require.size() == 0) && (exclude == null || exclude.size() == 0);
        }

        @Override
        public String toString() {
            return (require != null ? "require: " + require : "") + (exclude != null ? "\t, exclude: " + exclude : "");
        }
    }

    public Map<ParamMetadata.ParamType, Map<String, ParamMetadata>> getParamPermissionsMetadata() {
        return paramPermissionsMetadata;
    }

    public void put(ParamMetadata.ParamType paramType, String name, ParamMetadata paramMetadata) {
        if (paramPermissionsMetadata == null) paramPermissionsMetadata = new HashMap<>();
        paramPermissionsMetadata
                .computeIfAbsent(paramType, r -> new HashMap<>()).put(name, paramMetadata);
    }

    public boolean non() {
        return (role == null || role.non()) && (permissions == null || permissions.non());
    }

    public boolean nonAll() {
        return (role == null || role.non()) && (permissions == null || permissions.non())
                && (paramPermissionsMetadata == null
                || paramPermissionsMetadata.size() == 0
                || paramPermissionsMetadata.values().stream().noneMatch(Objects::nonNull));
    }

    public void overrideApi(PermRolesMeta permRolesMeta) {
        this.setRequireRoles(permRolesMeta.getRequireRoles());
        this.setExcludeRoles(permRolesMeta.getExcludeRoles());
        this.setRequirePermissions(permRolesMeta.getRequirePermissions());
        this.setExcludePermissions(permRolesMeta.getExcludePermissions());
    }

    public PermRolesMeta removeApi() {
        role = null;
        permissions = null;
        return this;
    }

    public PermRolesMeta() {
    }

    public Set<Set<String>> getRequireRoles() {
        if (role != null) return role.require;
        return null;
    }

    public void setRequireRoles(Set<Set<String>> requireRoles) {
        if (requireRoles == null) return;
        if (role == null) role = new Meta();
        this.role.require = requireRoles;
    }

    public Set<Set<String>> getExcludeRoles() {
        if (role != null) return role.exclude;
        return null;
    }

    public void setExcludeRoles(Set<Set<String>> excludeRoles) {
        if (excludeRoles == null) return;
        if (role == null) role = new Meta();
        this.role.exclude = excludeRoles;
    }

    public Set<Set<String>> getRequirePermissions() {
        if (permissions != null) return permissions.require;
        return null;
    }

    public void setRequirePermissions(Set<Set<String>> requirePermissions) {
        if (requirePermissions == null) return;
        if (permissions == null) permissions = new Meta();
        this.permissions.require = requirePermissions;
    }

    public Set<Set<String>> getExcludePermissions() {
        if (permissions != null) return permissions.exclude;
        return null;
    }

    public void setExcludePermissions(Set<Set<String>> excludePermissions) {
        if (excludePermissions == null) return;
        if (permissions == null) permissions = new Meta();
        this.permissions.exclude = excludePermissions;
    }

    public void setRequireRoles(Collection<String> requireRoles) {
        if (requireRoles == null) return;
        if (role == null) role = new Meta();
        this.role.require = CollectionUtils.splitStrValsToSets(PermissionDict.getPermSeparator(),
                requireRoles.toArray(new String[]{}));
    }

    public void setExcludeRoles(Collection<String> excludeRoles) {
        if (excludeRoles == null) return;
        if (role == null) role = new Meta();
        this.role.exclude = CollectionUtils.splitStrValsToSets(PermissionDict.getPermSeparator(),
                excludeRoles.toArray(new String[]{}));
    }

    public void setRequirePermissions(Collection<String> requirePermissions) {
        if (requirePermissions == null) return;
        if (permissions == null) permissions = new Meta();
        this.permissions.require = CollectionUtils.splitStrValsToSets(PermissionDict.getPermSeparator(),
                requirePermissions.toArray(new String[]{}));
    }

    public void setExcludePermissions(Collection<String> excludePermissions) {
        if (excludePermissions == null) return;
        if (permissions == null) permissions = new Meta();
        this.permissions.exclude = CollectionUtils.splitStrValsToSets(PermissionDict.getPermSeparator(),
                excludePermissions.toArray(new String[]{}));
    }

    public PermRolesMeta merge(PermRolesMeta other) {
        setExcludePermissions(other.getExcludePermissions());
        setRequirePermissions(other.getRequirePermissions());
        setRequireRoles(other.getRequireRoles());
        setExcludeRoles(other.getExcludeRoles());
        return this;
    }


    @Override
    public String toString() {
        return (role != null ? "( role> " + role + " )" : "") +
                (permissions != null ? "\t, ( permissions> " + permissions + " )" : "");
    }

}
