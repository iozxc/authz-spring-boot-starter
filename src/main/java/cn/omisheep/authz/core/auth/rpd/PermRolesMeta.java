package cn.omisheep.authz.core.auth.rpd;

import cn.omisheep.commons.util.CollectionUtils;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Collection;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@JsonInclude(NON_NULL)
public class PermRolesMeta {

    Meta role;
    Meta permissions;
//
//    @JsonInclude(NON_NULL)
//    private Map<ParamMetadata.ParamType, Map<String, ParamMetadata>> paramPermissionsMetadata;

//    @Data
//    @Accessors(chain = true)
//    @JsonInclude(NON_NULL)
//    public static class Meta {
//        private Set<Set<String>> require;
//        private Set<Set<String>> exclude;
//        private Set<String>      range; // scope of access
//        private Set<String>      resources; // required protect resources
//
//        public boolean non() {
//            return (require == null || require.size() == 0) && (exclude == null || exclude.size() == 0);
//        }
//
//        @Override
//        public String toString() {
//            return (require != null ? "require: " + require : "") + (exclude != null ? "\t, exclude: " + exclude : "");
//        }
//    }

//    public Map<ParamMetadata.ParamType, Map<String, ParamMetadata>> getParamPermissionsMetadata() {
//        return paramPermissionsMetadata;
//    }

    public boolean non() {
        return (role == null || role.non()) && (permissions == null || permissions.non());
    }

//    public boolean nonAll() {
//        return (role == null || role.non()) && (permissions == null || permissions.non())
//                && (paramPermissionsMetadata == null
//                || paramPermissionsMetadata.size() == 0
//                || paramPermissionsMetadata.values().stream().noneMatch(Objects::nonNull));
//    }

    public void removeApi() {
        role        = null;
        permissions = null;
    }

    public PermRolesMeta() {
    }

    public Set<Set<String>> getRequireRoles() {
        if (this.role != null) return this.role.require;
        return null;
    }

    public void setRequireRoles(Set<Set<String>> requireRoles) {
        if (requireRoles == null || requireRoles.isEmpty()) {
            if (this.role != null) this.role.require = null;
        } else {
            Set<Set<String>> set = filter(requireRoles);
            if (set.isEmpty()) {
                if (this.role != null) this.role.require = null;
                return;
            }
            if (this.role == null) this.role = new Meta();
            this.role.require = set;
        }
    }

    public Set<Set<String>> getExcludeRoles() {
        if (this.role != null) return this.role.exclude;
        return null;
    }

    public void setExcludeRoles(Set<Set<String>> excludeRoles) {
        if (excludeRoles == null || excludeRoles.isEmpty()) {
            if (this.role != null) this.role.exclude = null;
        } else {
            Set<Set<String>> set = filter(excludeRoles);
            if (set.isEmpty()) {
                if (this.role != null) this.role.exclude = null;
                return;
            }
            if (this.role == null) this.role = new Meta();
            this.role.exclude = set;
        }
    }

    public Set<Set<String>> getRequirePermissions() {
        if (permissions != null) return permissions.require;
        return null;
    }

    public void setRequirePermissions(Set<Set<String>> requirePermissions) {
        if (requirePermissions == null || requirePermissions.isEmpty()) {
            if (this.permissions != null) this.permissions.require = null;
        } else {
            Set<Set<String>> set = filter(requirePermissions);
            if (set.isEmpty()) {
                if (this.permissions != null) this.permissions.require = null;
                return;
            }
            if (this.permissions == null) this.permissions = new Meta();
            this.permissions.require = set;
        }
    }

    public Set<Set<String>> getExcludePermissions() {
        if (permissions != null) return permissions.exclude;
        return null;
    }

    public void setExcludePermissions(Set<Set<String>> excludePermissions) {
        if (excludePermissions == null || excludePermissions.isEmpty()) {
            if (this.permissions != null) this.permissions.exclude = null;
        } else {
            Set<Set<String>> set = filter(excludePermissions);
            if (set.isEmpty()) {
                if (this.permissions != null) this.permissions.exclude = null;
                return;
            }
            if (this.permissions == null) this.permissions = new Meta();
            this.permissions.exclude = set;
        }
    }

    private Set<Set<String>> filter(Set<Set<String>> set) {
        return set.stream().map(s -> {
                    Set<String> collect = s.stream().filter(Objects::nonNull)
                            .map(v-> v.replaceAll("&nbsp;"," "))
                            .map(String::trim)
                            .filter(v -> !v.isEmpty())
                            .collect(Collectors.toSet());
                    if (!collect.isEmpty()) return collect;
                    return null;
                }).filter(Objects::nonNull)
                .collect(Collectors.toSet());
    }

    public void setRequireRoles(Collection<String> requireRoles) {
        setRequireRoles(CollectionUtils.splitStrValsToSets(PermissionDict.getPermSeparator(),
                                                           requireRoles.toArray(new String[]{})));
    }

    public void setExcludeRoles(Collection<String> excludeRoles) {
        setExcludeRoles(CollectionUtils.splitStrValsToSets(PermissionDict.getPermSeparator(),
                                                           excludeRoles.toArray(new String[]{})));
    }

    public void setRequirePermissions(Collection<String> requirePermissions) {
        setRequirePermissions(CollectionUtils.splitStrValsToSets(PermissionDict.getPermSeparator(),
                                                                 requirePermissions.toArray(new String[]{})));
    }

    public void setExcludePermissions(Collection<String> excludePermissions) {
        setExcludePermissions(CollectionUtils.splitStrValsToSets(PermissionDict.getPermSeparator(),
                                                                 excludePermissions.toArray(new String[]{})));
    }

    public void setRole(Set<Set<String>> require,
                        Set<Set<String>> exclude) {
        if ((require == null || require.isEmpty()) && (exclude == null || exclude.isEmpty())) {
            this.role = null;
            return;
        }
        setRequireRoles(require);
        setExcludeRoles(exclude);
    }

    public void setPermissions(Set<Set<String>> require,
                               Set<Set<String>> exclude) {
        if ((require == null || require.isEmpty()) && (exclude == null || exclude.isEmpty())) {
            this.permissions = null;
            return;
        }
        setRequirePermissions(require);
        setExcludePermissions(exclude);
    }

    public void merge(PermRolesMeta other) {
        setExcludePermissions(other.getExcludePermissions());
        setRequirePermissions(other.getRequirePermissions());
        setRequireRoles(other.getRequireRoles());
        setExcludeRoles(other.getExcludeRoles());
    }

    @Override
    public String toString() {
        return (role != null ? "( role> " + role + " )" : "") +
                (permissions != null ? "\t, ( permissions> " + permissions + " )" : "");
    }

}
