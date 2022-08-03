package cn.omisheep.authz.core.auth.rpd;

import cn.omisheep.commons.util.CollectionUtils;
import com.fasterxml.jackson.annotation.JsonIgnore;
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

    Meta roles;
    Meta permissions;

    public boolean non() {
        return (roles == null || roles.non()) && (permissions == null || permissions.non());
    }

    public PermRolesMeta clear() {
        this.roles       = null;
        this.permissions = null;
        return this;
    }

    public PermRolesMeta() {
    }

    public Set<Set<String>> getRequireRoles() {
        if (this.roles != null) return this.roles.require;
        return null;
    }

    public Set<Set<String>> getExcludeRoles() {
        if (this.roles != null) return this.roles.exclude;
        return null;
    }

    public Set<Set<String>> getRequirePermissions() {
        if (permissions != null) return permissions.require;
        return null;
    }

    public Set<Set<String>> getExcludePermissions() {
        if (permissions != null) return permissions.exclude;
        return null;
    }

    @JsonIgnore
    public Meta getRoles() {
        return roles;
    }

    @JsonIgnore
    public Meta getPermissions() {
        return permissions;
    }

    public void setRequireRoles(Set<Set<String>> requireRoles) {
        if (requireRoles == null || requireRoles.isEmpty()) {
            if (this.roles != null) this.roles.require = null;
        } else {
            Set<Set<String>> set = filter(requireRoles);
            if (set.isEmpty()) {
                if (this.roles != null) this.roles.require = null;
                return;
            }
            if (this.roles == null) this.roles = new Meta();
            this.roles.require = set;
        }
    }

    public void setExcludeRoles(Set<Set<String>> excludeRoles) {
        if (excludeRoles == null || excludeRoles.isEmpty()) {
            if (this.roles != null) this.roles.exclude = null;
        } else {
            Set<Set<String>> set = filter(excludeRoles);
            if (set.isEmpty()) {
                if (this.roles != null) this.roles.exclude = null;
                return;
            }
            if (this.roles == null) this.roles = new Meta();
            this.roles.exclude = set;
        }
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
                            .map(v -> v.replaceAll("&nbsp;", " "))
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

    public void setRoles(Meta role) {
        if (role == null) return;
        this.setRoles(role.require, role.exclude);
    }

    public void setRoles(Set<Set<String>> require,
                         Set<Set<String>> exclude) {
        if ((require == null || require.isEmpty()) && (exclude == null || exclude.isEmpty())) {
            this.roles = null;
            return;
        }
        setRequireRoles(require);
        setExcludeRoles(exclude);
    }

    public void setPermissions(Meta permissions) {
        if (permissions == null) return;
        setPermissions(permissions.require, permissions.exclude);
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

    public PermRolesMeta merge(PermRolesMeta other) {
        if (other == null) return this;
        if (permissions == null) {
            setExcludePermissions(other.getExcludePermissions());
            setRequirePermissions(other.getRequirePermissions());
        } else {
            Set<Set<String>> requirePermissions = other.getRequirePermissions();
            if (requirePermissions != null) permissions.require.addAll(requirePermissions);
            Set<Set<String>> excludePermissions = other.getExcludePermissions();
            if (excludePermissions != null) permissions.exclude.addAll(excludePermissions);
        }
        if (roles == null) {
            setRequireRoles(other.getRequireRoles());
            setExcludeRoles(other.getExcludeRoles());
        } else {
            Set<Set<String>> requireRoles = other.getRequireRoles();
            if (requireRoles != null) roles.require.addAll(requireRoles);
            Set<Set<String>> excludeRoles = other.getExcludeRoles();
            if (excludeRoles != null) roles.exclude.addAll(excludeRoles);
        }
        return this;
    }

    @Override
    public String toString() {
        return (roles != null ? "( role : " + roles + " )" : "") +
                (permissions != null ? "\t, ( permissions : " + permissions + " )" : "");
    }

}
