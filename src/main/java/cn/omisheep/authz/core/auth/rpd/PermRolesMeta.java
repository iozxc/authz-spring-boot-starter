package cn.omisheep.authz.core.auth.rpd;

import cn.omisheep.commons.util.CollectionUtils;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.experimental.Accessors;

import java.util.Collection;
import java.util.Locale;
import java.util.Set;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class PermRolesMeta {
    private Set<Set<String>> requireRoles;
    private Set<Set<String>> excludeRoles;
    private Set<Set<String>> requirePermissions;
    private Set<Set<String>> excludePermissions;

    @Data
    @Accessors(chain = true)
    public static class Vo {
        Operate operate;

        public enum Operate {
            ADD,
            DELETE,
            MODIFY,
            GET,
            EMPTY
        }

        public Vo setOperate(Operate operate) {

            this.operate = operate;
            return this;
        }

        public Vo setOperate(String operate) {
            try {
                this.operate = Operate.valueOf(operate.toUpperCase(Locale.ROOT));
            } catch (Exception e) {
                this.operate = Operate.EMPTY;
            }
            return this;
        }

        String method;
        String api;
        Collection<String> requireRoles;
        Collection<String> excludeRoles;
        Collection<String> requirePermissions;
        Collection<String> excludePermissions;

        public Vo setMethod(String method) {
            if (method != null) {
                this.method = method.toUpperCase(Locale.ROOT);
            } else {
                this.method = null;
            }
            return this;
        }

        public PermRolesMeta build() {
            PermRolesMeta permRolesMeta = new PermRolesMeta();
            permRolesMeta.setRequireRoles(requireRoles);
            permRolesMeta.setExcludeRoles(excludeRoles);
            permRolesMeta.setRequirePermissions(requirePermissions);
            permRolesMeta.setExcludePermissions(excludePermissions);
            return permRolesMeta;
        }

        public static PermRolesMeta build(Collection<String> requireRoles,
                                          Collection<String> excludeRoles,
                                          Collection<String> requirePermissions,
                                          Collection<String> excludePermissions) {
            PermRolesMeta permRolesMeta = new PermRolesMeta();
            permRolesMeta.setRequireRoles(requireRoles);
            permRolesMeta.setExcludeRoles(excludeRoles);
            permRolesMeta.setRequirePermissions(requirePermissions);
            permRolesMeta.setExcludePermissions(excludePermissions);
            return permRolesMeta;
        }
    }

    public PermRolesMeta() {
    }

    public Set<Set<String>> getRequireRoles() {
        return requireRoles;
    }

    public void setRequireRoles(Set<Set<String>> requireRoles) {
        if (requireRoles == null) return;
        this.requireRoles = requireRoles;
    }

    public Set<Set<String>> getExcludeRoles() {
        return excludeRoles;
    }

    public void setExcludeRoles(Set<Set<String>> excludeRoles) {
        if (excludeRoles == null) return;
        this.excludeRoles = excludeRoles;
    }

    public Set<Set<String>> getRequirePermissions() {
        return requirePermissions;
    }

    public void setRequirePermissions(Set<Set<String>> requirePermissions) {
        if (requirePermissions == null) return;
        this.requirePermissions = requirePermissions;
    }

    public Set<Set<String>> getExcludePermissions() {
        return excludePermissions;
    }

    public void setExcludePermissions(Set<Set<String>> excludePermissions) {
        if (excludePermissions == null) return;
        this.excludePermissions = excludePermissions;
    }

    public void setRequireRoles(Collection<String> requireRoles) {
        if (requireRoles == null) return;
        this.requireRoles = CollectionUtils.splitStrValsToSets(PermissionDict.getPermSeparator(),
                requireRoles.toArray(new String[]{}));
    }

    public void setExcludeRoles(Collection<String> excludeRoles) {
        if (excludeRoles == null) return;
        this.excludeRoles = CollectionUtils.splitStrValsToSets(PermissionDict.getPermSeparator(),
                excludeRoles.toArray(new String[]{}));
    }

    public void setRequirePermissions(Collection<String> requirePermissions) {
        if (requirePermissions == null) return;
        this.requirePermissions = CollectionUtils.splitStrValsToSets(PermissionDict.getPermSeparator(),
                requirePermissions.toArray(new String[]{}));
    }

    public void setExcludePermissions(Collection<String> excludePermissions) {
        if (excludePermissions == null) return;
        this.excludePermissions = CollectionUtils.splitStrValsToSets(PermissionDict.getPermSeparator(),
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
        return "requireRoles: " + requireRoles +
                "\t, excludeRoles: " + excludeRoles +
                "\t, requirePermissions: " + requirePermissions +
                "\t, excludePermissions: " + excludePermissions;
    }

}
