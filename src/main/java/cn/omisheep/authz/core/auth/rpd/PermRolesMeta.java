package cn.omisheep.authz.core.auth.rpd;

import cn.omisheep.commons.util.CollectionUtils;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.experimental.Accessors;

import java.util.*;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;
import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@JsonInclude(NON_NULL)
public class PermRolesMeta {

    @Data
    @JsonInclude(NON_NULL)
    public static class Meta {
        private Set<Set<String>> require;
        private Set<Set<String>> exclude;
        private Set<String> resources; // required protect resources

        public boolean non() {
            return (require == null || require.size() == 0) && (exclude == null || exclude.size() == 0);
        }

        @Override
        public String toString() {
            return (require != null ? "require: " + require : "") + (exclude != null ? "\t, exclude: " + exclude : "");
        }
    }

    private Meta role;
    private Meta permissions;

    public static void main(String[] args) {
        HashMap<String, HashMap<String, String>> map = new HashMap<>();
//        map.put("1", new HashMap<>());
//        map.put("2", new HashMap<>());
        map.put("3", null);
        System.out.println(map.values());
        System.out.println(map.values().stream().count());
        System.out.println(map.values().stream().noneMatch(Objects::nonNull));
    }

    @JsonInclude(NON_NULL)
    private Map<ParamType, Map<String, ParamMetadata>> paramPermissionsMetadata;

    public Map<ParamType, Map<String, ParamMetadata>> getParamPermissionsMetadata() {
        return paramPermissionsMetadata;
    }

    public void put(ParamType paramType, String name, ParamMetadata paramMetadata) {
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

    public PermRolesMeta overrideApi(PermRolesMeta permRolesMeta) {
        this.setRequireRoles(permRolesMeta.getRequireRoles());
        this.setExcludeRoles(permRolesMeta.getExcludeRoles());
        this.setRequirePermissions(permRolesMeta.getRequirePermissions());
        this.setExcludePermissions(permRolesMeta.getExcludePermissions());
        return this;
    }

    public PermRolesMeta removeApi() {
        role = null;
        permissions = null;
        return this;
    }

    @Data
    @Accessors(chain = true)
    @JsonInclude(NON_EMPTY)
    public static class ParamMetadata {
        private Class<?> paramType;
        private List<Meta> rolesMetaList;
        private List<Meta> permissionsMetaList;

        public boolean non() {
            return (rolesMetaList == null || rolesMetaList.isEmpty()) && (permissionsMetaList == null || permissionsMetaList.isEmpty());
        }
    }

    public enum ParamType {
        PATH_VARIABLE,
        REQUEST_PARAM
    }

    @Data
    @Accessors(chain = true)
    public static class Vo {
        Operate operate;

        public enum Operate {
            ADD, OVERRIDE,
            DELETE, DEL,
            MODIFY, UPDATE,
            GET, READ,
            EMPTY, NON,
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
