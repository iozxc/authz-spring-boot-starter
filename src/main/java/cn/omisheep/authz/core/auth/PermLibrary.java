package cn.omisheep.authz.core.auth;

import java.util.Collection;

/**
 * @param <K> userId类型
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public interface PermLibrary<K> {

    /**
     * 根据userId获取该role
     *
     * @param userId role
     * @return 权限
     */
    Collection<String> getRolesByUserId(K userId);

    /**
     * 根据role获取该role的权限
     *
     * @param role role
     * @return 权限
     */
    Collection<String> getPermissionsByRole(String role);

}
