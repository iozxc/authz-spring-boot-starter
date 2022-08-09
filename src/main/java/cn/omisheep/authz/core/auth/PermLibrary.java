package cn.omisheep.authz.core.auth;

import java.util.ArrayList;
import java.util.Collection;

/**
 * 为了防止循环调用，PermLibrary里面的所有sql不会被数据权限拦截 @1.2.0
 *
 * @param <K> userId类型
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public interface PermLibrary<K> {

    /**
     * 根据userId获取该用户的role集合
     *
     * @param userId role
     * @return 权限
     */
    Collection<String> getRolesByUserId(K userId);

    /**
     * 根据role获取该role所具有的权限集合
     *
     * @param role role
     * @return 权限
     */
    default Collection<String> getPermissionsByRole(String role) {
        return new ArrayList<>(0);
    }

}
