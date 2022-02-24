package cn.omisheep.authz.core.auth;

import java.util.List;

/**
 * @param <K> userId类型
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public interface PermLibrary<K> {
    List<String> getRolesByUserId(K userId);

    List<String> getPermissionsByRole(String role);

    /**
     * 如果返回为null，则会调用 getRolesByUserId 或者 getPermissionsByRole
     * 所以查询结果为空，请返回空列表而不是null
     *
     * @param userId 用户id
     * @return 权限列表
     */
    default List<String> getPermissionsByUserId(K userId) {
        return null;
    }
}
