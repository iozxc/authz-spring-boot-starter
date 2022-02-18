package cn.omisheep.authz;

import java.util.List;

/**
 * qq: 1269670415
 *
 * @param <K> userId类型
 * @author zhou xin chen
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
