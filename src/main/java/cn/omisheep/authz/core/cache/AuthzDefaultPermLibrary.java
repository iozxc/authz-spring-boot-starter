package cn.omisheep.authz.core.cache;

import cn.omisheep.authz.core.auth.PermLibrary;

import java.util.List;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public class AuthzDefaultPermLibrary implements PermLibrary<Object> {

    @Override
    public List<String> getRolesByUserId(Object userId) {
        return null;
    }

    @Override
    public List<String> getPermissionsByRole(String role) {
        return null;
    }

}
