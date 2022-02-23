package cn.omisheep.authz.core.cache;

import cn.omisheep.authz.PermLibrary;

import java.util.List;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
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
