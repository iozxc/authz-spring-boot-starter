package cn.omisheep.authz.core.auth;

import cn.omisheep.authz.core.util.LogUtils;

import java.util.HashSet;
import java.util.Set;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class DefaultPermLibrary implements PermLibrary<Object> {
    @Override
    public Set<String> getRolesByUserId(Object userId) {
        LogUtils.debug("[WARN] 没有配置自定义的PermLibrary");
        return new HashSet<>();
    }

    @Override
    public Set<String> getPermissionsByRole(String role) {
        LogUtils.debug("[WARN] 没有配置自定义的PermLibrary");
        return new HashSet<>();
    }
}
