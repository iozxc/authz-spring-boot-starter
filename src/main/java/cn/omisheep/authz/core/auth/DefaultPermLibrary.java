package cn.omisheep.authz.core.auth;

import cn.omisheep.authz.core.util.LogUtils;

import java.util.HashSet;
import java.util.Set;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public class DefaultPermLibrary implements PermLibrary<Object> {
    @Override
    public Set<String> getRolesByUserId(Object userId) {
        LogUtils.logDebug("[WARN] 没有配置自定义的PermLibrary");
        return new HashSet<>();
    }

    @Override
    public Set<String> getPermissionsByRole(String role) {
        LogUtils.logDebug("[WARN] 没有配置自定义的PermLibrary");
        return new HashSet<>();
    }
}
