package cn.omisheep.authz.core.auth;

import cn.omisheep.authz.core.util.LogUtils;

import java.util.HashSet;
import java.util.Set;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class DefaultPermLibrary implements PermLibrary<String> {
    @Override
    public Set<String> getRolesByUserId(String userId) {
        LogUtils.warn("[WARN] 没有配置自定义的PermLibrary");
        return new HashSet<>();
    }

    @Override
    public Set<String> getPermissionsByRole(String role) {
        LogUtils.warn("[WARN] 没有配置自定义的PermLibrary");
        return new HashSet<>();
    }
}
