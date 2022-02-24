package cn.omisheep.authz.core.auth;

import cn.omisheep.authz.core.util.LogUtils;

import java.util.List;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public class DefaultPermLibrary implements PermLibrary<Object> {
    @Override
    public List<String> getRolesByUserId(Object userId) {
        LogUtils.logDebug("[WARN] 没有配置自定义的PermLibrary");
        return null;
    }

    @Override
    public List<String> getPermissionsByRole(String role) {
        LogUtils.logDebug("[WARN] 没有配置自定义的PermLibrary");
        return null;
    }
}
