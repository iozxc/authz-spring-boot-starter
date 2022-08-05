package cn.omisheep.authz.support.http.api;

import cn.omisheep.authz.core.AuthzManager;
import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.AuthzVersion;
import cn.omisheep.authz.core.msg.AuthzModifier;
import cn.omisheep.authz.support.entity.User;
import cn.omisheep.authz.support.http.ApiSupport;
import cn.omisheep.authz.support.http.annotation.Get;
import cn.omisheep.authz.support.http.annotation.JSON;
import cn.omisheep.authz.support.http.annotation.Param;
import cn.omisheep.authz.support.http.annotation.Post;
import cn.omisheep.web.entity.Result;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class StandardApiSupport implements ApiSupport {

    public StandardApiSupport(AuthzProperties properties) {
    }

    @Get(value = "/echo", desc = "echo")
    public Result echo(@Param String msg) {
        return Result.SUCCESS.data(msg);
    }

    @Post(value = "/operate", desc = "权限操作通用接口")
    public Result operate(@JSON AuthzModifier modifier,
                          User user) {
        if (user.getPermissions() == null || user.getPermissions().isEmpty()) {
            return Result.FAIL.data();
        }
        if (modifier == null) {return Result.FAIL.data();}
        try {
            AuthzProperties.DashboardConfig.DashboardPermission dashboardPermission = AuthzProperties.DashboardConfig.DashboardPermission.valueOf(
                    modifier.getTarget().name());

            if (user.getPermissions().contains(AuthzProperties.DashboardConfig.DashboardPermission.ALL)
                    || user.getPermissions().contains(dashboardPermission)) {
                return AuthzManager.operate(modifier);
            }
        } catch (Exception e) {
            Result.FAIL.data();
        }
        return Result.FAIL.data();
    }

    @Get(value = "/version", desc = "版本号")
    public String version() {
        return AuthzVersion.getVersion();
    }

}
