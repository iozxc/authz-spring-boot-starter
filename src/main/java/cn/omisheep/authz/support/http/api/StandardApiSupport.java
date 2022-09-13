package cn.omisheep.authz.support.http.api;

import cn.omisheep.authz.core.AuthzManager;
import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.AuthzResult;
import cn.omisheep.authz.core.AuthzVersion;
import cn.omisheep.authz.core.msg.AuthzModifier;
import cn.omisheep.authz.support.entity.User;
import cn.omisheep.authz.support.http.ApiSupport;
import cn.omisheep.authz.support.http.annotation.Get;
import cn.omisheep.authz.support.http.annotation.JSON;
import cn.omisheep.authz.support.http.annotation.Param;
import cn.omisheep.authz.support.http.annotation.Post;
import cn.omisheep.web.entity.ResponseResult;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class StandardApiSupport implements ApiSupport {

    public StandardApiSupport(AuthzProperties properties) {
    }

    @Get(value = "/echo", desc = "echo")
    public ResponseResult<String> echo(@Param("msg") String msg) {
        return AuthzResult.SUCCESS.data(msg);
    }

    @Post(value = "/operate", desc = "权限操作通用接口")
    public ResponseResult<?> operate(@JSON AuthzModifier modifier,
                                     User user) {
        if (user.getPermissions() == null || user.getPermissions().isEmpty()) {
            return AuthzResult.FAIL.data();
        }
        if (modifier == null) {return AuthzResult.FAIL.data();}
        try {
            AuthzProperties.DashboardConfig.DashboardPermission dashboardPermission = AuthzProperties.DashboardConfig.DashboardPermission.valueOf(
                    modifier.getTarget().name());

            if (user.getPermissions().contains(AuthzProperties.DashboardConfig.DashboardPermission.ALL)
                    || user.getPermissions().contains(dashboardPermission)) {
                return AuthzManager.operate(modifier);
            }
        } catch (Exception e) {
            AuthzResult.FAIL.data();
        }
        return AuthzResult.FAIL.data();
    }

    @Get(value = "/version", desc = "版本号")
    public String version() {
        return AuthzVersion.getVersion();
    }

}
