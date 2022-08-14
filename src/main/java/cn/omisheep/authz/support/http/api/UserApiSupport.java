package cn.omisheep.authz.support.http.api;

import cn.omisheep.authz.core.AuthzResult;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.config.Constants;
import cn.omisheep.authz.support.entity.User;
import cn.omisheep.authz.support.http.ApiSupport;
import cn.omisheep.authz.support.http.SupportServlet;
import cn.omisheep.authz.support.http.annotation.Get;
import cn.omisheep.authz.support.http.annotation.JSON;
import cn.omisheep.authz.support.http.annotation.Mapping;
import cn.omisheep.authz.support.http.annotation.Post;
import cn.omisheep.web.entity.ResponseResult;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Mapping(value = "/user", requireLogin = false)
public class UserApiSupport implements ApiSupport {

    private final Cache cache;

    public UserApiSupport(Cache cache) {
        this.cache = cache;
    }

    @Post(value = "/login", requireLogin = false, desc = "登录")
    public ResponseResult<?> login(@JSON User user,
                                   HttpMeta httpMeta) {
        if (user != null) {
            User loginUser = SupportServlet.login(user.getUsername(), user.getPassword(), httpMeta.getIp(), cache);
            if (loginUser == null) return AuthzResult.FAIL.data();
            return AuthzResult.SUCCESS.data("username", user.getUsername()).data("uuid", loginUser.getUuid());
        } else {
            return AuthzResult.FAIL.data();
        }
    }

    @Get(value = "/check-status", requireLogin = false, desc = "状态检查")
    public ResponseResult<Object> checkLogin(HttpMeta httpMeta) {
        if (!SupportServlet.requireLogin()) return AuthzResult.SUCCESS.data();
        User user = SupportServlet.connectPkg(httpMeta.getRequest(), httpMeta.getIp(), cache);
        if (user != null) {
            return AuthzResult.SUCCESS.data();
        } else {
            return AuthzResult.FAIL.data();
        }
    }

    @Get(value = "/logout", desc = "退出登录")
    public ResponseResult<Object> logout(User user) {
        if (!SupportServlet.requireLogin()) return AuthzResult.SUCCESS.data();
        cache.del(Constants.DASHBOARD_KEY_PREFIX.get() + user.getUuid());
        return AuthzResult.SUCCESS.data();
    }

    @Get(value = "/expiration-time", requireLogin = false, desc = "失效时间")
    public ResponseResult<Long> expirationTime() {
        return AuthzResult.SUCCESS.data(SupportServlet.getUnresponsiveExpirationTime());
    }

}
