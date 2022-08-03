package cn.omisheep.authz.support.http.api;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.support.entity.User;
import cn.omisheep.authz.support.http.ApiSupport;
import cn.omisheep.authz.support.http.SupportServlet;
import cn.omisheep.authz.support.http.annotation.Get;
import cn.omisheep.authz.support.http.annotation.JSON;
import cn.omisheep.authz.support.http.annotation.Mapping;
import cn.omisheep.authz.support.http.annotation.Post;
import cn.omisheep.web.entity.Result;

import javax.servlet.http.HttpServletRequest;

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
    public Result login(@JSON User user,
                        HttpMeta httpMeta) {
        if (user != null) {
            User loginUser = SupportServlet.login(user.getUsername(), user.getPassword(), httpMeta.getIp(), cache);
            if (loginUser == null) return Result.FAIL.data();
            return Result.SUCCESS.data("username", user.getUsername()).data("uuid", loginUser.getUuid());
        } else {
            return Result.FAIL.data();
        }
    }

    @Get(value = "/check-login", requireLogin = false, desc = "登录检查")
    public Result checkLogin(HttpServletRequest request) {
        if (!SupportServlet.requireLogin()) return Result.SUCCESS.data();
        User auth = SupportServlet.auth(request, cache);
        if (auth != null) {
            return Result.SUCCESS.data(auth.getUsername());
        } else {
            return Result.FAIL.data();
        }
    }

}
