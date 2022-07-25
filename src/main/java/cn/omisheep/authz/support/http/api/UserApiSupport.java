package cn.omisheep.authz.support.http.api;

import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.config.Constants;
import cn.omisheep.authz.support.entity.User;
import cn.omisheep.authz.support.http.ApiSupport;
import cn.omisheep.authz.support.http.SupportServlet;
import cn.omisheep.authz.support.http.annotation.*;
import cn.omisheep.commons.util.UUIDBits;
import cn.omisheep.web.entity.Result;

import javax.servlet.http.HttpServletRequest;
import java.util.concurrent.TimeUnit;

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

    @Post(value = "/login", requireLogin = false)
    public Result login(@JSON User user) {
        if (user != null) {
            User loginUser = SupportServlet.login(user.getUsername(), user.getPassword());
            if (loginUser == null) return Result.FAIL.data();
            loginUser.setUuid(UUIDBits.getUUIDBits(16));
            cache.set(Constants.DASHBOARD_KEY_PREFIX.get() + loginUser.getUuid(), user.getUsername(), 1, TimeUnit.HOURS);
            return Result.SUCCESS.data("username", user.getUsername()).data("uuid", loginUser.getUuid());
        } else {
            return Result.FAIL.data();
        }
    }

    @Get(value = "/check-login", requireLogin = false)
    public Result checkLogin(HttpServletRequest request, @Header("uuid") String uuid1, @Param("uuid") String uuid2) {
        if (!SupportServlet.requireLogin()) return Result.SUCCESS.data();
        User auth = SupportServlet.auth(request, cache);
        if (auth != null) {
            return Result.SUCCESS.data(auth.getUsername());
        } else {
            return Result.FAIL.data();
        }
    }

}
