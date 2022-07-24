package cn.omisheep.authz.support.http.api;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.config.Constants;
import cn.omisheep.authz.support.entity.User;
import cn.omisheep.authz.support.http.ApiSupport;
import cn.omisheep.authz.support.http.annotation.Get;
import cn.omisheep.authz.support.http.annotation.JSON;
import cn.omisheep.authz.support.http.annotation.Mapping;
import cn.omisheep.authz.support.http.annotation.Post;
import cn.omisheep.commons.util.UUIDBits;
import cn.omisheep.web.entity.Result;
import org.apache.commons.lang.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Mapping(value = "/user", requireLogin = false)
public class UserApiSupport implements ApiSupport {

    private final Set<User> users = new HashSet<>();
    private final Cache     cache;

    public UserApiSupport(AuthzProperties properties, Cache cache) {
        this.users.addAll(properties.getDashboard().getUsers());
        String username = properties.getDashboard().getUsername();
        String password = properties.getDashboard().getPassword();
        if (!StringUtils.isEmpty(username) && !StringUtils.isEmpty(password)) {
            this.users.add(new User().setUsername(username).setPassword(password).setPermissions(Collections.singletonList("*")));
        }
        this.cache = cache;
    }

    @Post(value = "/login", requireLogin = false)
    public Result login(@JSON User user) {
        if (user != null && users.stream().anyMatch(u -> StringUtils.equals(u.getUsername(), user.getUsername()) && StringUtils.equals(u.getPassword(), user.getPassword()))) {
            String uuid = UUIDBits.getUUIDBits(16);
            cache.set(Constants.DASHBOARD_KEY_PREFIX.get() + uuid, user.getUsername(), 1, TimeUnit.HOURS);
            return Result.SUCCESS.data("username", user.getUsername()).data("uuid", uuid);
        } else {
            return Result.FAIL.data();
        }
    }

    @Get(value = "/check-login", requireLogin = false)
    public Result checkLogin(HttpServletRequest request) {
        if (users.isEmpty()) return Result.SUCCESS.data();
        String uuid1 = request.getHeader("uuid");
        String uuid  = uuid1 != null ? uuid1 : request.getParameter("uuid");
        Object username     = cache.get(Constants.DASHBOARD_KEY_PREFIX.get() + uuid);
        if (username != null) {
            return Result.SUCCESS.data();
        } else {
            return Result.FAIL.data();
        }
    }

}
