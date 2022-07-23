package cn.omisheep.authz.support.http.api;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.support.http.ApiSupport;
import cn.omisheep.authz.support.http.SupportServlet;
import cn.omisheep.authz.support.http.annotation.Get;
import cn.omisheep.authz.support.http.annotation.Mapping;
import cn.omisheep.authz.support.http.annotation.Post;
import cn.omisheep.commons.util.UUIDBits;
import cn.omisheep.commons.util.web.JSONUtils;
import cn.omisheep.web.entity.Result;
import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.lang.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.Map;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Mapping("/user")
public class UserApiSupport implements ApiSupport {

    private final String username;
    private final String password;

    public UserApiSupport(AuthzProperties properties) {
        this.username = properties.getDashboard().getUsername();
        this.password = properties.getDashboard().getPassword();
    }

    @Post(value = "/login", requireLogin = false)
    public Result login(HttpServletRequest request, HttpServletResponse response, HttpMeta httpMeta) {
        Map<String, String> user = JSONUtils.parseJSON(httpMeta.getBody(), new TypeReference<Map<String, String>>() {});
        if (user != null && StringUtils.equals(user.get("username"), username) && StringUtils.equals(user.get("password"), password)) {
            HttpSession session = request.getSession();
            session.setAttribute(SupportServlet.SESSION_USER_KEY, UUIDBits.getUUIDBits(16));
            return Result.SUCCESS.data();
        } else {
            return Result.FAIL.data();
        }
    }

    @Get(value = "/check-login", requireLogin = false)
    public Result checkLogin(HttpServletRequest request, HttpServletResponse response, HttpMeta httpMeta) {
        if (StringUtils.isEmpty(username) || StringUtils.isEmpty(password)) return Result.SUCCESS.data();
        if (request.getSession().getAttribute(SupportServlet.SESSION_USER_KEY) != null) {
            return Result.SUCCESS.data();
        } else {
            return Result.FAIL.data();
        }
    }

}
