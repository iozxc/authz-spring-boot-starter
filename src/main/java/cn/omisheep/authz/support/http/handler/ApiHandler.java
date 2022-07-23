package cn.omisheep.authz.support.http.handler;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.authz.support.http.SupportServlet;
import cn.omisheep.commons.util.web.JSONUtils;
import lombok.Data;
import lombok.Getter;
import lombok.experimental.Accessors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Method;
import java.util.HashMap;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.2.0
 */
public class ApiHandler implements WebHandler {

    @Getter
    private static final HashMap<String, ApiInfo> api = new HashMap<>();

    private static final String PREFIX = "/v1/api";

    @Data
    @Accessors(chain = true)
    public static class ApiInfo {
        private String  method;
        private boolean requireLogin;
        private Method  invoke;
    }

    @Override
    public boolean match(String path) {
        return path.startsWith(PREFIX);
    }

    @Override
    public void process(HttpServletRequest request, HttpServletResponse response, HttpMeta httpMeta, String path) {
        String  apiPath = path.substring(PREFIX.length());
        ApiInfo apiInfo = api.get(apiPath);
        if (apiInfo == null || !apiInfo.getMethod().equals(httpMeta.getMethod())) {
            return;
        }
        if (apiInfo.requireLogin && request.getSession().getAttribute(SupportServlet.SESSION_USER_KEY) == null) {
            return;
        }
        Method invoke = apiInfo.getInvoke();
        try {
            Object obj = invoke.invoke(AUtils.getBean(invoke.getDeclaringClass()), request, response, httpMeta);
            response.setContentType("application/json;charset=utf-8");
            response.getWriter().println(JSONUtils.toPrettyJSONString(obj));
            return;
        } catch (Exception e) {
            return;
        }
    }
}
