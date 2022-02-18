package cn.omisheep.authz.core.handler;

import cn.omisheep.commons.util.HttpUtils;
import feign.RequestInterceptor;
import feign.RequestTemplate;

import javax.servlet.http.HttpServletRequest;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;

public class AuthzFeignRequestInterceptor implements RequestInterceptor {

    @Override
    public void apply(RequestTemplate template) {
        getHeaders(HttpUtils.getCurrentRequest()).forEach(template::header);
    }

    private Map<String, String> getHeaders(HttpServletRequest request) {
        Map<String, String> map = new LinkedHashMap<>();
        if (request == null) return map;
        Enumeration<String> enumeration = request.getHeaderNames();
        if (enumeration == null) return map;
        while (enumeration.hasMoreElements()) {
            String key = enumeration.nextElement();
            map.put(key, request.getHeader(key));
        }
        return map;
    }
}