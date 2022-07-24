package cn.omisheep.authz.support.http.handler;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.authz.support.http.annotation.JSON;
import cn.omisheep.authz.support.http.annotation.Param;
import cn.omisheep.authz.support.util.SupportUtils;
import cn.omisheep.commons.util.web.JSONUtils;
import lombok.Data;
import lombok.Getter;
import lombok.experimental.Accessors;
import org.springframework.core.annotation.AnnotationUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.ArrayList;
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
    public boolean requireLogin() {
        return false;
    }

    @Override
    public boolean match(String path) {
        return path.startsWith(PREFIX);
    }

    @Override
    public void process(HttpServletRequest request, HttpServletResponse response, HttpMeta httpMeta, String path, boolean auth) {
        String  apiPath = path.substring(PREFIX.length());
        ApiInfo apiInfo = api.get(apiPath);
        if (apiInfo == null || !apiInfo.getMethod().equals(httpMeta.getMethod())) {
            return;
        }
        if (apiInfo.requireLogin && !auth) {
            return;
        }
        Method      invoke     = apiInfo.getInvoke();
        Parameter[] parameters = invoke.getParameters();

        try {
            if (parameters == null || parameters.length == 0) {
                SupportUtils.toJSON(response, invoke.invoke(AUtils.getBean(invoke.getDeclaringClass())));
                return;
            }
            ArrayList<Object> objects = new ArrayList<>();
            for (Parameter parameter : parameters) {
                Class<?> type = parameter.getType();
                if (HttpServletRequest.class.equals(type)) {
                    objects.add(request);
                } else if (HttpServletResponse.class.equals(type)) {
                    objects.add(response);
                } else if (HttpSession.class.equals(type)) {
                    objects.add(request.getSession());
                } else if (HttpMeta.class.equals(type)) {
                    objects.add(httpMeta);
                } else {
                    if (AnnotationUtils.getAnnotation(parameter, JSON.class) != null) {
                        objects.add(JSONUtils.parseJSON(httpMeta.getBody(), type));
                    } else {
                        Param param = AnnotationUtils.getAnnotation(parameter, Param.class);
                        if (param != null) {
                            try {
                                String requestParameter = request.getParameter(parameter.getName());
                                if (requestParameter == null || requestParameter.equals("")) requestParameter = param.defaultValue();
                                objects.add(type.getConstructor(String.class).newInstance(requestParameter));
                            } catch (Exception e) {
                                objects.add(null);
                            }
                        } else {
                            objects.add(AUtils.getBean(type));
                        }
                    }
                }
            }
            SupportUtils.toJSON(response, invoke.invoke(AUtils.getBean(invoke.getDeclaringClass()), objects.toArray()));
        } catch (Exception e) {
            // skip
        }
    }
}
