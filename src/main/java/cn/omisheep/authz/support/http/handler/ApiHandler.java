package cn.omisheep.authz.support.http.handler;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.config.Constants;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.authz.support.entity.Docs;
import cn.omisheep.authz.support.http.annotation.Header;
import cn.omisheep.authz.support.http.annotation.JSON;
import cn.omisheep.authz.support.http.annotation.Param;
import cn.omisheep.authz.support.util.SupportUtils;
import cn.omisheep.commons.util.web.JSONUtils;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
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
import java.util.Map;
import java.util.Objects;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.2.0
 */
public class ApiHandler {

    @Getter
    private static final HashMap<String, ApiInfo> api = new HashMap<>();

    @Data
    @Accessors(chain = true)
    public static class ApiInfo {
        @JsonProperty(index = 2)
        private String  method;
        @JsonProperty(index = 1)
        private boolean requireLogin;
        @JsonIgnore
        private Method  invoke;
        @JsonProperty(index = 3)
        private String  desc;

        @JsonProperty(index = 4)
        public Object getReturn() {
            Map<String, String> map = PermissionDict.parseTypeForTemplate(invoke.getReturnType().getTypeName());
            if (map.isEmpty()) return invoke.getReturnType().getTypeName();
            return map;
        }
    }

    public void process(HttpServletRequest request,
                        HttpServletResponse response,
                        String path,
                        boolean auth) {
        HttpMeta httpMeta = (HttpMeta) request.getAttribute(Constants.HTTP_META);
        String   apiPath  = path.substring(Docs.VERSION_PATH.length());
        ApiInfo  apiInfo  = api.get(apiPath);
        if (apiInfo == null || !apiInfo.getMethod().equals(httpMeta.getMethod())) {
            SupportUtils.forbid(response);
            return;
        }
        if (apiInfo.requireLogin && !auth) {
            SupportUtils.forbid(response);
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

                if (AnnotationUtils.getAnnotation(parameter, JSON.class) != null) {
                    objects.add(JSONUtils.parseJSON(httpMeta.getBody(), type));
                    continue;
                }
                Param param = AnnotationUtils.getAnnotation(parameter, Param.class);
                if (param != null) {
                    try {
                        String requestParameter = request.getParameter(
                                !Objects.equals(param.name(), "") ? param.name() : parameter.getName());
                        objects.add(type.getConstructor(String.class).newInstance(requestParameter));
                    } catch (Exception e) {
                        objects.add(null);
                    }
                    continue;
                }
                Header header = AnnotationUtils.getAnnotation(parameter, Header.class);
                if (header != null) {
                    try {
                        String val = request.getHeader(
                                !Objects.equals(header.name(), "") ? header.name() : parameter.getName());
                        objects.add(type.getConstructor(String.class).newInstance(val));
                    } catch (Exception e) {
                        objects.add(null);
                    }
                    continue;
                }

                if (HttpServletRequest.class.equals(type)) {
                    objects.add(request);
                } else if (HttpServletResponse.class.equals(type)) {
                    objects.add(response);
                } else if (HttpSession.class.equals(type)) {
                    objects.add(request.getSession());
                } else if (HttpMeta.class.equals(type)) {
                    objects.add(httpMeta);
                } else {
                    objects.add(AUtils.getBean(type));
                }
            }
            SupportUtils.toJSON(response, invoke.invoke(AUtils.getBean(invoke.getDeclaringClass()), objects.toArray()));
        } catch (Exception e) {
            // skip
        }
    }
}
