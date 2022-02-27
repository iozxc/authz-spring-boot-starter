package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.method.HandlerMethod;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Order(40)
@SuppressWarnings("unchecked")
public class ParameterPermSlot implements Slot {

    @Override
    public boolean chain(HttpMeta httpMeta, HandlerMethod handler) throws Exception {
//        Map<String, String> pathVariables = (Map<String, String>) httpMeta.getRequest().getAttribute(
//                HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);

//        System.out.println(pathVariables.isEmpty());
//        String id = pathVariables.get("ids");
//        String x = pathVariables.get("x");

//        MethodParameter[] methodParameters = handler.getMethodParameters();
//        for (MethodParameter methodParameter : methodParameters) {
//            Constructor<?> constructor = methodParameter.getParameterType().getConstructor(String.class);
//            String text = httpMeta.getRequest().getParameter(methodParameter.getParameterName());
//            System.out.println("====");
//            System.out.println(methodParameter.getParameter().getName());
//            RequestParam param = AnnotationUtils.getAnnotation(methodParameter.getParameter(), RequestParam.class);
//            System.out.println(param.name());
//            System.out.println(text);
//            Object o = constructor.newInstance(text);
//            System.out.println(o);
//            System.out.println(o.getClass());
//            System.out.println("===");
//            System.out.println(httpMeta.getRequest().getParameter(methodParameter.getParameter().getName()));
//            System.out.println("===");
//            Roles roles = AnnotationUtils.getAnnotation(methodParameter.getParameter(), Roles.class);
//            Perms perms = AnnotationUtils.getAnnotation(methodParameter.getParameter(), Perms.class);
//            if (roles != null) {
//                boolean b = Arrays.asList(roles.hd()).contains("123");
//                if (b) return false;
//            }
//            if (perms != null) {
//                System.out.println(Arrays.toString(perms.require()));
//            }
        }
        return true;
    }
}
