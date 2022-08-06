package cn.omisheep.authz.core.auth.rpd;

import cn.omisheep.authz.AuthzAutoConfiguration;
import cn.omisheep.authz.core.AuthzContext;
import cn.omisheep.authz.core.util.LogUtils;
import com.fasterxml.jackson.annotation.JsonIgnore;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class ArgsHandler {

    private ArgsHandler() {
        throw new UnsupportedOperationException();
    }

    public static List<Class<?>> argParameterList(String argsName) {
        ArgsMeta meta = PermissionDict.getArgs().get(argsName);
        if (meta == null) return null;
        return meta.parameters;
    }

    public static Object handle(String argName,
                                Object... otherArgs) {
        ArgsMeta meta = PermissionDict.getArgs().get(argName);
        if (meta == null) {
            LogUtils.error("arg {} is null", argName);
            return null;
        }
        try {
            Object bean = AuthzContext.getBean(meta.type);
            return meta.method.invoke(bean, otherArgs);
        } catch (Exception e) {
            try {
                if (Modifier.isStatic(meta.method.getModifiers())) {
                    return meta.method.invoke(null, otherArgs);
                } else {
                    int modifiers = meta.type.getModifiers();
                    if (Modifier.isAbstract(modifiers) || Modifier.isInterface(modifiers)) {
                        LogUtils.error("{} bean 不存在 且不能实例化 ， 或者参数个数、类型不正确", meta.type);
                        return null;
                    }
                    return meta.method.invoke(meta.type.newInstance(), otherArgs);
                }
            } catch (Exception ex) {
                LogUtils.error("{} 构造函数异常", meta.type);
                LogUtils.error(e);
                return null;
            }
        }
    }

    public static Map<String, String> parseTypeForTemplate(String className) {
        if (className.startsWith("java.")) return new HashMap<>();
        HashMap<String, String> typeTemplate = new HashMap<>();
        try {
            Class<?> clz = Class.forName(className, false, AuthzAutoConfiguration.class.getClassLoader());
            for (Method method : clz.getMethods()) {
                if (method.isAnnotationPresent(JsonIgnore.class)) continue;
                String name = method.getName();
                if ((name.startsWith("get") || name.startsWith("is"))
                        && Modifier.isPublic(method.getModifiers()) && !Modifier.isStatic(
                        method.getModifiers()) && !Modifier.isAbstract(method.getModifiers()) && !Modifier.isNative(
                        method.getModifiers()) && !Modifier.isFinal(method.getModifiers())) {
                    String field;
                    if (name.startsWith("get")) {
                        field = name.substring(3, 4).toLowerCase(Locale.ROOT) + name.substring(4);
                    } else {
                        field = name.substring(2, 3).toLowerCase(Locale.ROOT) + name.substring(3);
                    }

                    try {
                        if (clz.getDeclaredField(field).isAnnotationPresent(JsonIgnore.class)) continue;
                    } catch (Exception e) {
                        // skip
                    }

                    typeTemplate.put(field, method.getReturnType().getTypeName());
                }
            }
        } catch (Exception e) {
            return new HashMap<>();
        }
        return typeTemplate;
    }

}
