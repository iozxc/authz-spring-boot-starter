package cn.omisheep.authz.core.auth.rpd;

import cn.omisheep.authz.core.init.AuInit;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.authz.core.util.LogUtils;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.google.common.base.Objects;
import com.sun.javafx.collections.ObservableMapWrapper;
import com.sun.javafx.collections.UnmodifiableObservableMap;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Slf4j
public class PermissionDict {

    private static PermissionDict SELF;

    public static PermissionDict self() {
        return SELF;
    }

    private static Map<String, Map<String, PermRolesMeta>> authzMetadata;

    private static Map<String, ArgsMeta> argsMetadata;

    private static Map<String, List<DataPermMeta>> dataPermMetadata;

    private static final Map<String, Map<String, String>> authzResourcesNameAndTemplate = new HashMap<>();

    private static Map<String, Map<String, FieldData>> fieldMetadata;

    // ----------------------------------------- json ----------------------------------------- //
    private static Map<String, Map<String, PermRolesMeta>> m1;
    private static Map<String, Map<String, String>> m2;
    private static Map<String, List<DataPermMeta>> m3;
    private static Map<String, ArgsMeta> m4;
    private static Map<String, Map<String, FieldData>> m5;

    public Map<String, Map<String, PermRolesMeta>> getAuthzMetadata() {
        return m1;
    }

    public Map<String, Map<String, String>> getAuthzResourcesNameAndTemplate() {
        return m2;
    }

    public Map<String, List<DataPermMeta>> getDataPermMetadata() {
        return m3;
    }

    public Map<String, ArgsMeta> getArgsMetadata() {
        return m4;
    }

    public Map<String, Map<String, FieldData>> getFieldMetadata() {
        return m5;
    }

    // ----------------------------------------- func ----------------------------------------- //

    public static List<Class<?>> argType(String argsName) {
        ArgsMeta meta = argsMetadata.get(argsName);
        if (meta == null) return null;
        return meta.parameterList;
    }

    public static Object argsHandle(String argsName, Object... otherArgs) {
        ArgsMeta meta = argsMetadata.get(argsName);
        if (meta == null) {
            LogUtils.logError("arg {} is null", argsName);
            return null;
        }
        try {
            Object bean = AUtils.getBean(meta.type);
            return meta.method.invoke(bean, otherArgs);
        } catch (Exception e) {
            try {
                if (Modifier.isStatic(meta.method.getModifiers())) {
                    return meta.method.invoke(null, otherArgs);
                } else {
                    int modifiers = meta.type.getModifiers();
                    if (Modifier.isAbstract(modifiers) || Modifier.isInterface(modifiers)) {
                        log.error("{} bean 不存在 且不能实例化 ， 或者参数个数、类型不正确", meta.type);
                        return null;
                    }
                    return meta.method.invoke(meta.type.newInstance(), otherArgs);
                }
            } catch (Exception ex) {
                log.error("{} 构造函数异常", meta.type);
                return null;
            }
        }
    }

    public static Map<String, String> parseTypeForTemplate(String className) {
        HashMap<String, String> typeTemplate = new HashMap<>();
        try {
            Class<?> clz = Class.forName(className);
            for (Method method : clz.getMethods()) {
                String name = method.getName();
                if ((name.startsWith("get") || name.startsWith("is"))
                        && Modifier.isPublic(method.getModifiers()) && !Modifier.isStatic(method.getModifiers()) && !Modifier.isAbstract(method.getModifiers()) && !Modifier.isNative(method.getModifiers()) && !Modifier.isFinal(method.getModifiers())) {
                    String field;
                    if (name.startsWith("get")) {
                        field = name.substring(3, 4).toLowerCase(Locale.ROOT) + name.substring(4);
                    } else {
                        field = name.substring(2, 3).toLowerCase(Locale.ROOT) + name.substring(3);
                    }
                    typeTemplate.put(field, method.getReturnType().getTypeName());
                }
            }
        } catch (Exception e) {
            return new HashMap<>();
        }
        return typeTemplate;
    }

    public synchronized PermRolesMeta modify(PermRolesMeta.Vo permRolesMetaVo) {
        boolean change = false;
        try {
            Map<String, PermRolesMeta> target = authzMetadata.get(permRolesMetaVo.getMethod());
            PermRolesMeta meta = target.get(permRolesMetaVo.getApi());
            switch (permRolesMetaVo.getOperate()) {
                case ADD:
                case OVERRIDE:
                    change = true;
                    if (meta != null) return meta.overrideApi(permRolesMetaVo.build());
                    else return target.put(permRolesMetaVo.getApi(), permRolesMetaVo.build());
                case MODIFY:
                case UPDATE:
                    change = true;
                    return meta.merge(permRolesMetaVo.build());
                case DELETE:
                case DEL:
                    if (meta != null) return meta.removeApi();
                    else return null;
                case GET:
                case READ:
                    return meta;
                default:
                    return null;
            }
        } catch (Exception e) {
            return null;
        } finally {
            if (change) {
                PermRolesMeta meta = authzMetadata.get(permRolesMetaVo.getMethod()).get(permRolesMetaVo.getApi());
                if (meta == null || meta.nonAll()) {
                    authzMetadata.get(permRolesMetaVo.getMethod()).remove(permRolesMetaVo.getApi());
                }
                Map<String, PermRolesMeta> metaMap = authzMetadata.get(permRolesMetaVo.getMethod());
                if (metaMap.size() == 0) authzMetadata.remove(permRolesMetaVo.getMethod());
            }
            m1 = new UnmodifiableObservableMap<>(new ObservableMapWrapper<>(authzMetadata));
        }
    }

    // ----------------------------------------- init ----------------------------------------- //

    public static void init(PermissionDict permissionDict) {
        if (SELF != null) {
            AuInit.log.error("permissionDict 已经初始化");
            return;
        }
        SELF = permissionDict;
    }

    public static void initAuthzMetadata(Map<String, Map<String, PermRolesMeta>> authzMetadata) {
        if (PermissionDict.authzMetadata != null) {
            AuInit.log.error("authzMetadata 已经初始化");
            return;
        }
        PermissionDict.authzMetadata = authzMetadata;
        m1 = new UnmodifiableObservableMap<>(new ObservableMapWrapper<>(authzMetadata));
    }

    public static void addAuthzResourcesNames(Set<String> authzResourcesNames) {
        if (authzResourcesNames == null) return;
        Set<String> names = new HashSet<>();
        for (String authzResourcesName : authzResourcesNames) {
            try {
                Map<String, String> fieldMap = PermissionDict.authzResourcesNameAndTemplate.computeIfAbsent(authzResourcesName, r -> new HashMap<>());
                fieldMap.putAll(parseTypeForTemplate(authzResourcesName));
                names.add(authzResourcesName);
            } catch (Exception ignored) {
            }
        }
        m2 = new UnmodifiableObservableMap<>(new ObservableMapWrapper<>(authzResourcesNameAndTemplate));
        AuInit.log.info("authz resources add success ⬇: \n{}", names);
    }

    public static void initDataPerm(Map<String, List<DataPermMeta>> dataPermMetadata) {
        if (PermissionDict.dataPermMetadata != null) {
            AuInit.log.error("dataPermMetadata 已经初始化");
            return;
        }
        PermissionDict.dataPermMetadata = dataPermMetadata;
        m3 = new UnmodifiableObservableMap<>(new ObservableMapWrapper<>(dataPermMetadata));
    }

    public static void initArgs(Map<String, ArgsMeta> argsMetadata) {
        if (PermissionDict.argsMetadata != null) {
            AuInit.log.error("authzMetadata 已经初始化");
            return;
        }
        PermissionDict.argsMetadata = argsMetadata;
        m4 = new UnmodifiableObservableMap<>(new ObservableMapWrapper<>(argsMetadata));
    }

    public static void initFieldMetadata(Map<String, Map<String, FieldData>> fieldMetadata) {
        if (PermissionDict.fieldMetadata != null) {
            AuInit.log.error("fieldMetadata 已经初始化");
            return;
        }
        PermissionDict.fieldMetadata = fieldMetadata;
        m5 = new UnmodifiableObservableMap<>(new ObservableMapWrapper<>(fieldMetadata));
    }

    public static void setPermSeparator(String permSeparator) {
        PermissionDict.permSeparator = permSeparator;
    }

    private static String permSeparator = ",";

    public static String getPermSeparator() {
        return permSeparator;
    }

    @Getter
    public static class ArgsMeta {
        private final Class<?> type;
        private final Method method;
        private final List<Class<?>> parameterList;
        private final Class<?> returnType;
        @JsonInclude(JsonInclude.Include.NON_EMPTY)
        private final Map<String, String> returnTypeTemplate;

        private ArgsMeta(Class<?> type, Method method) {
            this.type = type;
            this.method = method;
            this.returnType = method.getReturnType();
            this.parameterList = Arrays.stream(method.getParameterTypes()).collect(Collectors.toList());
            this.returnTypeTemplate = parseTypeForTemplate(this.returnType.getTypeName());
        }

        public String getMethod() {
            return method.getName();
        }

        public static ArgsMeta of(Class<?> type, Method method) {
            return new ArgsMeta(type, method);
        }

        public static ArgsMeta of(Class<?> type, String methodName, Class<?>... args) {
            try {
                return new ArgsMeta(type, type.getMethod(methodName, args));
            } catch (NoSuchMethodException e) {
                e.printStackTrace();
                return null;
            }
        }

        public static ArgsMeta of(Object type, String methodName, Class<?>... args) {
            return of(type.getClass(), methodName, args);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof ArgsMeta)) return false;
            ArgsMeta meta = (ArgsMeta) o;
            return Objects.equal(method, meta.method) && Objects.equal(type, meta.type);
        }

        @Override
        public int hashCode() {
            return Objects.hashCode(method, type);
        }
    }
}
