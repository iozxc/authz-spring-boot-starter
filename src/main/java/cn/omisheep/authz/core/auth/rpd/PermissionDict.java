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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Slf4j
public class PermissionDict {

    private static final AtomicInteger version = new AtomicInteger(0);

    private static PermissionDict SELF;

    public static PermissionDict self() {
        return SELF;
    }

    private static Map<String, Map<String, PermRolesMeta>> authzMetadata; // api权限和api的参数权限

    private static Map<String, ArgsMeta> argsMetadata; // args

    private static Map<String, List<DataPermMeta>> dataPermMetadata; // 数据行权限

    private static Map<String, Map<String, FieldData>> fieldMetadata; // 数据列权限

    private static final Map<String, Map<String, String>> authzResourcesNameAndTemplate = new HashMap<>();

    // String String ParamType String Class
    // method api ParamType paramName paramClass
    @Getter
    private static final Map<String, Map<String, Map<ParamMetadata.ParamType, Map<String, Class<?>>>>> rawMap = new HashMap<>();

    // ----------------------------------------- json ----------------------------------------- //

    private static Map<String, Map<String, PermRolesMeta>> m1;
    private static Map<String, Map<String, String>> m2;
    private static Map<String, List<DataPermMeta>> m3;
    private static Map<String, Map<String, FieldData>> m4;
    private static Map<String, ArgsMeta> m5;
    private static final Map<String, Map<String, Map<ParamMetadata.ParamType, Map<String, Class<?>>>>> m6 =
            new UnmodifiableObservableMap<>(new ObservableMapWrapper<>(rawMap));

    public Map<String, Map<String, PermRolesMeta>> getAuthzMetadata() {
        return m1;
    }

    public Map<String, Map<String, String>> getAuthzResourcesNameAndTemplate() {
        return m2;
    }

    public Map<String, List<DataPermMeta>> getDataPermMetadata() {
        return m3;
    }

    public Map<String, Map<String, FieldData>> getFieldMetadata() {
        return m4;
    }

    public Map<String, ArgsMeta> getArgsMetadata() {
        return m5;
    }

    public Map<String, Map<String, Map<ParamMetadata.ParamType, Map<String, Class<?>>>>> getRawParamMap() {
        return m6;
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

    // ----------------------------------------- func ----------------------------------------- //

    public Object modify(AuthzModifier authzModifier) {
        try {
            switch (authzModifier.getTarget()) {
                case API:
                    return modifyAPI(authzModifier);
                case PATH_VARIABLE_PERMISSION:
                case PATH_VAR_PERMISSION:
                case PATH_VARIABLE_ROLE:
                case PATH_VAR_ROLE:
                case REQUEST_PARAM_ROLE:
                case PARAM_ROLE:
                case REQUEST_PARAM_PERMISSION:
                case PARAM_PERMISSION:
                    return modifyParam(authzModifier);
                case NON:
                    return null;
            }
            return null;
        } finally {
            version.incrementAndGet();
        }
    }

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

    private final ReentrantLock lock = new ReentrantLock();

    public PermRolesMeta modifyAPI(AuthzModifier authzModifier) {
        lock.lock();
        try {
            Map<String, PermRolesMeta> target = authzMetadata.get(authzModifier.getMethod());
            PermRolesMeta meta = target.get(authzModifier.getApi());
            switch (authzModifier.getOperate()) {
                case ADD:
                case OVERRIDE:
                    if (meta != null) meta.overrideApi(authzModifier.build());
                    else target.put(authzModifier.getApi(), authzModifier.build());
                    return target.get(authzModifier.getApi());
                case MODIFY:
                case UPDATE:
                    return meta.merge(authzModifier.build());
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
            m1 = new UnmodifiableObservableMap<>(new ObservableMapWrapper<>(authzMetadata));
            lock.unlock();
        }
    }

    @SuppressWarnings("all")
    public Object modifyParam(AuthzModifier authzModifier) {
        lock.lock();
        try {
            PermRolesMeta meta = authzMetadata.get(authzModifier.getMethod()).get(authzModifier.getApi());
            AuthzModifier.Target target = authzModifier.getTarget();

            Object[] objects = getParamMetaList(meta, authzModifier);

            ParamMetadata paramMetadata = (ParamMetadata) objects[0];
            List<PermRolesMeta.Meta> metaList = (List<PermRolesMeta.Meta>) objects[1]; // 可能需要操作的list

            if (metaList == null) {
                return "api not found";
            }

            switch (authzModifier.getOperate()) {
                case ADD:
                case OVERRIDE:
                    PermRolesMeta.Meta _m;
                    if (Arrays.asList(authzModifier.getTarget().with).contains("role")) {
                        _m = authzModifier.build().role;
                    } else {
                        _m = authzModifier.build().permissions;
                    }
                    if (authzModifier.getIndex() != null) {
                        metaList.add(authzModifier.getIndex(), _m);
                    } else {
                        metaList.add(_m);
                    }
                    if (authzModifier.getRange() != null) {
                        _m.setRange(new HashSet<>(authzModifier.getRange()));
                    }
                    if (authzModifier.getResources() != null) {
                        _m.setRange(new HashSet<>(authzModifier.getResources()));
                    }
                    return metaList;
                case DEL:
                case DELETE:
                    if (authzModifier.getIndex() != null) metaList.remove(metaList.get(authzModifier.getIndex()));
                    else {
                        if (target.i == 2 || target.i == 3) {
                            meta.getParamPermissionsMetadata().get(ParamMetadata.ParamType.PATH_VARIABLE).remove(authzModifier.getValue());
                        } else {
                            meta.getParamPermissionsMetadata().get(ParamMetadata.ParamType.REQUEST_PARAM).remove(authzModifier.getValue());
                        }
                    }
                    return meta;
                case MODIFY:
                case UPDATE:
                    PermRolesMeta build = authzModifier.build();
                    PermRolesMeta.Meta m = metaList.get(authzModifier.getIndex());
                    if (Arrays.asList(authzModifier.getTarget().with).contains("role")) {
                        if (build.getRequireRoles() != null)
                            m.setRequire(build.getRequireRoles());
                        if (build.getExcludeRoles() != null)
                            m.setExclude(build.getExcludeRoles());
                    } else {
                        if (build.getRequirePermissions() != null)
                            m.setRequire(build.getRequirePermissions());
                        if (build.getExcludePermissions() != null)
                            m.setExclude(build.getExcludePermissions());
                    }
                    if (authzModifier.getRange() != null) {
                        m.setRange(new HashSet<>(authzModifier.getRange()));
                    }
                    if (authzModifier.getResources() != null) {
                        m.setResources(new HashSet<>(authzModifier.getResources()));
                    }
                    return m;
                case GET:
                case READ:
                    if (authzModifier.getIndex() == null) {
                        return paramMetadata;
                    } else {
                        return metaList.get(authzModifier.getIndex());
                    }
                case NON:
                    return null;
            }

            return paramMetadata;
        } catch (Exception e) {
            return null;
        } finally {
            lock.unlock();
        }
    }

    private Object[] getParamMetaList(PermRolesMeta meta, AuthzModifier authzModifier) {
        boolean isAdd = authzModifier.getOperate() == AuthzModifier.Operate.ADD || authzModifier.getOperate() == AuthzModifier.Operate.OVERRIDE;
        ParamMetadata paramMetadata;
        if (meta == null) {
            if (isAdd) {

                Map<ParamMetadata.ParamType, Map<String, Class<?>>> paramTypeMapMap = rawMap.get(authzModifier.getMethod()).get(authzModifier.getApi());

                switch (authzModifier.getTarget().i) {
                    case 2:
                    case 3:
                        Class<?> aClass1 = paramTypeMapMap.get(ParamMetadata.ParamType.PATH_VARIABLE).get(authzModifier.getValue());
                        if (aClass1 != null) {
                            meta = authzMetadata.computeIfAbsent(authzModifier.getMethod(), r -> new HashMap<>())
                                    .computeIfAbsent(authzModifier.getApi(), r -> new PermRolesMeta());
                            ParamMetadata pmd = new ParamMetadata();
                            meta.put(ParamMetadata.ParamType.PATH_VARIABLE,
                                    authzModifier.getValue(),
                                    pmd.setParamType(aClass1));
                        } else {
                            return null;
                        }
                        break;
                    case 4:
                    case 5:
                        Class<?> aClass2 = paramTypeMapMap.get(ParamMetadata.ParamType.REQUEST_PARAM).get(authzModifier.getValue());
                        if (aClass2 != null) {
                            meta = authzMetadata.computeIfAbsent(authzModifier.getMethod(), r -> new HashMap<>())
                                    .computeIfAbsent(authzModifier.getApi(), r -> new PermRolesMeta());
                            ParamMetadata pmd = new ParamMetadata();
                            meta.put(ParamMetadata.ParamType.REQUEST_PARAM,
                                    authzModifier.getValue(),
                                    pmd.setParamType(aClass2));
                        } else {
                            return null;
                        }
                        break;
                    default:
                        return null;
                }
            } else {
                return null;
            }
        }
        switch (authzModifier.getTarget().i) {
            case 2:
                paramMetadata = meta.getParamPermissionsMetadata().get(ParamMetadata.ParamType.PATH_VARIABLE)
                        .computeIfAbsent(authzModifier.getValue(),
                                r -> new ParamMetadata().setParamType(rawMap.get(authzModifier.getMethod()).get(authzModifier.getApi()).get(ParamMetadata.ParamType.PATH_VARIABLE).get(authzModifier.getValue())));
                if (paramMetadata != null) {
                    List<PermRolesMeta.Meta> rolesMetaList = paramMetadata.getRolesMetaList();
                    if (rolesMetaList == null && isAdd) {
                        rolesMetaList = new ArrayList<>();
                        paramMetadata.setRolesMetaList(rolesMetaList);
                    }
                    return new Object[]{paramMetadata, paramMetadata.getRolesMetaList()};
                } else {
                    if (isAdd) {
                        paramMetadata = meta.getParamPermissionsMetadata().get(ParamMetadata.ParamType.PATH_VARIABLE).computeIfAbsent(authzModifier.getValue(), r -> new ParamMetadata());
                        paramMetadata.setRolesMetaList(new ArrayList<>());
                        return new Object[]{paramMetadata, paramMetadata.getRolesMetaList()};
                    } else {
                        return null;
                    }
                }
            case 3:
                paramMetadata = meta.getParamPermissionsMetadata().get(ParamMetadata.ParamType.PATH_VARIABLE).computeIfAbsent(authzModifier.getValue(),
                        r -> new ParamMetadata().setParamType(rawMap.get(authzModifier.getMethod()).get(authzModifier.getApi()).get(ParamMetadata.ParamType.PATH_VARIABLE).get(authzModifier.getValue())));

                if (paramMetadata != null) {
                    List<PermRolesMeta.Meta> permissionsMetaList = paramMetadata.getPermissionsMetaList();
                    if (permissionsMetaList == null && isAdd) {
                        permissionsMetaList = new ArrayList<>();
                        paramMetadata.setPermissionsMetaList(permissionsMetaList);
                    }
                    return new Object[]{paramMetadata, paramMetadata.getPermissionsMetaList()};
                } else {
                    if (isAdd) {
                        paramMetadata = meta.getParamPermissionsMetadata().get(ParamMetadata.ParamType.PATH_VARIABLE).computeIfAbsent(authzModifier.getValue(), r -> new ParamMetadata());
                        paramMetadata.setPermissionsMetaList(new ArrayList<>());
                        return new Object[]{paramMetadata, paramMetadata.getPermissionsMetaList()};

                    } else {
                        return null;
                    }
                }
            case 4:
                paramMetadata = meta.getParamPermissionsMetadata().get(ParamMetadata.ParamType.REQUEST_PARAM).computeIfAbsent(authzModifier.getValue(),
                        r -> new ParamMetadata().setParamType(rawMap.get(authzModifier.getMethod()).get(authzModifier.getApi()).get(ParamMetadata.ParamType.REQUEST_PARAM).get(authzModifier.getValue())));

                if (paramMetadata != null) {
                    List<PermRolesMeta.Meta> rolesMetaList = paramMetadata.getRolesMetaList();
                    if (rolesMetaList == null && isAdd) {
                        rolesMetaList = new ArrayList<>();
                        paramMetadata.setRolesMetaList(rolesMetaList);
                    }
                    return new Object[]{paramMetadata, paramMetadata.getRolesMetaList()};
                } else {
                    if (isAdd) {
                        paramMetadata = meta.getParamPermissionsMetadata().get(ParamMetadata.ParamType.REQUEST_PARAM).computeIfAbsent(authzModifier.getValue(), r -> new ParamMetadata());
                        paramMetadata.setRolesMetaList(new ArrayList<>());
                        return new Object[]{paramMetadata, paramMetadata.getRolesMetaList()};
                    } else {
                        return null;
                    }
                }
            case 5:
                paramMetadata = meta.getParamPermissionsMetadata().get(ParamMetadata.ParamType.REQUEST_PARAM).computeIfAbsent(authzModifier.getValue(),
                        r -> new ParamMetadata().setParamType(rawMap.get(authzModifier.getMethod()).get(authzModifier.getApi()).get(ParamMetadata.ParamType.REQUEST_PARAM).get(authzModifier.getValue())));

                if (paramMetadata != null) {
                    List<PermRolesMeta.Meta> permissionsMetaList = paramMetadata.getPermissionsMetaList();
                    if (permissionsMetaList == null && isAdd) {
                        permissionsMetaList = new ArrayList<>();
                        paramMetadata.setPermissionsMetaList(permissionsMetaList);
                    }
                    return new Object[]{paramMetadata, paramMetadata.getPermissionsMetaList()};

                } else {
                    if (isAdd) {
                        paramMetadata = meta.getParamPermissionsMetadata().get(ParamMetadata.ParamType.REQUEST_PARAM).computeIfAbsent(authzModifier.getValue(), r -> new ParamMetadata());
                        paramMetadata.setPermissionsMetaList(new ArrayList<>());
                        return new Object[]{paramMetadata, paramMetadata.getPermissionsMetaList()};

                    } else {
                        return null;
                    }
                }
        }
        return null;
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

    public static void initFieldMetadata(Map<String, Map<String, FieldData>> fieldMetadata) {
        if (PermissionDict.fieldMetadata != null) {
            AuInit.log.error("fieldMetadata 已经初始化");
            return;
        }
        PermissionDict.fieldMetadata = fieldMetadata;
        m4 = new UnmodifiableObservableMap<>(new ObservableMapWrapper<>(fieldMetadata));
    }

    public static void initArgs(Map<String, ArgsMeta> argsMetadata) {
        if (PermissionDict.argsMetadata != null) {
            AuInit.log.error("authzMetadata 已经初始化");
            return;
        }
        PermissionDict.argsMetadata = argsMetadata;
        m5 = new UnmodifiableObservableMap<>(new ObservableMapWrapper<>(argsMetadata));
    }

    public static void setPermSeparator(String permSeparator) {
        PermissionDict.permSeparator = permSeparator;
    }

    private static String permSeparator = ",";

    public static String getPermSeparator() {
        return permSeparator;
    }

}
