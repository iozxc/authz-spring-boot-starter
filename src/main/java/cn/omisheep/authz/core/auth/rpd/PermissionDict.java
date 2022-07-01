package cn.omisheep.authz.core.auth.rpd;

import cn.omisheep.authz.core.auth.AuthzModifiable;
import cn.omisheep.authz.core.auth.AuthzModifier;
import cn.omisheep.authz.core.init.AuInit;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.authz.support.util.IPRange;
import cn.omisheep.authz.support.util.IPRangeMeta;
import cn.omisheep.web.entity.Result;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.google.common.base.Objects;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Slf4j
public class PermissionDict implements AuthzModifiable {

    private static final AtomicInteger version = new AtomicInteger(0);

    private static PermissionDict SELF;

    public static PermissionDict self() {
        return SELF;
    }

    @Setter
    private static HashSet<IPRange> globalAllow;

    @Setter
    private static HashSet<IPRange> globalDeny;

    @Setter
    private static boolean supportNative;

    private static Map<String, Map<String, PermRolesMeta>> authzMetadata; // api权限和api的参数权限

    private static Map<String, Set<String>> certificatedMetadata; // certificatedMetadata 哪些接口需要登录-若有role和perms，则同同理

    private static Map<String, ArgsMeta> argsMetadata; // args

    private static Map<String, List<DataPermMeta>> dataPermMetadata; // 数据行权限

    private static Map<String, Map<String, FieldData>> fieldMetadata; // 数据列权限

    private static Map<String, Map<String, IPRangeMeta>> ipRangeMeta;

    private static final Map<String, Map<String, String>> authzResourcesNameAndTemplate = new HashMap<>();

    // String String ParamType String Class
    // method api ParamType paramName paramClass
    @Getter
    private static final Map<String, Map<String, Map<ParamMetadata.ParamType, Map<String, Class<?>>>>> rawMap = new HashMap<>();

    // ----------------------------------------- json ----------------------------------------- //

    private static       Map<String, Map<String, PermRolesMeta>>                                       m1;
    private static       Map<String, Map<String, String>>                                              m2;
    private static       Map<String, List<DataPermMeta>>                                               m3;
    private static       Map<String, Map<String, FieldData>>                                           m4;
    private static       Map<String, ArgsMeta>                                                         m5;
    private static final Map<String, Map<String, Map<ParamMetadata.ParamType, Map<String, Class<?>>>>> m6 =
            Collections.unmodifiableMap(rawMap);
    private static       Map<String, Map<String, IPRangeMeta>>                                         m7;
    private static       Map<String, Set<String>>                                                      m8;

    public boolean isSupportNative() {
        return PermissionDict.supportNative;
    }

    public Map<String, Map<String, PermRolesMeta>> getRolePermission() {
        return m1;
    }

    public Map<String, Map<String, String>> getResourcesNameAndTemplate() {
        return m2;
    }

    public Map<String, List<DataPermMeta>> getDataPermission() {
        return m3;
    }

    public Map<String, Map<String, FieldData>> getFieldsData() {
        return m4;
    }

    public Map<String, ArgsMeta> getArgs() {
        return m5;
    }

    public Map<String, Map<String, Map<ParamMetadata.ParamType, Map<String, Class<?>>>>> getRawParamMap() {
        return m6;
    }

    public Map<String, Map<String, IPRangeMeta>> getIPRange() {
        return m7;
    }

    public Map<String, Set<String>> getCertificatedMetadata() {
        return m8;
    }

    public HashSet<IPRange> getGlobalAllow() {return globalAllow;}

    public HashSet<IPRange> getGlobalDeny()  {return globalDeny;}

    @Getter
    public static class ArgsMeta {
        private final Class<?>            type;
        private final Method              method;
        private final List<Class<?>>      parameterList;
        private final Class<?>            returnType;
        @JsonInclude(JsonInclude.Include.NON_EMPTY)
        private final Map<String, String> returnTypeTemplate;

        private ArgsMeta(Class<?> type, Method method) {
            this.type               = type;
            this.method             = method;
            this.returnType         = method.getReturnType();
            this.parameterList      = Arrays.stream(method.getParameterTypes()).collect(Collectors.toList());
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

    @Nullable
    public Object modify(@NonNull AuthzModifier authzModifier) {
        try {
            if (authzModifier.getTarget() == null) {
                return modifyParam(authzModifier);
            }
            switch (authzModifier.getTarget()) {
                case API:
                    return modifyAPI(authzModifier);
                case PATH:
                case PARAM:
                case PATH_VARIABLE_PERMISSION:
                case PATH_VAR_PERMISSION:
                case PATH_VARIABLE_ROLE:
                case PATH_VAR_ROLE:
                case REQUEST_PARAM_ROLE:
                case PARAM_ROLE:
                case REQUEST_PARAM_PERMISSION:
                case PARAM_PERMISSION:
                    return modifyParam(authzModifier);
                case DATA_ROW:
                case DATA_COL:
                    return modifyData(authzModifier);
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

    public Object modifyAPI(AuthzModifier authzModifier) {
        lock.lock();
        try {
            switch (authzModifier.getOperate()) {
                case ADD: {
                    Map<String, PermRolesMeta> target = authzMetadata.get(authzModifier.getMethod());
                    PermRolesMeta              build  = authzModifier.build();
                    target.put(authzModifier.getApi(), build);
                    if (build.non()) certificatedMetadata.get(authzModifier.getMethod()).remove(authzModifier.getApi());
                    else certificatedMetadata.get(authzModifier.getMethod()).add(authzModifier.getApi());
                    return Result.SUCCESS;
                }
                case MODIFY:
                case UPDATE: {
                    authzMetadata.get(authzModifier.getMethod())
                            .get(authzModifier.getApi())
                            .merge(authzModifier.build());
                    if (authzMetadata.get(authzModifier.getMethod()).get(authzModifier.getApi()).non()) {
                        certificatedMetadata.get(authzModifier.getMethod()).remove(authzModifier.getApi());
                    } else {
                        certificatedMetadata.get(authzModifier.getMethod()).add(authzModifier.getApi());
                    }
                    return Result.SUCCESS;
                }
                case DELETE:
                case DEL: {
                    authzMetadata.get(authzModifier.getMethod())
                            .get(authzModifier.getApi()).removeApi();
                    certificatedMetadata.get(authzModifier.getMethod()).remove(authzModifier.getApi());
                    return Result.SUCCESS;
                }
                case GET:
                case READ:
                    if (authzModifier.getApi() == null && authzModifier.getMethod() == null) return authzMetadata;
                    if (authzModifier.getApi() == null) return authzMetadata.get(authzModifier.getMethod());
                    if (authzModifier.getMethod() == null) {
                        HashMap<String, List<PermRolesMeta>> mp = new HashMap<>();
                        authzMetadata.forEach((k, v) -> v.entrySet().stream().map(e -> {
                            if (e.getKey().equals(authzModifier.getApi())) return e.getValue();
                            return null;
                        }).filter(java.util.Objects::nonNull).forEach(s -> mp.computeIfAbsent(k, r -> new ArrayList<>()).add(s)));
                        return mp;
                    }
                    Map<String, PermRolesMeta> target = authzMetadata.get(authzModifier.getMethod());
                    return target.get(authzModifier.getApi());
                default:
                    return Result.FAIL;
            }
        } catch (Exception e) {
            return Result.FAIL;
        } finally {
            lock.unlock();
        }
    }

    @SuppressWarnings("all")
    public Object modifyParam(AuthzModifier authzModifier) {
        lock.lock();
        try {
            PermRolesMeta        meta   = authzMetadata.get(authzModifier.getMethod()).get(authzModifier.getApi());
            AuthzModifier.Target target = authzModifier.getTarget();

            if (target == null &&
                    (authzModifier.getOperate() == AuthzModifier.Operate.GET || authzModifier.getOperate() == AuthzModifier.Operate.READ)) {
                if (authzModifier.getTarget() == null && authzModifier.getValue() == null)
                    return meta.getParamPermissionsMetadata();
                HashMap<Object, Object>    map = new HashMap<>();
                Map<String, ParamMetadata> m1  = meta.getParamPermissionsMetadata().get(ParamMetadata.ParamType.PATH_VARIABLE);
                Map<String, ParamMetadata> m2  = meta.getParamPermissionsMetadata().get(ParamMetadata.ParamType.REQUEST_PARAM);
                if (m1 != null && m1.containsKey(authzModifier.getValue())) map.put("PATH_VARIABLE", m1.get(authzModifier.getValue()));
                if (m2 != null && m2.containsKey(authzModifier.getValue())) map.put("REQUEST_PARAM", m2.get(authzModifier.getValue()));
                return map;
            }

            Object[] objects = getParamMetaList(meta, authzModifier);


            ParamMetadata            paramMetadata = (ParamMetadata) objects[0];
            List<PermRolesMeta.Meta> metaList      = (List<PermRolesMeta.Meta>) objects[1]; // 可能需要操作的list

            if (metaList == null) {
                return Result.FAIL;
            }

            switch (authzModifier.getOperate()) {
                case ADD:
                    PermRolesMeta.Meta _m;
                    if (authzModifier.getTarget().contains("role")) {
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
                        if (target == AuthzModifier.Target.PATH) {
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
                    if (authzModifier.getTarget().contains("role")) {
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
                    return Result.SUCCESS;
            }

            return paramMetadata;
        } catch (Exception e) {
            return Result.FAIL;
        } finally {
            lock.unlock();
        }
    }

    private Object[] getParamMetaList(PermRolesMeta meta, AuthzModifier authzModifier) {
        boolean       isAdd = authzModifier.getOperate() == AuthzModifier.Operate.ADD;
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

    public Object modifyData(AuthzModifier authzModifier) {
        try {
            lock.lock();
            String className = authzModifier.getClassName();
            if (className == null) {
                if (authzModifier.getTarget() == AuthzModifier.Target.DATA_COL) {
                    return fieldMetadata;
                } else if (authzModifier.getTarget() == AuthzModifier.Target.DATA_ROW) {
                    return dataPermMetadata;
                }
                return Result.FAIL;
            }
            if (authzResourcesNameAndTemplate.get(className) == null) return Result.FAIL;
            if (authzModifier.getTarget() == AuthzModifier.Target.DATA_ROW) {
                switch (authzModifier.getOperate()) {
                    case ADD:
                        DataPermMeta dataPermMeta;
                        Rule rule = authzModifier.getRule();
                        if (rule == null) {
                            dataPermMeta = DataPermMeta.of(authzModifier.getCondition());
                        } else {
                            dataPermMeta = DataPermMeta.of(rule);
                        }
                        PermRolesMeta build = authzModifier.build();
                        dataPermMeta.setRoles(build.role);
                        dataPermMeta.setPermissions(build.permissions);
                        dataPermMeta.setArgsMap(authzModifier.getArgsMap());
                        dataPermMetadata.computeIfAbsent(className, r -> new ArrayList<>()).add(dataPermMeta);
                        break;
                    case MODIFY:
                    case UPDATE:
                        if (authzModifier.getIndex() == null) return Result.FAIL;
                        if (dataPermMetadata.get(className) == null) return Result.FAIL;
                        DataPermMeta old_data_mata = dataPermMetadata.get(className).get(authzModifier.getIndex());
                        DataPermMeta new_data_mata = null;

                        if (authzModifier.getCondition() != null) {
                            new_data_mata = DataPermMeta.of(authzModifier.getCondition());
                        }
                        if (authzModifier.getRule() != null) {
                            new_data_mata = DataPermMeta.of(authzModifier.getRule());
                        }
                        if (new_data_mata != null) {
                            old_data_mata.setRule(new_data_mata.getRule());
                            old_data_mata.setCondition(new_data_mata.getCondition());
                        }
                        PermRolesMeta build_new = authzModifier.build();
                        if (build_new.role != null) {
                            old_data_mata.setRoles(build_new.role);
                        }
                        if (build_new.permissions != null) {
                            old_data_mata.setPermissions(build_new.permissions);
                        }
                        if (authzModifier.getArgsMap() != null) {
                            old_data_mata.setArgsMap(authzModifier.getArgsMap());
                        }
                        break;
                    case DEL:
                    case DELETE:
                        Integer index = authzModifier.getIndex();
                        if (dataPermMetadata.get(className) == null) return Result.FAIL;
                        if (index == null) dataPermMetadata.get(className).clear();
                        else dataPermMetadata.get(className).remove(index.intValue());
                        break;
                    case GET:
                    case READ:
                        if (dataPermMetadata.get(className) == null) return dataPermMetadata;
                        if (authzModifier.getIndex() == null) return dataPermMetadata.get(className);
                        else return dataPermMetadata.get(className).get(authzModifier.getIndex());
                    default:
                        return Result.FAIL;
                }
                return dataPermMetadata.get(className);
            } else {
                switch (authzModifier.getOperate()) {
                    case ADD: {
                        if (authzModifier.getFieldName() == null) return Result.FAIL;
                        PermRolesMeta build     = authzModifier.build();
                        FieldData     fieldData = new FieldData(className, build.role, build.permissions);
                        fieldMetadata.computeIfAbsent(className, r -> new HashMap<>()).put(authzModifier.getFieldName(), fieldData);
                    }

                    case UPDATE:
                    case MODIFY: {
                        if (authzModifier.getFieldName() == null) return Result.FAIL;
                        PermRolesMeta build     = authzModifier.build();
                        FieldData     fieldData = new FieldData(className, build.role, build.permissions);
                        FieldData     fd        = fieldMetadata.computeIfAbsent(className, r -> new HashMap<>()).computeIfAbsent(authzModifier.getFieldName(), r -> new FieldData(className, null, null));
                        if (fieldData.getPermissions() != null) fd.setPermissions(fieldData.getPermissions());
                        if (fieldData.getRoles() != null) fd.setRoles(fieldData.getRoles());
                    }

                    case READ:
                    case GET: {
                        return fieldMetadata.get(authzModifier.getFieldName());
                    }

                    case DELETE:
                    case DEL: {
                        if (authzModifier.getFieldName() == null) {
                            fieldMetadata.remove(className);
                        } else {
                            fieldMetadata.get(className).remove(authzModifier.getFieldName());
                        }
                        return Result.SUCCESS;
                    }
                }
            }
            return Result.FAIL;
        } catch (Exception e) {
            return Result.FAIL;
        } finally {
            lock.unlock();
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

        m1 = Collections.unmodifiableMap(authzMetadata);
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
        m2 = Collections.unmodifiableMap(authzResourcesNameAndTemplate);
        AuInit.log.info("authz resources add success ⬇: \n{}", names);
    }

    public static void initDataPerm(Map<String, List<DataPermMeta>> dataPermMetadata) {
        if (PermissionDict.dataPermMetadata != null) {
            AuInit.log.error("dataPermMetadata 已经初始化");
            return;
        }
        PermissionDict.dataPermMetadata = dataPermMetadata;
        m3                              = Collections.unmodifiableMap(dataPermMetadata);
    }

    public static void initFieldMetadata(Map<String, Map<String, FieldData>> fieldMetadata) {
        if (PermissionDict.fieldMetadata != null) {
            AuInit.log.error("fieldMetadata 已经初始化");
            return;
        }
        PermissionDict.fieldMetadata = fieldMetadata;
        m4                           = Collections.unmodifiableMap(fieldMetadata);
    }

    public static void initArgs(Map<String, ArgsMeta> argsMetadata) {
        if (PermissionDict.argsMetadata != null) {
            AuInit.log.error("authzMetadata 已经初始化");
            return;
        }
        PermissionDict.argsMetadata = argsMetadata;
        m5                          = Collections.unmodifiableMap(argsMetadata);
    }

    public static void initIPRangeMeta(Map<String, Map<String, IPRangeMeta>> ipRangeMeta) {
        if (PermissionDict.ipRangeMeta != null) {
            AuInit.log.error("ipRangeMeta 已经初始化");
            return;
        }
        PermissionDict.ipRangeMeta = ipRangeMeta;

        m7 = Collections.unmodifiableMap(ipRangeMeta);
    }

    public static void initCertificatedMetadata(Map<String, Set<String>> certificatedMetadata) {
        if (PermissionDict.certificatedMetadata != null) {
            AuInit.log.error("certificatedMetadata 已经初始化");
            return;
        }
        PermissionDict.certificatedMetadata = certificatedMetadata;
        m8                                  = Collections.unmodifiableMap(certificatedMetadata);
    }

    public static void setPermSeparator(String permSeparator) {
        PermissionDict.permSeparator = permSeparator;
    }

    private static String permSeparator = ",";

    public static String getPermSeparator() {
        return permSeparator;
    }

}
