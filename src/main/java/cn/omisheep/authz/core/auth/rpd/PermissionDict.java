package cn.omisheep.authz.core.auth.rpd;

import cn.omisheep.authz.annotation.*;
import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.config.AuInit;
import cn.omisheep.authz.core.config.Constants;
import cn.omisheep.authz.core.msg.AuthzModifier;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.authz.core.util.RedisUtils;
import cn.omisheep.authz.core.util.ValueMatcher;
import cn.omisheep.authz.support.util.IPRange;
import cn.omisheep.authz.support.util.IPRangeMeta;
import cn.omisheep.commons.util.Async;
import cn.omisheep.web.entity.Result;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.google.common.base.Objects;
import lombok.Getter;
import org.springframework.boot.autoconfigure.web.servlet.error.BasicErrorController;
import org.springframework.context.ApplicationContext;
import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.*;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;

import static cn.omisheep.authz.core.auth.rpd.ParamMetadata.ParamType.PATH_VARIABLE;
import static cn.omisheep.authz.core.auth.rpd.ParamMetadata.ParamType.REQUEST_PARAM;
import static cn.omisheep.authz.core.util.MetaUtils.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class PermissionDict {

    private static final Map<String, List<Map<String, String>>> _controllerMetadata = new HashMap<>();

    private static final Map<String, Map<String, PermRolesMeta>> _authzMetadata = new HashMap<>(); // api权限和api的参数权限

    private static final Map<String, Set<String>> _certificatedMetadata = new HashMap<>(); // certificatedMetadata 哪些接口需要登录-若有role和perms，则同同理

    private static final Map<String, ArgsMeta> _argsMetadata = new HashMap<>(); // args

    private static final Map<String, List<DataPermMeta>> _dataPermMetadata = new HashMap<>(); // 数据行权限

    private static final Map<String, Map<String, FieldData>> _fieldMetadata = new HashMap<>(); // 数据列权限

    private static final Map<String, Map<String, IPRangeMeta>> _ipRangeMeta = new HashMap<>();

    private static final Map<String, Map<String, String>> _authzResourcesNameAndTemplate = new HashMap<>();

    private static final Map<String, Map<String, Map<ParamMetadata.ParamType, Map<String, Class<?>>>>> _rawMap = new HashMap<>();

    private static boolean _supportNative;

    private static final Set<IPRange> _globalAllow = new HashSet<>();

    private static final Set<IPRange> _globalDeny = new HashSet<>();

    // ----------------------------------------- unModify ----------------------------------------- //

    @Getter
    private static final Map<String, Map<String, PermRolesMeta>>                                       rolePermission           = Collections.unmodifiableMap(
            _authzMetadata);
    @Getter
    private static final Map<String, Map<String, String>>                                              resourcesNameAndTemplate = Collections.unmodifiableMap(
            _authzResourcesNameAndTemplate);
    @Getter
    private static final Map<String, List<DataPermMeta>>                                               dataPermission           = Collections.unmodifiableMap(
            _dataPermMetadata);
    @Getter
    private static final Map<String, Map<String, FieldData>>                                           fieldsData               = Collections.unmodifiableMap(
            _fieldMetadata);
    @Getter
    private static final Map<String, ArgsMeta>                                                         args                     = Collections.unmodifiableMap(
            _argsMetadata);
    @Getter
    private static final Map<String, Map<String, Map<ParamMetadata.ParamType, Map<String, Class<?>>>>> rawParamMap              =
            Collections.unmodifiableMap(_rawMap);
    @Getter
    private static final Map<String, Map<String, IPRangeMeta>>                                         iPRange                  = Collections.unmodifiableMap(
            _ipRangeMeta);
    @Getter
    private static final Map<String, Set<String>>                                                      certificatedMetadata     = Collections.unmodifiableMap(
            _certificatedMetadata);
    @Getter
    private static final Set<IPRange>                                                                  globalAllow              = Collections.unmodifiableSet(
            _globalAllow);
    @Getter
    private static final Set<IPRange>                                                                  globalDeny               = Collections.unmodifiableSet(
            _globalDeny);
    @Getter
    private static final Map<String, List<Map<String, String>>>                                        controllerMetadata       = Collections.unmodifiableMap(
            _controllerMetadata);

    public static boolean isSupportNative() {
        return PermissionDict._supportNative;
    }

    @Getter
    public static class ArgsMeta {
        private final Class<?>            type;
        private final Method              method;
        @JsonInclude(JsonInclude.Include.NON_EMPTY)
        private final List<Class<?>>      parameterList;
        private final Class<?>            returnType;
        @JsonInclude(JsonInclude.Include.NON_EMPTY)
        private final Map<String, String> returnTypeTemplate;

        private ArgsMeta(Class<?> type,
                         Method method) {
            this.type               = type;
            this.method             = method;
            this.returnType         = method.getReturnType();
            this.parameterList      = Arrays.stream(method.getParameterTypes()).collect(Collectors.toList());
            this.returnTypeTemplate = parseTypeForTemplate(this.returnType.getTypeName());
        }

        public String getMethod() {
            return method.getName();
        }

        public static ArgsMeta of(Class<?> type,
                                  Method method) {
            return new ArgsMeta(type, method);
        }

        public static ArgsMeta of(Class<?> type,
                                  String methodName,
                                  Class<?>... args) {
            try {
                return new ArgsMeta(type, type.getMethod(methodName, args));
            } catch (NoSuchMethodException e) {
                LogUtils.error("NoSuchMethodException", e);
                return null;
            }
        }

        public static ArgsMeta of(Object type,
                                  String methodName,
                                  Class<?>... args) {
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
    public static Object modify(@NonNull AuthzModifier authzModifier) {
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
    }

    public static List<Class<?>> argType(String argsName) {
        ArgsMeta meta = _argsMetadata.get(argsName);
        if (meta == null) return null;
        return meta.parameterList;
    }

    public static Object argsHandle(String argName,
                                    Object... otherArgs) {
        ArgsMeta meta = _argsMetadata.get(argName);
        if (meta == null) {
            LogUtils.error("arg {} is null", argName);
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
            Class<?> clz = Class.forName(className);
            for (Method method : clz.getMethods()) {
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
                    typeTemplate.put(field, method.getReturnType().getTypeName());
                }
            }
        } catch (Exception e) {
            return new HashMap<>();
        }
        return typeTemplate;
    }

    private final static ReentrantLock lock = new ReentrantLock();

    public static Object modifyAPI(AuthzModifier authzModifier) {
        lock.lock();
        try {
            switch (authzModifier.getOperate()) {
                case ADD: {
                    Map<String, PermRolesMeta> target = _authzMetadata.get(authzModifier.getApi());
                    PermRolesMeta              build  = authzModifier.build();
                    target.put(authzModifier.getMethod(), build);
                    if (build.non()) {
                        _certificatedMetadata.get(authzModifier.getApi()).remove(
                                authzModifier.getMethod());
                    } else {_certificatedMetadata.get(authzModifier.getApi()).add(authzModifier.getMethod());}
                    return Result.SUCCESS;
                }
                case MODIFY:
                case UPDATE: {
                    _authzMetadata.get(authzModifier.getApi())
                            .get(authzModifier.getMethod())
                            .merge(authzModifier.build());
                    if (_authzMetadata.get(authzModifier.getApi()).get(authzModifier.getMethod()).non()) {
                        _certificatedMetadata.get(authzModifier.getApi()).remove(authzModifier.getMethod());
                    } else {
                        _certificatedMetadata.get(authzModifier.getApi()).add(authzModifier.getMethod());
                    }
                    return Result.SUCCESS;
                }
                case DELETE:
                case DEL: {
                    _authzMetadata.get(authzModifier.getApi())
                            .get(authzModifier.getMethod()).removeApi();
                    _certificatedMetadata.get(authzModifier.getApi()).remove(authzModifier.getMethod());
                    return Result.SUCCESS;
                }
                case GET:
                case READ:
                    if (authzModifier.getApi() == null && authzModifier.getMethod() == null) return rolePermission;
                    if (authzModifier.getApi() == null) {
                        return rolePermission.values().stream().filter(
                                stringPermRolesMetaMap -> stringPermRolesMetaMap.containsKey(
                                        authzModifier.getMethod())).map(
                                stringPermRolesMetaMap -> stringPermRolesMetaMap.get(
                                        authzModifier.getMethod())).collect(Collectors.toList());
                    }
                    if (authzModifier.getMethod() == null) {
                        return rolePermission.get(authzModifier.getApi());
                    }
                    return rolePermission.get(authzModifier.getApi()).get(authzModifier.getMethod());
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
    public static Object modifyParam(AuthzModifier authzModifier) {
        lock.lock();
        try {
            PermRolesMeta        meta   = _authzMetadata.get(authzModifier.getApi()).get(authzModifier.getMethod());
            AuthzModifier.Target target = authzModifier.getTarget();

            if (target == null &&
                    (authzModifier.getOperate() == AuthzModifier.Operate.GET || authzModifier.getOperate() == AuthzModifier.Operate.READ)) {
                if (authzModifier.getTarget() == null && authzModifier.getValue() == null) {
                    return meta.getParamPermissionsMetadata();
                }
                HashMap<Object, Object>    map = new HashMap<>();
                Map<String, ParamMetadata> m1  = meta.getParamPermissionsMetadata().get(PATH_VARIABLE);
                Map<String, ParamMetadata> m2  = meta.getParamPermissionsMetadata().get(REQUEST_PARAM);
                if (m1 != null && m1.containsKey(authzModifier.getValue())) {
                    map.put(PATH_VARIABLE.getVal(),
                            m1.get(authzModifier.getValue()));
                }
                if (m2 != null && m2.containsKey(authzModifier.getValue())) {
                    map.put(REQUEST_PARAM.getVal(),
                            m2.get(authzModifier.getValue()));
                }
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
                    if (authzModifier.getIndex() != null) {
                        metaList.remove(metaList.get(authzModifier.getIndex()));
                    } else {
                        if (target == AuthzModifier.Target.PATH) {
                            meta.getParamPermissionsMetadata().get(PATH_VARIABLE).remove(authzModifier.getValue());
                        } else {
                            meta.getParamPermissionsMetadata().get(REQUEST_PARAM).remove(authzModifier.getValue());
                        }
                    }
                    return meta;
                case MODIFY:
                case UPDATE:
                    PermRolesMeta build = authzModifier.build();
                    PermRolesMeta.Meta m = metaList.get(authzModifier.getIndex());
                    if (authzModifier.getTarget().contains("role")) {
                        if (build.getRequireRoles() != null) {m.setRequire(build.getRequireRoles());}
                        if (build.getExcludeRoles() != null) {m.setExclude(build.getExcludeRoles());}
                    } else {
                        if (build.getRequirePermissions() != null) {m.setRequire(build.getRequirePermissions());}
                        if (build.getExcludePermissions() != null) {m.setExclude(build.getExcludePermissions());}
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

    private static Object[] getParamMetaList(PermRolesMeta meta,
                                             AuthzModifier authzModifier) {
        boolean       isAdd = authzModifier.getOperate() == AuthzModifier.Operate.ADD;
        ParamMetadata paramMetadata;
        if (meta == null) {
            if (isAdd) {

                Map<ParamMetadata.ParamType, Map<String, Class<?>>> paramTypeMapMap = _rawMap.get(
                        authzModifier.getApi()).get(authzModifier.getMethod());

                switch (authzModifier.getTarget().i) {
                    case 2:
                    case 3:
                        Class<?> aClass1 = paramTypeMapMap.get(PATH_VARIABLE).get(authzModifier.getValue());
                        if (aClass1 != null) {
                            meta = _authzMetadata.computeIfAbsent(authzModifier.getApi(), r -> new HashMap<>())
                                    .computeIfAbsent(authzModifier.getMethod(), r -> new PermRolesMeta());
                            ParamMetadata pmd = new ParamMetadata();
                            meta.put(PATH_VARIABLE,
                                     authzModifier.getValue(),
                                     pmd.setParamType(aClass1));
                        } else {
                            return null;
                        }
                        break;
                    case 4:
                    case 5:
                        Class<?> aClass2 = paramTypeMapMap.get(REQUEST_PARAM).get(authzModifier.getValue());
                        if (aClass2 != null) {
                            meta = _authzMetadata.computeIfAbsent(authzModifier.getApi(), r -> new HashMap<>())
                                    .computeIfAbsent(authzModifier.getMethod(), r -> new PermRolesMeta());
                            ParamMetadata pmd = new ParamMetadata();
                            meta.put(REQUEST_PARAM,
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
                paramMetadata = meta.getParamPermissionsMetadata().get(PATH_VARIABLE)
                        .computeIfAbsent(authzModifier.getValue(),
                                         r -> new ParamMetadata().setParamType(
                                                 _rawMap.get(authzModifier.getApi()).get(authzModifier.getMethod()).get(
                                                         PATH_VARIABLE).get(authzModifier.getValue())));
                if (paramMetadata != null) {
                    List<PermRolesMeta.Meta> rolesMetaList = paramMetadata.getRolesMetaList();
                    if (rolesMetaList == null && isAdd) {
                        rolesMetaList = new ArrayList<>();
                        paramMetadata.setRolesMetaList(rolesMetaList);
                    }
                    return new Object[]{paramMetadata, paramMetadata.getRolesMetaList()};
                } else {
                    if (isAdd) {
                        paramMetadata = meta.getParamPermissionsMetadata().get(PATH_VARIABLE).computeIfAbsent(
                                authzModifier.getValue(), r -> new ParamMetadata());
                        paramMetadata.setRolesMetaList(new ArrayList<>());
                        return new Object[]{paramMetadata, paramMetadata.getRolesMetaList()};
                    } else {
                        return null;
                    }
                }
            case 3:
                paramMetadata = meta.getParamPermissionsMetadata().get(PATH_VARIABLE).computeIfAbsent(
                        authzModifier.getValue(),
                        r -> new ParamMetadata().setParamType(
                                _rawMap.get(authzModifier.getApi()).get(authzModifier.getMethod()).get(
                                        PATH_VARIABLE).get(authzModifier.getValue())));
                if (paramMetadata != null) {
                    List<PermRolesMeta.Meta> permissionsMetaList = paramMetadata.getPermissionsMetaList();
                    if (permissionsMetaList == null && isAdd) {
                        permissionsMetaList = new ArrayList<>();
                        paramMetadata.setPermissionsMetaList(permissionsMetaList);
                    }
                    return new Object[]{paramMetadata, paramMetadata.getPermissionsMetaList()};
                } else {
                    if (isAdd) {
                        paramMetadata = meta.getParamPermissionsMetadata().get(PATH_VARIABLE).computeIfAbsent(
                                authzModifier.getValue(), r -> new ParamMetadata());
                        paramMetadata.setPermissionsMetaList(new ArrayList<>());
                        return new Object[]{paramMetadata, paramMetadata.getPermissionsMetaList()};

                    } else {
                        return null;
                    }
                }
            case 4:
                paramMetadata = meta.getParamPermissionsMetadata().get(REQUEST_PARAM).computeIfAbsent(
                        authzModifier.getValue(),
                        r -> new ParamMetadata().setParamType(
                                _rawMap.get(authzModifier.getApi()).get(authzModifier.getMethod()).get(
                                        REQUEST_PARAM).get(authzModifier.getValue())));
                if (paramMetadata != null) {
                    List<PermRolesMeta.Meta> rolesMetaList = paramMetadata.getRolesMetaList();
                    if (rolesMetaList == null && isAdd) {
                        rolesMetaList = new ArrayList<>();
                        paramMetadata.setRolesMetaList(rolesMetaList);
                    }
                    return new Object[]{paramMetadata, paramMetadata.getRolesMetaList()};
                } else {
                    if (isAdd) {
                        paramMetadata = meta.getParamPermissionsMetadata().get(REQUEST_PARAM).computeIfAbsent(
                                authzModifier.getValue(), r -> new ParamMetadata());
                        paramMetadata.setRolesMetaList(new ArrayList<>());
                        return new Object[]{paramMetadata, paramMetadata.getRolesMetaList()};
                    } else {
                        return null;
                    }
                }
            case 5:
                paramMetadata = meta.getParamPermissionsMetadata().get(REQUEST_PARAM).computeIfAbsent(
                        authzModifier.getValue(),
                        r -> new ParamMetadata().setParamType(
                                _rawMap.get(authzModifier.getApi()).get(authzModifier.getMethod()).get(
                                        REQUEST_PARAM).get(authzModifier.getValue())));
                if (paramMetadata != null) {
                    List<PermRolesMeta.Meta> permissionsMetaList = paramMetadata.getPermissionsMetaList();
                    if (permissionsMetaList == null && isAdd) {
                        permissionsMetaList = new ArrayList<>();
                        paramMetadata.setPermissionsMetaList(permissionsMetaList);
                    }
                    return new Object[]{paramMetadata, paramMetadata.getPermissionsMetaList()};

                } else {
                    if (isAdd) {
                        paramMetadata = meta.getParamPermissionsMetadata().get(REQUEST_PARAM).computeIfAbsent(
                                authzModifier.getValue(), r -> new ParamMetadata());
                        paramMetadata.setPermissionsMetaList(new ArrayList<>());
                        return new Object[]{paramMetadata, paramMetadata.getPermissionsMetaList()};

                    } else {
                        return null;
                    }
                }
        }
        return null;
    }

    public static Object modifyData(AuthzModifier authzModifier) {
        try {
            lock.lock();
            String className = authzModifier.getClassName();
            if (className == null) {
                if (authzModifier.getTarget() == AuthzModifier.Target.DATA_COL) {
                    return fieldsData;
                } else if (authzModifier.getTarget() == AuthzModifier.Target.DATA_ROW) {
                    return dataPermission;
                }
                return Result.FAIL;
            }
            if (_authzResourcesNameAndTemplate.get(className) == null) return Result.FAIL;
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
                        _dataPermMetadata.computeIfAbsent(className, r -> new ArrayList<>()).add(dataPermMeta);
                        break;
                    case MODIFY:
                    case UPDATE:
                        if (authzModifier.getIndex() == null) return Result.FAIL;
                        if (_dataPermMetadata.get(className) == null) return Result.FAIL;
                        DataPermMeta old_data_mata = _dataPermMetadata.get(className).get(authzModifier.getIndex());
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
                        if (_dataPermMetadata.get(className) == null) return Result.FAIL;
                        if (index == null) {_dataPermMetadata.get(className).clear();} else {
                            _dataPermMetadata.get(
                                    className).remove(index.intValue());
                        }
                        break;
                    case GET:
                    case READ:
                        if (_dataPermMetadata.get(className) == null) return dataPermission;
                        if (authzModifier.getIndex() == null) {return dataPermission.get(className);} else {
                            return dataPermission.get(className).get(authzModifier.getIndex());
                        }
                    default:
                        return Result.FAIL;
                }
                return dataPermission.get(className);
            } else {
                switch (authzModifier.getOperate()) {
                    case ADD: {
                        if (authzModifier.getFieldName() == null) return Result.FAIL;
                        PermRolesMeta build     = authzModifier.build();
                        FieldData     fieldData = new FieldData(className, build.role, build.permissions);
                        _fieldMetadata.computeIfAbsent(className, r -> new HashMap<>()).put(
                                authzModifier.getFieldName(),
                                fieldData);
                    }

                    case UPDATE:
                    case MODIFY: {
                        if (authzModifier.getFieldName() == null) return Result.FAIL;
                        PermRolesMeta build     = authzModifier.build();
                        FieldData     fieldData = new FieldData(className, build.role, build.permissions);
                        FieldData fd = _fieldMetadata.computeIfAbsent(className,
                                                                      r -> new HashMap<>()).computeIfAbsent(
                                authzModifier.getFieldName(), r -> new FieldData(className, null, null));
                        if (fieldData.getPermissions() != null) fd.setPermissions(fieldData.getPermissions());
                        if (fieldData.getRoles() != null) fd.setRoles(fieldData.getRoles());
                    }

                    case READ:
                    case GET: {
                        return fieldsData.get(authzModifier.getFieldName());
                    }

                    case DELETE:
                    case DEL: {
                        if (authzModifier.getFieldName() == null) {
                            _fieldMetadata.remove(className);
                        } else {
                            _fieldMetadata.get(className).remove(authzModifier.getFieldName());
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

    public static void setPermSeparator(String permSeparator) {
        PermissionDict.permSeparator = permSeparator;
    }

    private static String permSeparator = ",";

    public static String getPermSeparator() {
        return permSeparator;
    }

    private static boolean isInit     = false;
    private static boolean isInitArgs = false;

    public static void initArgs(Set<String> authzResourcesNames,
                                Map<String, Map<String, FieldData>> fieldMetadata,
                                HashMap<String, List<DataPermMeta>> map,
                                HashMap<String, PermissionDict.ArgsMeta> args) {
        if (isInitArgs) {
            AuInit.log.error("PermissionDict已初始化");
        }
        isInitArgs = true;
        for (String authzResourcesName : authzResourcesNames) {
            try {
                Map<String, String> fieldMap = _authzResourcesNameAndTemplate.computeIfAbsent(authzResourcesName,
                                                                                              r -> new HashMap<>());
                fieldMap.putAll(parseTypeForTemplate(authzResourcesName));
            } catch (Exception ignored) {
            }
        }
        _fieldMetadata.putAll(fieldMetadata);
        _dataPermMetadata.putAll(map);
        _argsMetadata.putAll(args);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    public static void init(AuthzProperties properties,
                            ApplicationContext applicationContext,
                            PermLibrary permLibrary,
                            Cache cache,
                            Map<RequestMappingInfo, HandlerMethod> mapRet) {
        if (isInit) {
            AuInit.log.error("PermissionDict已初始化");
        }
        isInit = true;

        PermissionDict.setPermSeparator(Constants.COMMA);
        Set<String>                toBeLoadedRoles = new HashSet<>();
        Map<String, PermRolesMeta> pMap            = new HashMap<>();
        Map<String, PermRolesMeta> rMap            = new HashMap<>();
        Map<String, IPRangeMeta>   iMap            = new HashMap<>();
        LinkedList<String>         cList           = new LinkedList<>();

        applicationContext.getBeansWithAnnotation(Roles.class).forEach((key, value) -> {
            String name  = getTypeName(value);
            Roles  roles = getAnnotation(value, Roles.class);
            if (roles != null) {
                cList.add(getTypeName(value));
                rMap.put(name, generatePermRolesMeta(null, roles));
            }
        });

        applicationContext.getBeansWithAnnotation(Perms.class).forEach((key, value) -> {
            String name  = getTypeName(value);
            Perms  perms = getAnnotation(value, Perms.class);
            if (perms != null) {
                cList.add(getTypeName(value));
                pMap.put(name, generatePermRolesMeta(perms, null));
            }
        });

        applicationContext.getBeansWithAnnotation(Certificated.class).forEach((key, value) -> {
            Certificated certificated = getAnnotation(value, Certificated.class);
            if (certificated != null) {
                cList.add(getTypeName(value));
            }
        });

        applicationContext.getBeansWithAnnotation(IPRangeLimit.class).forEach((key, value) -> {
            IPRangeLimit ipRangeLimit = getAnnotation(value, IPRangeLimit.class);
            if (ipRangeLimit == null) return;
            iMap.put(getTypeName(value), new IPRangeMeta().setAllow(ipRangeLimit.allow()).setDeny(ipRangeLimit.deny()));
        });

        mapRet.forEach((key, value) -> {
            IPRangeMeta   iFc = iMap.get(value.getBeanType().getName());
            PermRolesMeta pFc = pMap.get(value.getBeanType().getName());
            PermRolesMeta rFc = rMap.get(value.getBeanType().getName());
            PermRolesMeta permRolesMeta = generatePermRolesMeta(value.getMethodAnnotation(Perms.class),
                                                                value.getMethodAnnotation(Roles.class));
            IPRangeMeta ipRangeMeta = new IPRangeMeta();
            List<String> mtds = key.getMethodsCondition().getMethods().stream().map(Enum::name).collect(
                    Collectors.toList());
            Set<String> patterns = getPatterns(key);

            if (!value.getBeanType().equals(BasicErrorController.class)) {
                List<Map<String, String>> clm = _controllerMetadata
                        .computeIfAbsent(value.getBeanType().getSimpleName(), r -> new ArrayList<>());
                patterns.forEach(p -> mtds.forEach(m -> {
                    HashMap<String, String> map = new HashMap<>();
                    map.put("method", m);
                    map.put("path", p);
                    clm.add(map);
                }));
            }

            // 初始化Certificated
            Certificated certificated = AnnotatedElementUtils.getMergedAnnotation(value.getMethod(),
                                                                                  Certificated.class);
            if (cList.contains(value.getBeanType().getTypeName()) || certificated != null) {
                patterns.forEach(p -> _certificatedMetadata.computeIfAbsent(p, r -> new HashSet<>()).addAll(mtds));
            }

            // 初始化API权限
            if (rFc != null) {
                if (permRolesMeta == null) permRolesMeta = new PermRolesMeta();
                if (rFc.getRequireRoles() != null) {
                    if (permRolesMeta.getRequireRoles() != null) {
                        permRolesMeta.getRequireRoles().addAll(rFc.getRequireRoles());
                    } else {
                        permRolesMeta.setRequireRoles(rFc.getRequireRoles());
                    }
                }
                if (rFc.getExcludeRoles() != null) {
                    if (permRolesMeta.getExcludeRoles() != null) {
                        permRolesMeta.getExcludeRoles().addAll(rFc.getExcludeRoles());
                    } else {
                        permRolesMeta.setExcludeRoles(rFc.getExcludeRoles());
                    }
                }
            }
            if (pFc != null) {
                if (permRolesMeta == null) permRolesMeta = new PermRolesMeta();
                Set<Set<String>> requirePermissions = pFc.getRequirePermissions();
                if (requirePermissions != null) {
                    if (permRolesMeta.getRequirePermissions() != null) {
                        permRolesMeta.getRequirePermissions().addAll(requirePermissions);
                    } else {
                        permRolesMeta.setRequirePermissions(requirePermissions);
                    }
                }
                if (pFc.getExcludePermissions() != null) {
                    Set<Set<String>> excludePermissions = pFc.getExcludePermissions();
                    if (permRolesMeta.getExcludePermissions() != null) {
                        permRolesMeta.getExcludePermissions().addAll(excludePermissions);
                    } else {
                        permRolesMeta.setExcludePermissions(excludePermissions);
                    }
                }
            }
            if (permRolesMeta != null) {
                Set<Set<String>> requireRoles = permRolesMeta.getRequireRoles();
                Set<Set<String>> excludeRoles = permRolesMeta.getExcludeRoles();
                if (requireRoles != null) requireRoles.forEach(toBeLoadedRoles::addAll);
                if (excludeRoles != null) excludeRoles.forEach(toBeLoadedRoles::addAll);

                PermRolesMeta finalPermRolesMeta = permRolesMeta;
                mtds.forEach(method -> patterns.forEach(
                        patternValue -> _authzMetadata.computeIfAbsent(patternValue, r -> new HashMap<>())
                                .put(method, finalPermRolesMeta)
                ));
            }

            // 初始化IPRange权限
            if (iFc != null) {
                ipRangeMeta.setAllow(iFc.getAllow());
                ipRangeMeta.setDeny(iFc.getDeny());
            }
            IPRangeLimit ipRangeLimit = value.getMethodAnnotation(IPRangeLimit.class);
            if (ipRangeLimit != null) {
                ipRangeMeta.setAllow(ipRangeLimit.allow()).setDeny(ipRangeLimit.deny());
                if (iFc != null) {
                    ipRangeMeta.getAllow().addAll(iFc.getAllow());
                    ipRangeMeta.getDeny().addAll(iFc.getDeny());
                }
            }
            if (ipRangeMeta.getDeny() != null && !ipRangeMeta.getDeny()
                    .isEmpty() || ipRangeMeta.getAllow() != null && !ipRangeMeta.getAllow().isEmpty()) {
                mtds.forEach(method -> patterns.forEach(
                        patternValue -> _ipRangeMeta.computeIfAbsent(patternValue, r -> new HashMap<>()).put(
                                method, ipRangeMeta)));
            }

            // ------------- 初始化参数权限 --------------- //
            mtds.forEach(method -> patterns.forEach(patternValue -> {
                Map<ParamMetadata.ParamType, Map<String, Class<?>>> rawParamTypeMapMap =
                        _rawMap.computeIfAbsent(patternValue, r -> new HashMap<>())
                                .computeIfAbsent(method, r -> new HashMap<>());
                for (MethodParameter param : value.getMethodParameters()) {
                    Class<?> paramType = param.getParameter().getType();
                    if (ValueMatcher.checkType(paramType).isOther()) {
                        continue;
                    }

                    RequestParam requestParam = param.getParameterAnnotation(RequestParam.class);
                    PathVariable pathVariable = param.getParameterAnnotation(PathVariable.class);
                    String       paramName    = param.getParameter().getName();

                    ParamMetadata.ParamType type;
                    if (pathVariable != null) {
                        type = ParamMetadata.ParamType.PATH_VARIABLE;
                        if (!pathVariable.name().equals("")) paramName = pathVariable.name();
                    } else if (requestParam != null) {
                        type = ParamMetadata.ParamType.REQUEST_PARAM;
                        if (!requestParam.name().equals("")) paramName = requestParam.name();
                    } else {
                        continue;
                    }

                    Map<String, Class<?>> rawParamMap = rawParamTypeMapMap.computeIfAbsent(type,
                                                                                           r -> new HashMap<>());
                    rawParamMap.put(paramName, paramType);

                    Roles          rolesByParam   = param.getParameterAnnotation(Roles.class);
                    Perms          permsByParam   = param.getParameterAnnotation(Perms.class);
                    BatchAuthority batchAuthority = param.getParameterAnnotation(BatchAuthority.class);

                    if (rolesByParam != null || permsByParam != null || batchAuthority != null) {
                        ArrayList<PermRolesMeta.Meta> rolesMetaList = new ArrayList<>();
                        ArrayList<PermRolesMeta.Meta> permsMetaList = new ArrayList<>();
                        PermRolesMeta.Meta            vr            = generateRolesMeta(rolesByParam);
                        PermRolesMeta.Meta            vp            = generatePermMeta(permsByParam);
                        if (vr != null) rolesMetaList.add(vr);
                        if (vp != null) permsMetaList.add(vp);

                        if (batchAuthority != null) {
                            Roles[] rs = batchAuthority.roles();
                            for (Roles r : rs) {
                                PermRolesMeta.Meta v = generateRolesMeta(r);
                                if (v != null) {
                                    rolesMetaList.add(v);
                                    if (v.getRequire() != null) v.getRequire().forEach(toBeLoadedRoles::addAll);
                                    if (v.getExclude() != null) v.getExclude().forEach(toBeLoadedRoles::addAll);
                                }
                            }
                            Perms[] ps = batchAuthority.perms();
                            for (Perms p : ps) {
                                PermRolesMeta.Meta v = generatePermMeta(p);
                                if (v != null) permsMetaList.add(v);
                            }
                        }

                        PermRolesMeta meta = _authzMetadata.computeIfAbsent(patternValue, r -> new HashMap<>())
                                .computeIfAbsent(method, r -> new PermRolesMeta());
                        meta.put(type, paramName,
                                 new ParamMetadata(paramType, rolesMetaList, permsMetaList)
                        );
                    }

                }
            }));

        });

        _globalAllow.addAll(IPRangeMeta.parse(properties.getGlobalIpRange().getAllow()));
        _globalDeny.addAll(IPRangeMeta.parse(properties.getGlobalIpRange().getDeny()));
        _supportNative = properties.getGlobalIpRange().isSupportNative();

        if (properties.getCache().isEnableRedis()) {
            Async.run(() -> {
                List<Set<String>> toBeLoadedRolesKeys = RedisUtils.Obj.get(
                        toBeLoadedRoles.stream()
                                .map(role -> Constants.PERMISSIONS_BY_ROLE_KEY_PREFIX.get() + role)
                                .collect(Collectors.toList())
                );
                Iterator<String>             iterator = toBeLoadedRoles.iterator();
                HashMap<String, Set<String>> map      = new HashMap<>();
                toBeLoadedRolesKeys.forEach(perms -> map.put(iterator.next(), perms));
                map.forEach((role, v) -> {
                    Set<String> permissions = permLibrary.getPermissionsByRole(role);
                    if (permissions != null) {
                        cache.setSneaky(Constants.PERMISSIONS_BY_ROLE_KEY_PREFIX.get() + role, permissions,
                                        Cache.INFINITE);
                    }
                });
            });
        }
    }

}
