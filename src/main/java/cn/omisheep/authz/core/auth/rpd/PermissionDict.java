package cn.omisheep.authz.core.auth.rpd;

import cn.omisheep.authz.annotation.*;
import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.ipf.Httpd;
import cn.omisheep.authz.core.auth.ipf.LimitMeta;
import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.config.AuInit;
import cn.omisheep.authz.core.config.AuthzAppVersion;
import cn.omisheep.authz.core.config.Constants;
import cn.omisheep.authz.core.msg.AuthzModifier;
import cn.omisheep.authz.core.util.RedisUtils;
import cn.omisheep.authz.core.util.ValueMatcher;
import cn.omisheep.authz.support.util.IPRange;
import cn.omisheep.authz.support.util.IPRangeMeta;
import cn.omisheep.commons.util.Async;
import cn.omisheep.web.entity.Result;
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

import java.util.*;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;

import static cn.omisheep.authz.core.util.MetaUtils.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class PermissionDict {

    /**
     * controller
     */
    private static final Map<String, List<Map<String, String>>> _controllerMetadata = new HashMap<>();

    /**
     * api权限
     */
    private static final Map<String, Map<String, PermRolesMeta>> _authzMetadata = new HashMap<>();

    /**
     * api的参数权限
     */
    private static final Map<String, Map<String, Map<String, ParamMetadata>>> _authzParamMetadata = new HashMap<>();

    /**
     * certificatedMetadata 哪些接口需要登录-若有role和perms，则同同理
     */
    private static final Map<String, Set<String>> _certificatedMetadata = new HashMap<>();

    /**
     * args
     */
    private static final Map<String, ArgsMeta> _argsMetadata = new HashMap<>();

    /**
     * 数据行权限
     */
    private static final Map<String, List<DataPermRolesMeta>> _dataPermMetadata = new HashMap<>();

    /**
     * 数据列权限
     */
    private static final Map<String, Map<String, FieldDataPermRolesMeta>> _fieldMetadata = new HashMap<>();

    /**
     * iprange
     */
    private static final Map<String, Map<String, IPRangeMeta>> _ipRangeMeta = new HashMap<>();

    /**
     * 资源模版
     */
    private static final Map<String, Map<String, String>> _authzResourcesNameAndTemplate = new HashMap<>();

    /**
     * 是否拦截本地ip
     */
    private static boolean _supportNative;

    /**
     * 允许的ip范围
     */
    private static final Set<IPRange> _globalAllow = new HashSet<>();

    /**
     * 拦截的ip访问
     */
    private static final Set<IPRange> _globalDeny = new HashSet<>();

    // ----------------------------------------- unModify ----------------------------------------- //

    @Getter
    private static final Map<String, Map<String, PermRolesMeta>>              rolePermission           = Collections.unmodifiableMap(
            _authzMetadata);
    @Getter
    private static final Map<String, Map<String, Map<String, ParamMetadata>>> paramPermission          = Collections.unmodifiableMap(
            _authzParamMetadata);
    @Getter
    private static final Map<String, Map<String, String>>                     resourcesNameAndTemplate = Collections.unmodifiableMap(
            _authzResourcesNameAndTemplate);
    @Getter
    private static final Map<String, List<DataPermRolesMeta>>                 dataPermission           = Collections.unmodifiableMap(
            _dataPermMetadata);
    @Getter
    private static final Map<String, Map<String, FieldDataPermRolesMeta>>     fieldsData               = Collections.unmodifiableMap(
            _fieldMetadata);
    @Getter
    private static final Map<String, ArgsMeta>                                args                     = Collections.unmodifiableMap(
            _argsMetadata);

    @Getter
    private static final Map<String, Map<String, IPRangeMeta>>  iPRange              = Collections.unmodifiableMap(
            _ipRangeMeta);
    @Getter
    private static final Map<String, Set<String>>               certificatedMetadata = Collections.unmodifiableMap(
            _certificatedMetadata);
    @Getter
    private static final Set<IPRange>                           globalAllow          = Collections.unmodifiableSet(
            _globalAllow);
    @Getter
    private static final Set<IPRange>                           globalDeny           = Collections.unmodifiableSet(
            _globalDeny);
    @Getter
    private static final Map<String, List<Map<String, String>>> controllerMetadata   = Collections.unmodifiableMap(
            _controllerMetadata);

    public static boolean isSupportNative() {
        return PermissionDict._supportNative;
    }

    // ----------------------------------------- func ----------------------------------------- //

    public static void putParam(String api,
                                String method,
                                String name,
                                ParamMetadata paramMetadata) {
        _authzParamMetadata
                .computeIfAbsent(api, r -> new HashMap<>())
                .computeIfAbsent(method, r -> new HashMap<>())
                .computeIfAbsent(name, r -> paramMetadata)
                .setParamMetaList(paramMetadata.getParamMetaList());
    }

    public static void putParam(String api,
                                String method) {
        _authzParamMetadata
                .computeIfAbsent(api, r -> new HashMap<>())
                .computeIfAbsent(method, r -> new HashMap<>());
    }

    @Nullable
    public static Object modify(@NonNull AuthzModifier authzModifier) {
        if (authzModifier.getTarget() == null) {
            return modifyParam(authzModifier);
        }
        switch (authzModifier.getTarget()) {
            case API:
            case LOGIN:
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

    private final static ReentrantLock lock = new ReentrantLock();

    private static Result returnObj(String api,
                                    String method) {
        PermRolesMeta _v = null;
        try {
            _v = _authzMetadata.get(api).get(method);
        } catch (Exception e) {
            // skip
        }
        boolean k = false;

        try {
            k = _certificatedMetadata.get(api).contains(method);
        } catch (Exception e) {
            // skip
        }

        Map<String, ParamMetadata> paramAuth = null;

        try {
            paramAuth = _authzParamMetadata.get(api)
                    .get(method);
        } catch (Exception e) {
            // skip
        }
        LimitMeta rateLimit = null;

        try {
            rateLimit = Httpd.getRateLimitMetadata().get(api)
                    .get(method);
        } catch (Exception e) {
            // skip
        }

        if (_v != null) {
            return Result.SUCCESS
                    .data("auth", _v)
                    .data("hasAuth", !_v.non())
                    .data("requireLogin", !_v.non() || k)
                    .data("paramAuth", paramAuth)
                    .data("rateLimit", rateLimit)
                    .data("hasRateLimit", rateLimit != null)
                    .data("hasParamAuth", paramAuth != null);
        } else {
            return Result.SUCCESS
                    .data("auth", null)
                    .data("hasAuth", false)
                    .data("paramAuth", paramAuth)
                    .data("rateLimit", rateLimit)
                    .data("hasRateLimit", rateLimit != null)
                    .data("hasParamAuth", paramAuth != null)
                    .data("requireLogin", k);
        }
    }

    public static Object modifyAPI(AuthzModifier authzModifier) {
        lock.lock();
        String api    = authzModifier.getApi();
        String method = authzModifier.getMethod();

        try {
            if (AuthzModifier.Target.LOGIN.equals(authzModifier.getTarget())) {
                try {
                    boolean login = (boolean) authzModifier.getValue();
                    if (login) {
                        _certificatedMetadata.computeIfAbsent(api, r -> new HashSet<>()).add(method);
                    } else {
                        if (_certificatedMetadata.containsKey(api)) {
                            _certificatedMetadata.get(api).remove(method);
                        }
                    }
                    return Result.SUCCESS.data();
                } catch (Exception e) {
                    return Result.FAIL.data();
                }
            }

            switch (authzModifier.getOperate()) {
                case ADD:
                case MODIFY:
                case UPDATE: {
                    PermRolesMeta build = authzModifier.build();
                    if (build != null) {
                        _authzMetadata.computeIfAbsent(api, r -> new HashMap<>())
                                .computeIfAbsent(authzModifier.getMethod(), r -> new PermRolesMeta())
                                .clear().merge(build);
                        if (_authzMetadata.get(api).get(method).non()) {
                            _certificatedMetadata.computeIfAbsent(api, r -> new HashSet<>()).remove(method);
                        } else {
                            _certificatedMetadata.computeIfAbsent(api, r -> new HashSet<>()).add(method);
                        }
                    }

                    Map<String, PermRolesMeta> metaMap = _authzMetadata.get(api);
                    if (metaMap != null) {
                        PermRolesMeta permRolesMeta = metaMap.get(method);
                        if (permRolesMeta != null) {
                            if (build == null) permRolesMeta.clear();
                            if (permRolesMeta.non()) {
                                metaMap.remove(method);
                            }
                        }
                        if (metaMap.isEmpty()) _authzMetadata.remove(api);
                    }

                    return returnObj(api, method);
                }
                case DELETE:
                case DEL: {
                    _authzMetadata.get(api).get(method).clear();
                    if (_authzMetadata.get(api).get(method).non()) {
                        _authzMetadata.get(api).remove(method);
                    }
                    if (_authzMetadata.get(api).isEmpty()) {
                        _authzMetadata.remove(api);
                    }
                    return Result.SUCCESS;
                }
                case GET:
                case READ:
                    if (api == null && method == null) return rolePermission;
                    if (api == null) {
                        return rolePermission.values().stream().filter(
                                stringPermRolesMetaMap -> stringPermRolesMetaMap.containsKey(
                                        authzModifier.getMethod())).map(
                                stringPermRolesMetaMap -> stringPermRolesMetaMap.get(
                                        authzModifier.getMethod())).collect(Collectors.toList());
                    }
                    if (method == null) {
                        return rolePermission.get(authzModifier.getApi());
                    }
                    return rolePermission.get(api).get(method);
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
//            PermRolesMeta        meta   = _authzMetadata.get(authzModifier.getApi()).get(authzModifier.getMethod());
//            AuthzModifier.Target target = authzModifier.getTarget();
//
//            if (target == null &&
//                    (authzModifier.getOperate() == AuthzModifier.Operate.GET || authzModifier.getOperate() == AuthzModifier.Operate.READ)) {
//                if (authzModifier.getTarget() == null && authzModifier.getValue() == null) {
//                    return meta.getParamPermissionsMetadata();
//                }
//                HashMap<Object, Object>    map = new HashMap<>();
//                Map<String, ParamPermRolesMeta> m1  = meta.getParamPermissionsMetadata().get(PATH_VARIABLE);
//                Map<String, ParamPermRolesMeta> m2  = meta.getParamPermissionsMetadata().get(REQUEST_PARAM);
//                if (m1 != null && m1.containsKey(authzModifier.getValue())) {
//                    map.put(PATH_VARIABLE.getVal(),
//                            m1.get(authzModifier.getValue()));
//                }
//                if (m2 != null && m2.containsKey(authzModifier.getValue())) {
//                    map.put(REQUEST_PARAM.getVal(),
//                            m2.get(authzModifier.getValue()));
//                }
//                return map;
//            }
//
//            Object[] objects = getParamMetaList(meta, authzModifier);
//
//
//            ParamPermRolesMeta            paramMetadata = (ParamPermRolesMeta) objects[0];
//            List<PermRolesMeta.Meta> metaList      = (List<PermRolesMeta.Meta>) objects[1]; // 可能需要操作的list
//
//            if (metaList == null) {
//                return Result.FAIL;
//            }
//
//            switch (authzModifier.getOperate()) {
//                case ADD:
//                    PermRolesMeta.Meta _m;
//                    if (authzModifier.getTarget().contains("role")) {
//                        _m = authzModifier.build().role;
//                    } else {
//                        _m = authzModifier.build().permissions;
//                    }
//                    if (authzModifier.getIndex() != null) {
//                        metaList.add(authzModifier.getIndex(), _m);
//                    } else {
//                        metaList.add(_m);
//                    }
//                    if (authzModifier.getRange() != null) {
//                        _m.setRange(new HashSet<>(authzModifier.getRange()));
//                    }
//                    if (authzModifier.getResources() != null) {
//                        _m.setRange(new HashSet<>(authzModifier.getResources()));
//                    }
//                    return metaList;
//                case DEL:
//                case DELETE:
//                    if (authzModifier.getIndex() != null) {
//                        metaList.remove(metaList.get(authzModifier.getIndex()));
//                    } else {
//                        if (target == AuthzModifier.Target.PATH) {
//                            meta.getParamPermissionsMetadata().get(PATH_VARIABLE).remove(authzModifier.getValue());
//                        } else {
//                            meta.getParamPermissionsMetadata().get(REQUEST_PARAM).remove(authzModifier.getValue());
//                        }
//                    }
//                    return meta;
//                case MODIFY:
//                case UPDATE:
//                    PermRolesMeta build = authzModifier.build();
//                    PermRolesMeta.Meta m = metaList.get(authzModifier.getIndex());
//                    if (authzModifier.getTarget().contains("role")) {
//                        if (build.getRequireRoles() != null) {m.setRequire(build.getRequireRoles());}
//                        if (build.getExcludeRoles() != null) {m.setExclude(build.getExcludeRoles());}
//                    } else {
//                        if (build.getRequirePermissions() != null) {m.setRequire(build.getRequirePermissions());}
//                        if (build.getExcludePermissions() != null) {m.setExclude(build.getExcludePermissions());}
//                    }
//                    if (authzModifier.getRange() != null) {
//                        m.setRange(new HashSet<>(authzModifier.getRange()));
//                    }
//                    if (authzModifier.getResources() != null) {
//                        m.setResources(new HashSet<>(authzModifier.getResources()));
//                    }
//                    return m;
//                case GET:
//                case READ:
//                    if (authzModifier.getIndex() == null) {
//                        return paramMetadata;
//                    } else {
//                        return metaList.get(authzModifier.getIndex());
//                    }
//                case NON:
//                    return Result.SUCCESS;
//            }
//
//            return paramMetadata;
            return Result.SUCCESS;
        } catch (Exception e) {
            return Result.FAIL;
        } finally {
            lock.unlock();
        }
    }

//    private static Object[] getParamMetaList(PermRolesMeta meta,
//                                             AuthzModifier authzModifier) {
//        boolean       isAdd = authzModifier.getOperate() == AuthzModifier.Operate.ADD;
//        ParamPermRolesMeta paramMetadata;
//        if (meta == null) {
//            if (isAdd) {
//
//                Map<ParamPermRolesMeta.ParamType, Map<String, Class<?>>> paramTypeMapMap = _rawMap.get(
//                        authzModifier.getApi()).get(authzModifier.getMethod());
//
//                switch (authzModifier.getTarget().i) {
//                    case 2:
//                    case 3:
//                        Class<?> aClass1 = paramTypeMapMap.get(PATH_VARIABLE).get(authzModifier.getValue());
//                        if (aClass1 != null) {
//                            meta = _authzMetadata.computeIfAbsent(authzModifier.getApi(), r -> new HashMap<>())
//                                    .computeIfAbsent(authzModifier.getMethod(), r -> new PermRolesMeta());
//                            ParamPermRolesMeta pmd = new ParamPermRolesMeta();
//                            meta.put(PATH_VARIABLE,
//                                     (String) authzModifier.getValue(),
//                                     pmd.setParamType(aClass1));
//                        } else {
//                            return null;
//                        }
//                        break;
//                    case 4:
//                    case 5:
//                        Class<?> aClass2 = paramTypeMapMap.get(REQUEST_PARAM).get(authzModifier.getValue());
//                        if (aClass2 != null) {
//                            meta = _authzMetadata.computeIfAbsent(authzModifier.getApi(), r -> new HashMap<>())
//                                    .computeIfAbsent(authzModifier.getMethod(), r -> new PermRolesMeta());
//                            ParamPermRolesMeta pmd = new ParamPermRolesMeta();
//                            meta.put(REQUEST_PARAM,
//                                     (String) authzModifier.getValue(),
//                                     pmd.setParamType(aClass2));
//                        } else {
//                            return null;
//                        }
//                        break;
//                    default:
//                        return null;
//                }
//            } else {
//                return null;
//            }
//        }
//        switch (authzModifier.getTarget().i) {
//            case 2:
//                paramMetadata = meta.getParamPermissionsMetadata().get(PATH_VARIABLE)
//                        .computeIfAbsent((String) authzModifier.getValue(),
//                                         r -> new ParamPermRolesMeta().setParamType(
//                                                 _rawMap.get(authzModifier.getApi()).get(authzModifier.getMethod()).get(
//                                                         PATH_VARIABLE).get(authzModifier.getValue())));
//                if (paramMetadata != null) {
//                    List<PermRolesMeta.Meta> rolesMetaList = paramMetadata.getRolesMetaList();
//                    if (rolesMetaList == null && isAdd) {
//                        rolesMetaList = new ArrayList<>();
//                        paramMetadata.setRolesMetaList(rolesMetaList);
//                    }
//                    return new Object[]{paramMetadata, paramMetadata.getRolesMetaList()};
//                } else {
//                    if (isAdd) {
//                        paramMetadata = meta.getParamPermissionsMetadata().get(PATH_VARIABLE).computeIfAbsent(
//                                (String) authzModifier.getValue(), r -> new ParamPermRolesMeta());
//                        paramMetadata.setRolesMetaList(new ArrayList<>());
//                        return new Object[]{paramMetadata, paramMetadata.getRolesMetaList()};
//                    } else {
//                        return null;
//                    }
//                }
//            case 3:
//                paramMetadata = meta.getParamPermissionsMetadata().get(PATH_VARIABLE).computeIfAbsent(
//                        (String) authzModifier.getValue(),
//                        r -> new ParamPermRolesMeta().setParamType(
//                                _rawMap.get(authzModifier.getApi()).get(authzModifier.getMethod()).get(
//                                        PATH_VARIABLE).get(authzModifier.getValue())));
//                if (paramMetadata != null) {
//                    List<PermRolesMeta.Meta> permissionsMetaList = paramMetadata.getPermissionsMetaList();
//                    if (permissionsMetaList == null && isAdd) {
//                        permissionsMetaList = new ArrayList<>();
//                        paramMetadata.setPermissionsMetaList(permissionsMetaList);
//                    }
//                    return new Object[]{paramMetadata, paramMetadata.getPermissionsMetaList()};
//                } else {
//                    if (isAdd) {
//                        paramMetadata = meta.getParamPermissionsMetadata().get(PATH_VARIABLE).computeIfAbsent(
//                                (String) authzModifier.getValue(), r -> new ParamPermRolesMeta());
//                        paramMetadata.setPermissionsMetaList(new ArrayList<>());
//                        return new Object[]{paramMetadata, paramMetadata.getPermissionsMetaList()};
//
//                    } else {
//                        return null;
//                    }
//                }
//            case 4:
//                paramMetadata = meta.getParamPermissionsMetadata().get(REQUEST_PARAM).computeIfAbsent(
//                        (String) authzModifier.getValue(),
//                        r -> new ParamPermRolesMeta().setParamType(
//                                _rawMap.get(authzModifier.getApi()).get(authzModifier.getMethod()).get(
//                                        REQUEST_PARAM).get(authzModifier.getValue())));
//                if (paramMetadata != null) {
//                    List<PermRolesMeta.Meta> rolesMetaList = paramMetadata.getRolesMetaList();
//                    if (rolesMetaList == null && isAdd) {
//                        rolesMetaList = new ArrayList<>();
//                        paramMetadata.setRolesMetaList(rolesMetaList);
//                    }
//                    return new Object[]{paramMetadata, paramMetadata.getRolesMetaList()};
//                } else {
//                    if (isAdd) {
//                        paramMetadata = meta.getParamPermissionsMetadata().get(REQUEST_PARAM).computeIfAbsent(
//                                (String) authzModifier.getValue(), r -> new ParamPermRolesMeta());
//                        paramMetadata.setRolesMetaList(new ArrayList<>());
//                        return new Object[]{paramMetadata, paramMetadata.getRolesMetaList()};
//                    } else {
//                        return null;
//                    }
//                }
//            case 5:
//                paramMetadata = meta.getParamPermissionsMetadata().get(REQUEST_PARAM).computeIfAbsent(
//                        (String) authzModifier.getValue(),
//                        r -> new ParamPermRolesMeta().setParamType(
//                                _rawMap.get(authzModifier.getApi()).get(authzModifier.getMethod()).get(
//                                        REQUEST_PARAM).get(authzModifier.getValue())));
//                if (paramMetadata != null) {
//                    List<PermRolesMeta.Meta> permissionsMetaList = paramMetadata.getPermissionsMetaList();
//                    if (permissionsMetaList == null && isAdd) {
//                        permissionsMetaList = new ArrayList<>();
//                        paramMetadata.setPermissionsMetaList(permissionsMetaList);
//                    }
//                    return new Object[]{paramMetadata, paramMetadata.getPermissionsMetaList()};
//
//                } else {
//                    if (isAdd) {
//                        paramMetadata = meta.getParamPermissionsMetadata().get(REQUEST_PARAM).computeIfAbsent(
//                                (String) authzModifier.getValue(), r -> new ParamPermRolesMeta());
//                        paramMetadata.setPermissionsMetaList(new ArrayList<>());
//                        return new Object[]{paramMetadata, paramMetadata.getPermissionsMetaList()};
//
//                    } else {
//                        return null;
//                    }
//                }
//        }
//        return null;
//    }

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
                        DataPermRolesMeta dataPermRolesMeta;
                        Rule rule = authzModifier.getRule();
                        if (rule == null) {
                            dataPermRolesMeta = DataPermRolesMeta.of(authzModifier.getCondition());
                        } else {
                            dataPermRolesMeta = DataPermRolesMeta.of(rule);
                        }
                        PermRolesMeta build = authzModifier.build();
                        dataPermRolesMeta.setRoles(build.roles);
                        dataPermRolesMeta.setPermissions(build.permissions);
                        dataPermRolesMeta.setArgsMap(authzModifier.getArgsMap());
                        _dataPermMetadata.computeIfAbsent(className, r -> new ArrayList<>()).add(dataPermRolesMeta);
                        break;
                    case MODIFY:
                    case UPDATE:
                        if (authzModifier.getIndex() == null) return Result.FAIL;
                        if (_dataPermMetadata.get(className) == null) return Result.FAIL;
                        DataPermRolesMeta old_data_mata = _dataPermMetadata.get(className)
                                .get(authzModifier.getIndex());
                        DataPermRolesMeta new_data_mata = null;

                        if (authzModifier.getCondition() != null) {
                            new_data_mata = DataPermRolesMeta.of(authzModifier.getCondition());
                        }
                        if (authzModifier.getRule() != null) {
                            new_data_mata = DataPermRolesMeta.of(authzModifier.getRule());
                        }
                        if (new_data_mata != null) {
                            old_data_mata.setRule(new_data_mata.getRule());
                            old_data_mata.setCondition(new_data_mata.getCondition());
                        }
                        PermRolesMeta build_new = authzModifier.build();
                        if (build_new.roles != null) {
                            old_data_mata.setRoles(build_new.roles);
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
                        PermRolesMeta          build     = authzModifier.build();
                        FieldDataPermRolesMeta fieldData = FieldDataPermRolesMeta.of(className, build);
                        _fieldMetadata.computeIfAbsent(className, r -> new HashMap<>()).put(
                                authzModifier.getFieldName(),
                                fieldData);
                    }
                    case UPDATE:
                    case MODIFY: {
                        if (authzModifier.getFieldName() == null) return Result.FAIL;
                        PermRolesMeta          build     = authzModifier.build();
                        FieldDataPermRolesMeta fieldData = FieldDataPermRolesMeta.of(className, build);
                        FieldDataPermRolesMeta fd = _fieldMetadata.computeIfAbsent(className,
                                                                                   r -> new HashMap<>())
                                .computeIfAbsent(
                                        authzModifier.getFieldName(),
                                        r -> new FieldDataPermRolesMeta());
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

    private PermissionDict() {
        throw new UnsupportedOperationException();
    }

    public static void initArgs(Set<String> authzResourcesNames,
                                Map<String, Map<String, FieldDataPermRolesMeta>> fieldMetadata,
                                HashMap<String, List<DataPermRolesMeta>> map,
                                HashMap<String, ArgsMeta> args) {
        if (isInitArgs) {
            AuInit.log.error("PermissionDict已初始化");
        }
        isInitArgs = true;
        for (String authzResourcesName : authzResourcesNames) {
            try {
                Map<String, String> fieldMap = _authzResourcesNameAndTemplate.computeIfAbsent(authzResourcesName,
                                                                                              r -> new HashMap<>());
                fieldMap.putAll(ArgsHandler.parseTypeForTemplate(authzResourcesName));
            } catch (Exception ignored) {
            }
        }
        _fieldMetadata.putAll(fieldMetadata);
        _dataPermMetadata.putAll(map);
        _argsMetadata.putAll(args);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    public static void init(ApplicationContext applicationContext,
                            PermLibrary permLibrary,
                            Cache cache,
                            Map<RequestMappingInfo, HandlerMethod> mapRet) {
        if (isInit) {
            AuInit.log.error("PermissionDict已初始化");
        }
        isInit = true;

        PermissionDict.setPermSeparator(Constants.COMMA);
        Set<String>                toBeLoadedRoles = new HashSet<>();
        Map<String, PermRolesMeta> cMap            = new HashMap<>();
        Map<String, IPRangeMeta>   iMap            = new HashMap<>();
        Set<String>                cList           = new HashSet<>();

        applicationContext.getBeansWithAnnotation(Auth.class).forEach((key, value) -> {
            String    name  = getTypeName(value);
            Set<Auth> auths = getAnnotations(value, Auth.class);
            if (auths != null) {
                PermRolesMeta permRolesMeta = generatePermRolesMeta(auths);
                if (permRolesMeta != null && !permRolesMeta.non()) {
                    cMap.put(name, permRolesMeta);
                    cList.add(getTypeName(value));
                }
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

            List<String> mtds = key.getMethodsCondition().getMethods().stream().map(Enum::name).collect(
                    Collectors.toList());
            Set<String> patterns = getPatterns(key);

            // ------------- 初始化Controller --------------- //
            {
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
            }

            // ------------- 初始化Api权限 --------------- //
            Set<Auth> auths = AnnotatedElementUtils.getAllMergedAnnotations(value.getMethod(),
                                                                            Auth.class);

            PermRolesMeta permRolesMeta = new PermRolesMeta().merge(generatePermRolesMeta(auths))
                    .merge(cMap.get(value.getBeanType().getName()));

            if (!permRolesMeta.non()) {
                mtds.forEach(method -> patterns.forEach(
                        patternValue -> _authzMetadata.computeIfAbsent(patternValue, r -> new HashMap<>())
                                .put(method, permRolesMeta)
                ));
            }

            // ------------- Load --------------- //
            {
                Set<Set<String>> requireRoles = permRolesMeta.getRequireRoles();
                Set<Set<String>> excludeRoles = permRolesMeta.getExcludeRoles();
                if (requireRoles != null) requireRoles.forEach(toBeLoadedRoles::addAll);
                if (excludeRoles != null) excludeRoles.forEach(toBeLoadedRoles::addAll);
            }

            // ------------- 初始化Certificated --------------- //
            Certificated certificated = AnnotatedElementUtils.getMergedAnnotation(value.getMethod(),
                                                                                  Certificated.class);
            if (cList.contains(value.getBeanType().getTypeName()) || certificated != null) {
                patterns.forEach(p -> _certificatedMetadata.computeIfAbsent(p, r -> new HashSet<>()).addAll(mtds));
            }

            // ------------- 初始化RateLimit --------------- //
            // 初始化IPRange权限
            IPRangeMeta iFc         = iMap.get(value.getBeanType().getName());
            IPRangeMeta ipRangeMeta = new IPRangeMeta();
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
                putParam(patternValue, method);
                for (MethodParameter param : value.getMethodParameters()) {
                    // ------------- 元信息初始化 --------------- //
                    RequestParam requestParam = param.getParameterAnnotation(RequestParam.class);
                    PathVariable pathVariable = param.getParameterAnnotation(PathVariable.class);
                    String       paramName    = param.getParameter().getName();
                    Class<?>     clz          = param.getParameter().getType();

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

                    putParam(patternValue, method, paramName, ParamMetadata.of(clz, type, null));

                    // ------------- 权限信息初始化 --------------- //

                    AuthParam      authParam      = param.getParameterAnnotation(AuthParam.class);
                    BatchAuthParam batchAuthParam = param.getParameterAnnotation(BatchAuthParam.class);

                    if (authParam == null && batchAuthParam == null) continue;

                    if (ValueMatcher.checkTypeByClass(clz).isOther()) {
                        continue;
                    }

                    List<AuthParam> authParamList = new ArrayList<>();
                    authParamList.add(authParam);
                    if (batchAuthParam != null) {
                        authParamList.addAll(Arrays.asList(batchAuthParam.value()));
                    }

                    List<ParamPermRolesMeta> paramPermRolesMetas = new ArrayList<>();
                    for (AuthParam ap : authParamList) {
                        paramPermRolesMetas.add(generateParamMeta(ap));
                    }
                    paramPermRolesMetas = paramPermRolesMetas.stream()
                            .filter(java.util.Objects::nonNull)
                            .collect(Collectors.toList());

                    if (paramPermRolesMetas.isEmpty()) continue;

                    putParam(patternValue, method, paramName,
                             ParamMetadata.of(clz, type, paramPermRolesMetas));

                }
            }));

        });

        _globalAllow.addAll(IPRangeMeta.parse(AuthzAppVersion.properties.getGlobalIpRange().getAllow()));
        _globalDeny.addAll(IPRangeMeta.parse(AuthzAppVersion.properties.getGlobalIpRange().getDeny()));
        _supportNative = AuthzAppVersion.properties.getGlobalIpRange().isSupportNative();

        if (AuthzAppVersion.properties.getCache().isEnableRedis()) {
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
