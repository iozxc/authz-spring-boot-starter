package cn.omisheep.authz.core;

import cn.omisheep.authz.annotation.BatchAuthority;
import cn.omisheep.authz.annotation.Perms;
import cn.omisheep.authz.annotation.RateLimit;
import cn.omisheep.authz.annotation.Roles;
import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.deviced.DeviceConfig;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.auth.ipf.Httpd;
import cn.omisheep.authz.core.auth.ipf.LimitMeta;
import cn.omisheep.authz.core.auth.rpd.PermRolesMeta;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.cache.Message;
import cn.omisheep.authz.core.tk.AuKey;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.authz.core.util.RedisUtils;
import cn.omisheep.commons.util.Async;
import cn.omisheep.commons.util.CollectionUtils;
import cn.omisheep.commons.util.TaskBuilder;
import lombok.SneakyThrows;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.handler.AbstractHandlerMethodMapping;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@SuppressWarnings("all")
public class AuCoreInitialization implements ApplicationContextAware {

    @Value("${server.servlet.context-path:}")
    private String contextPath;

    private final AuthzProperties properties;

    private final Httpd httpd;

    private final UserDevicesDict userDevicesDict;

    private final PermissionDict permissionDict;

    private final PermLibrary permLibrary;

    private final Cache cache;

    private ApplicationContext ctx;

    public AuCoreInitialization(AuthzProperties properties,
                                Httpd httpd,
                                UserDevicesDict userDevicesDict,
                                PermissionDict permissionDict,
                                PermLibrary permLibrary,
                                Cache cache) {
        this.properties = properties;
        this.httpd = httpd;
        this.userDevicesDict = userDevicesDict;
        this.permissionDict = permissionDict;
        this.cache = cache;
        this.permLibrary = permLibrary;
    }

    @Override
    @SneakyThrows
    public void setApplicationContext(ApplicationContext applicationContext) {
        this.ctx = applicationContext;
        AbstractHandlerMethodMapping<RequestMappingInfo> methodMapping =
                (AbstractHandlerMethodMapping<RequestMappingInfo>) applicationContext.getBean("requestMappingHandlerMapping");
        Map<RequestMappingInfo, HandlerMethod> mapRet = methodMapping.getHandlerMethods();

        // init PermissionDict
        initPermissionDict(applicationContext, mapRet);
        LogUtils.logDebug("⬇ PermissionDict init success ⬇\n{}\n", AUtils.beautifulJson(permissionDict));

        // init Httpd
        initHttpd(applicationContext, mapRet);
        LogUtils.logDebug("⬇ Httpd init success ⬇\n{}\n", AUtils.beautifulJson(httpd));

        // init UserDevicesDict
        initUserDevicesDict();
        LogUtils.logDebug("UserDevicesDict init success");

        // init Jobs
        TaskBuilder.schedule(AuKey::refreshKeyGroup, properties.getRsaKeyRefreshWithPeriod());
        if (!properties.getCache().isEnableRedis()) {
            TaskBuilder.schedule(Pelcron::activeExpireCycle, properties.getUserBufferRefreshWithPeriod());
        }
        TaskBuilder.schedule(Pelcron::GC, properties.getGcPeriod());

        AuInit.log.info("Started Authz  Message id: {}", Message.id);
    }


    private void initPermissionDict(ApplicationContext applicationContext, Map<RequestMappingInfo, HandlerMethod> mapRet) {
        PermissionDict.setPermSeparator(properties.getPermSeparator());
        Set<String> roles = new HashSet<>();
        HashMap<String, Map<String, PermRolesMeta>> authzMetadata = new HashMap<>();
        Map<String, PermRolesMeta> pMap = new HashMap<>();
        Map<String, PermRolesMeta> rMap = new HashMap<>();
        applicationContext.getBeansWithAnnotation(Perms.class).forEach((key, value) -> {
            pMap.put(value.getClass().getName(),
                    generatePermRolesMeta(AnnotationUtils.getAnnotation(value.getClass(), Perms.class), null));
        });

        applicationContext.getBeansWithAnnotation(Roles.class).forEach((key, value) -> {
            rMap.put(value.getClass().getName(),
                    generatePermRolesMeta(null, AnnotationUtils.getAnnotation(value.getClass(), Roles.class)));
        });

        mapRet.forEach((key, value) -> {
            PermRolesMeta pFc = pMap.get(value.getBeanType().getName());
            PermRolesMeta rFc = rMap.get(value.getBeanType().getName());
            PermRolesMeta permRolesMeta = generatePermRolesMeta(value.getMethodAnnotation(Perms.class), value.getMethodAnnotation(Roles.class));

            if (rFc != null) {
                if (permRolesMeta.getRequireRoles() != null) {
                    permRolesMeta.getRequireRoles().addAll(rFc.getRequireRoles());
                } else {
                    permRolesMeta.setExcludeRoles(rFc.getRequireRoles());
                }
                if (permRolesMeta.getExcludeRoles() != null) {
                    permRolesMeta.getExcludeRoles().addAll(rFc.getExcludeRoles());
                } else {
                    permRolesMeta.setExcludeRoles(rFc.getExcludeRoles());
                }
            }
            if (pFc != null) {
                if (permRolesMeta.getRequirePermissions() != null) {
                    permRolesMeta.getRequirePermissions().addAll(pFc.getRequirePermissions());
                } else {
                    permRolesMeta.setRequirePermissions(rFc.getRequirePermissions());
                }
                if (permRolesMeta.getExcludePermissions() != null) {
                    permRolesMeta.getExcludePermissions().addAll(pFc.getExcludePermissions());
                } else {
                    permRolesMeta.setExcludePermissions(rFc.getExcludePermissions());
                }
            }
            if (permRolesMeta != null) {
                Set<Set<String>> requireRoles = permRolesMeta.getRequireRoles();
                Set<Set<String>> excludeRoles = permRolesMeta.getExcludeRoles();
                if (requireRoles != null) requireRoles.forEach(roles::addAll);
                if (excludeRoles != null) excludeRoles.forEach(roles::addAll);

                key.getMethodsCondition().getMethods().forEach(method -> {
                    key.getPatternsCondition().getPatterns().forEach(patternValue ->
                            authzMetadata.computeIfAbsent(method.toString(), r -> new HashMap<>()).put(contextPath + patternValue, permRolesMeta)
                    );
                });
            }

            // ------------- parameters init --------------- //
            key.getMethodsCondition().getMethods().forEach(method -> {
                key.getPatternsCondition().getPatterns().forEach(patternValue -> {
                    for (MethodParameter param : value.getMethodParameters()) {
                        Roles rolesByParam = param.getParameterAnnotation(Roles.class);
                        Perms permsByParam = param.getParameterAnnotation(Perms.class);
                        BatchAuthority batchAuthority = param.getParameterAnnotation(BatchAuthority.class);

                        if (rolesByParam != null || permsByParam != null || batchAuthority != null) {
                            RequestParam requestParam = param.getParameterAnnotation(RequestParam.class);
                            PathVariable pathVariable = param.getParameterAnnotation(PathVariable.class);
                            String paramName = param.getParameter().getName();

                            PermRolesMeta.ParamType type = null;
                            if (pathVariable != null) {
                                type = PermRolesMeta.ParamType.PATH_VARIABLE;
                                if (!pathVariable.name().equals("")) paramName = pathVariable.name();
                            } else if (requestParam != null) {
                                type = PermRolesMeta.ParamType.REQUEST_PARAM;
                                if (!requestParam.name().equals("")) paramName = requestParam.name();
                            }

                            ArrayList<PermRolesMeta.Meta> rolesMeta = new ArrayList<>();
                            ArrayList<PermRolesMeta.Meta> permsMeta = new ArrayList<>();
                            PermRolesMeta.Meta vr = generateRolesMeta(rolesByParam);
                            PermRolesMeta.Meta vp = generatePermMeta(permsByParam);
                            if (vr != null) rolesMeta.add(vr);
                            if (vp != null) permsMeta.add(vp);

                            if (batchAuthority != null) {
                                Roles[] rs = batchAuthority.roles();
                                for (Roles r : rs) {
                                    PermRolesMeta.Meta v = generateRolesMeta(r);
                                    if (v != null) rolesMeta.add(v);
                                }
                                Perms[] ps = batchAuthority.perms();
                                for (Perms p : ps) {
                                    PermRolesMeta.Meta v = generatePermMeta(p);
                                    if (v != null) permsMeta.add(v);
                                }
                            }

                            if (type != null) {
                                PermRolesMeta meta = authzMetadata.computeIfAbsent(method.toString(), r -> new HashMap<>())
                                        .computeIfAbsent(contextPath + patternValue, r -> new PermRolesMeta());
                                meta.put(type, paramName,
                                        new PermRolesMeta.ParamMetadata()
                                                .setRolesMeta(rolesMeta)
                                                .setPermissionsMeta(permsMeta)
                                );
                            }
                        }

                    }

                });
            });

        });

        try {
            permissionDict.init(authzMetadata);
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }

        Async.run(() -> {
            List<String> collect = roles.stream().collect(Collectors.toList());
            List<Set<String>> rolesPerms = RedisUtils.Obj.get(
                    collect.stream()
                            .map(role -> Constants.PERMISSIONS_BY_ROLE_KEY_PREFIX + role)
                            .collect(Collectors.toList())
            );
            Iterator<String> iterator = collect.iterator();
            HashMap<String, Set<String>> map = new HashMap<>();
            rolesPerms.forEach(perms -> map.put(iterator.next(), perms));
            map.forEach((role, v) -> {
                Set<String> permissions = permLibrary.getPermissionsByRole(role);
                cache.setSneaky(Constants.PERMISSIONS_BY_ROLE_KEY_PREFIX + role, permissions, Cache.INFINITE);
            });
        });

    }

    private PermRolesMeta.Meta generatePermMeta(Perms p) {
        if (p == null) return null;
        PermRolesMeta.Meta permsMeta = new PermRolesMeta.Meta();
        boolean flag = false;
        if (p.require() != null && p.require().length != 0) {
            permsMeta.setRequire(CollectionUtils.splitStrValsToSets(properties.getPermSeparator(), p.require()));
            flag = true;
        }
        if (p.exclude() != null && p.exclude().length != 0) {
            permsMeta.setExclude(CollectionUtils.splitStrValsToSets(properties.getPermSeparator(), p.exclude()));
            flag = true;
        }
        permsMeta.setResources(CollectionUtils.newSet(p.resources()));
        return flag ? permsMeta : null;
    }

    private PermRolesMeta.Meta generateRolesMeta(Roles r) {
        if (r == null) return null;
        PermRolesMeta.Meta rolesMeta = new PermRolesMeta.Meta();
        boolean flag = false;
        if (r.require() != null && r.require().length != 0) {
            rolesMeta.setRequire(CollectionUtils.splitStrValsToSets(properties.getPermSeparator(), r.require()));
            flag = true;
        }
        if (r.exclude() != null && r.exclude().length != 0) {
            rolesMeta.setExclude(CollectionUtils.splitStrValsToSets(properties.getPermSeparator(), r.exclude()));
            flag = true;
        }
        rolesMeta.setResources(CollectionUtils.newSet(r.resources()));
        return flag ? rolesMeta : null;
    }

    private PermRolesMeta generatePermRolesMeta(Perms p, Roles r) {
        PermRolesMeta prm = new PermRolesMeta();
        boolean flag = false;
        if (p != null) {
            if (p.require() != null && p.require().length != 0) {
                prm.setRequirePermissions(CollectionUtils.splitStrValsToSets(properties.getPermSeparator(), p.require()));
            }
            if (p.exclude() != null && p.exclude().length != 0) {
                prm.setExcludePermissions(CollectionUtils.splitStrValsToSets(properties.getPermSeparator(), p.exclude()));
            }
            flag = true;
        }
        if (r != null) {
            if (r.require() != null && r.require().length != 0) {
                prm.setRequireRoles(CollectionUtils.splitStrValsToSets(properties.getPermSeparator(), r.require()));
            }
            if (r.exclude() != null && r.exclude().length != 0) {
                prm.setExcludeRoles(CollectionUtils.splitStrValsToSets(properties.getPermSeparator(), r.exclude()));
            }
            flag = true;
        }
        return flag ? prm : null;
    }

    private void initHttpd(ApplicationContext applicationContext, Map<RequestMappingInfo, HandlerMethod> mapRet) {
        Map<String, Map<String, LimitMeta>> httpdLimitedMetaMap = httpd.getRateLimitMetadata();
        HashMap<String, LimitMeta> cMap = new HashMap<>();

        applicationContext.getBeansWithAnnotation(RateLimit.class).forEach((key, value) -> {
            Class<?> aClass = AopUtils.getTargetClass(value);
            RateLimit rateLimit = aClass.getAnnotation(RateLimit.class);
            if (rateLimit != null) {
                cMap.put(aClass.getName(),
                        new LimitMeta(rateLimit.window(), rateLimit.maxRequests(), rateLimit.punishmentTime(), rateLimit.minInterval(), rateLimit.associatedPatterns(), rateLimit.bannedType()));
            }
        });

        mapRet.forEach((key, value) -> {
            Set<RequestMethod> methods = key.getMethodsCondition().getMethods();
            Set<String> patternValues = key.getPatternsCondition().getPatterns();
            RateLimit rateLimit = value.getMethodAnnotation(RateLimit.class);
            if (rateLimit != null) {
                LimitMeta limitMeta = new LimitMeta(rateLimit.window(), rateLimit.maxRequests(), rateLimit.punishmentTime(), rateLimit.minInterval(), rateLimit.associatedPatterns(), rateLimit.bannedType());
                methods.forEach(
                        method -> patternValues.forEach(
                                patternValue -> httpdLimitedMetaMap.computeIfAbsent(method.toString(), r -> new HashMap<>()).put(contextPath + patternValue, limitMeta))
                );
            } else {
                methods.forEach(
                        method -> {
                            patternValues.forEach(
                                    patternValue -> {
                                        LimitMeta limitMeta = cMap.get(value.getBeanType().getName());
                                        if (limitMeta != null)
                                            httpdLimitedMetaMap
                                                    .computeIfAbsent(method.toString(), r -> new HashMap<>()).put(contextPath + patternValue, limitMeta);
                                    });
                        });
            }

            HashMap<String, Httpd.RequestPool> requestPool = new HashMap<>();

            key.getMethodsCondition().getMethods().forEach(
                    method -> {
                        key.getPatternsCondition()
                                .getPatterns()
                                .forEach(
                                        patternValue -> requestPool.put(contextPath + patternValue, new Httpd.RequestPool()));
                        httpd.getRequestPools().computeIfAbsent(method.toString(), r -> new ConcurrentHashMap<>()).putAll(requestPool);
                    });
        });

    }

    private void initUserDevicesDict() {
        DeviceConfig.isSupportMultiDevice = properties.getUser().isSupportMultiDevice();
        DeviceConfig.isSupportMultiUserForSameDeviceType = properties.getUser().isSupportMultiUserForSameDeviceType();
    }

}
