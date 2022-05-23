package cn.omisheep.authz.core.init;

import cn.omisheep.authz.annotation.*;
import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.Constants;
import cn.omisheep.authz.core.Pelcron;
import cn.omisheep.authz.core.VersionInfo;
import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.deviced.DeviceConfig;
import cn.omisheep.authz.core.auth.deviced.UserDevicesDict;
import cn.omisheep.authz.core.auth.ipf.Httpd;
import cn.omisheep.authz.core.auth.ipf.LimitMeta;
import cn.omisheep.authz.core.auth.rpd.AuthzDefender;
import cn.omisheep.authz.core.auth.rpd.ParamMetadata;
import cn.omisheep.authz.core.auth.rpd.PermRolesMeta;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.msg.Message;
import cn.omisheep.authz.core.tk.AuKey;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.authz.core.util.LogUtils;
import cn.omisheep.authz.core.util.RedisUtils;
import cn.omisheep.authz.core.util.ValueMatcher;
import cn.omisheep.authz.support.util.IPRangeMeta;
import cn.omisheep.commons.util.Async;
import cn.omisheep.commons.util.CollectionUtils;
import cn.omisheep.commons.util.TaskBuilder;
import lombok.SneakyThrows;
import org.springframework.aop.support.AopUtils;
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
import java.util.concurrent.ScheduledFuture;
import java.util.stream.Collectors;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@SuppressWarnings("all")
public class AuCoreInitialization implements ApplicationContextAware {

    private final AuthzProperties properties;

    private final Httpd httpd;

    private final UserDevicesDict userDevicesDict;

    private final PermissionDict permissionDict;

    private final AuthzDefender authzDefender;

    private final PermLibrary permLibrary;

    private final Cache cache;

    private ApplicationContext ctx;

    public AuCoreInitialization(AuthzProperties properties,
                                Httpd httpd,
                                UserDevicesDict userDevicesDict,
                                PermissionDict permissionDict,
                                PermLibrary permLibrary,
                                AuthzDefender authzDefender,
                                Cache cache) {
        this.properties      = properties;
        this.httpd           = httpd;
        this.userDevicesDict = userDevicesDict;
        this.permissionDict  = permissionDict;
        this.cache           = cache;
        this.permLibrary     = permLibrary;
        this.authzDefender   = authzDefender;
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

        AuthzDefender.init(authzDefender);

        // init Jobs
        AuKey.setTime(properties.getUserBufferRefreshWithPeriod());
        if (properties.getRsa().isAuto() && properties.getRsa().getCustomPrivateKey() != null && properties.getRsa().getCustomPublicKey() != null) {
            ScheduledFuture<?> schedule = TaskBuilder.schedule(AuKey::refreshKeyGroup, properties.getRsa().getRsaKeyRefreshWithPeriod());
            AuKey.setAuto(true);
            AuKey.setScheduledFuture(schedule);
        } else {
            AuKey.setAuto(false);
            AuthzProperties.RSAConfig rsaConfig = properties.getRsa();
            AuKey.setAuKeyPair(rsaConfig.getCustomPublicKey(), rsaConfig.getCustomPrivateKey());
        }

        if (!properties.getCache().isEnableRedis()) {
            TaskBuilder.schedule(Pelcron::activeExpireCycle, properties.getUserBufferRefreshWithPeriod());
        }
        TaskBuilder.schedule(Pelcron::GC, properties.getGcPeriod());

        AuInit.log.info("Started Authz  Message id: {}", Message.uuid);

        VersionInfo.born();
    }

    private void initPermissionDict(ApplicationContext applicationContext, Map<RequestMappingInfo, HandlerMethod> mapRet) {
        PermissionDict.setPermSeparator(Constants.COMMA);
        Set<String>                                 toBeLoadedRoles = new HashSet<>();
        HashMap<String, Map<String, PermRolesMeta>> authzMetadata   = new HashMap<>();
        HashMap<String, Map<String, IPRangeMeta>>   ipRangeMedata   = new HashMap<>();
        Map<String, PermRolesMeta>                  pMap            = new HashMap<>();
        Map<String, PermRolesMeta>                  rMap            = new HashMap<>();
        Map<String, IPRangeMeta>                    iMap            = new HashMap<>();

        applicationContext.getBeansWithAnnotation(Perms.class).forEach((key, value) -> {
            pMap.put(value.getClass().getName(),
                    generatePermRolesMeta(AnnotationUtils.getAnnotation(value.getClass(), Perms.class), null));
        });

        applicationContext.getBeansWithAnnotation(Roles.class).forEach((key, value) -> {
            rMap.put(value.getClass().getName(),
                    generatePermRolesMeta(null, AnnotationUtils.getAnnotation(value.getClass(), Roles.class)));
        });

        applicationContext.getBeansWithAnnotation(IPRangeLimit.class).forEach((key, value) -> {
            IPRangeLimit ipRangeLimit = AnnotationUtils.getAnnotation(value.getClass(), IPRangeLimit.class);
            iMap.put(value.getClass().getName(), new IPRangeMeta().setAllow(ipRangeLimit.allow()).setDeny(ipRangeLimit.deny()));
        });

        mapRet.forEach((key, value) -> {
            IPRangeMeta   iFc           = iMap.get(value.getBeanType().getName());
            PermRolesMeta pFc           = pMap.get(value.getBeanType().getName());
            PermRolesMeta rFc           = rMap.get(value.getBeanType().getName());
            PermRolesMeta permRolesMeta = generatePermRolesMeta(value.getMethodAnnotation(Perms.class), value.getMethodAnnotation(Roles.class));
            IPRangeMeta   ipRangeMeta   = new IPRangeMeta();
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
                if (pFc.getRequirePermissions() != null) {
                    if (permRolesMeta.getRequirePermissions() != null) {
                        permRolesMeta.getRequirePermissions().addAll(pFc.getRequirePermissions());
                    } else {
                        permRolesMeta.setRequirePermissions(rFc.getRequirePermissions());
                    }
                }
                if (pFc.getExcludePermissions() != null) {
                    if (permRolesMeta.getExcludePermissions() != null) {
                        permRolesMeta.getExcludePermissions().addAll(pFc.getExcludePermissions());
                    } else {
                        permRolesMeta.setExcludePermissions(rFc.getExcludePermissions());
                    }
                }
            }
            if (permRolesMeta != null) {
                Set<Set<String>> requireRoles = permRolesMeta.getRequireRoles();
                Set<Set<String>> excludeRoles = permRolesMeta.getExcludeRoles();
                if (requireRoles != null) requireRoles.forEach(toBeLoadedRoles::addAll);
                if (excludeRoles != null) excludeRoles.forEach(toBeLoadedRoles::addAll);

                PermRolesMeta finalPermRolesMeta = permRolesMeta;
                key.getMethodsCondition().getMethods().forEach(method -> {
                    getPatterns(key).forEach(patternValue ->
                            authzMetadata.computeIfAbsent(method.toString(), r -> new HashMap<>()).put(patternValue, finalPermRolesMeta)
                    );
                });
            }

            if (iFc != null) {
                ipRangeMeta.setAllow(iFc.getAllow());
                ipRangeMeta.setDeny(iFc.getDeny());
            }

            IPRangeLimit ipRangeLimit = value.getMethodAnnotation(IPRangeLimit.class);
            if (ipRangeLimit != null) {
                ipRangeMeta.setAllow(ipRangeLimit.allow()).setDeny(ipRangeLimit.deny());
                ipRangeMeta.getAllow().addAll(iFc.getAllow());
                ipRangeMeta.getDeny().addAll(iFc.getDeny());
            }
            if (ipRangeMeta.getDeny() != null && !ipRangeMeta.getDeny().isEmpty() || ipRangeMeta.getAllow() != null && !ipRangeMeta.getAllow().isEmpty()) {
                key.getMethodsCondition().getMethods().forEach(method -> {
                    getPatterns(key).forEach(patternValue ->
                            ipRangeMedata.computeIfAbsent(method.toString(), r -> new HashMap<>()).put(patternValue, ipRangeMeta)
                    );
                });
            }


            // ------------- parameters init --------------- //
            key.getMethodsCondition().getMethods().forEach(method -> {
                getPatterns(key).forEach(patternValue -> {
                    Map<String, Map<ParamMetadata.ParamType, Map<String, Class<?>>>> methodRawMap       = permissionDict.getRawMap().computeIfAbsent(method.toString(), r -> new HashMap<>());
                    Map<ParamMetadata.ParamType, Map<String, Class<?>>>              rawParamTypeMapMap = methodRawMap.computeIfAbsent(patternValue, r -> new HashMap<>());
                    for (MethodParameter param : value.getMethodParameters()) {
                        Class<?> paramType = param.getParameter().getType();
                        if (ValueMatcher.checkType(paramType).isOther()) {
                            continue;
                        }

                        RequestParam requestParam = param.getParameterAnnotation(RequestParam.class);
                        PathVariable pathVariable = param.getParameterAnnotation(PathVariable.class);
                        String       paramName    = param.getParameter().getName();

                        ParamMetadata.ParamType type = null;
                        if (pathVariable != null) {
                            type = ParamMetadata.ParamType.PATH_VARIABLE;
                            if (!pathVariable.name().equals("")) paramName = pathVariable.name();
                        } else if (requestParam != null) {
                            type = ParamMetadata.ParamType.REQUEST_PARAM;
                            if (!requestParam.name().equals("")) paramName = requestParam.name();
                        }

                        Map<String, Class<?>> rawParamMap = rawParamTypeMapMap.computeIfAbsent(type, r -> new HashMap<>());
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

                            if (type != null) {
                                PermRolesMeta meta = authzMetadata.computeIfAbsent(method.toString(), r -> new HashMap<>())
                                        .computeIfAbsent(patternValue, r -> new PermRolesMeta());
                                meta.put(type, paramName,
                                        new ParamMetadata(paramType, rolesMetaList, permsMetaList)
                                );
                            }
                        }

                    }
                });
            });

        });

        try {
            permissionDict.initAuthzMetadata(authzMetadata);
            permissionDict.initIPRangeMeta(ipRangeMedata);
            permissionDict.setGlobalAllow(IPRangeMeta.parse(properties.getGlobalIpRange().getAllow()));
            permissionDict.setGlobalDeny(IPRangeMeta.parse(properties.getGlobalIpRange().getDeny()));
            permissionDict.setSupportNative(properties.getGlobalIpRange().isSupportNative());
        } catch (Exception e) {
            e.printStackTrace();
        }
        PermissionDict.init(permissionDict);

        Async.run(() -> {
            List<String> collect = toBeLoadedRoles.stream().collect(Collectors.toList());
            List<Set<String>> rolesPerms = RedisUtils.Obj.get(
                    collect.stream()
                            .map(role -> Constants.PERMISSIONS_BY_ROLE_KEY_PREFIX + role)
                            .collect(Collectors.toList())
            );
            Iterator<String>             iterator = collect.iterator();
            HashMap<String, Set<String>> map      = new HashMap<>();
            rolesPerms.forEach(perms -> map.put(iterator.next(), perms));
            map.forEach((role, v) -> {
                Set<String> permissions = permLibrary.getPermissionsByRole(role);
                cache.setSneaky(Constants.PERMISSIONS_BY_ROLE_KEY_PREFIX + role, permissions, Cache.INFINITE);
            });
        });

    }

    public static PermRolesMeta.Meta generatePermMeta(Perms p) {
        if (p == null) return null;
        PermRolesMeta.Meta permsMeta = new PermRolesMeta.Meta();
        boolean            flag      = false;
        if (p.require() != null && p.require().length != 0) {
            permsMeta.setRequire(CollectionUtils.splitStrValsToSets(Constants.COMMA, p.require()));
            flag = true;
        }
        if (p.exclude() != null && p.exclude().length != 0) {
            permsMeta.setExclude(CollectionUtils.splitStrValsToSets(Constants.COMMA, p.exclude()));
            flag = true;
        }
        if (p.paramResources().length != 0) {
            permsMeta.setResources(CollectionUtils.ofSet(p.paramResources()));
        }
        if (p.paramRange().length != 0) {
            permsMeta.setRange(CollectionUtils.ofSet(p.paramRange()));
        }
        return flag ? permsMeta : null;
    }

    public static PermRolesMeta.Meta generateRolesMeta(Roles r) {
        if (r == null) return null;
        PermRolesMeta.Meta rolesMeta = new PermRolesMeta.Meta();
        boolean            flag      = false;
        if (r.require() != null && r.require().length != 0) {
            rolesMeta.setRequire(CollectionUtils.splitStrValsToSets(Constants.COMMA, r.require()));
            flag = true;
        }
        if (r.exclude() != null && r.exclude().length != 0) {
            rolesMeta.setExclude(CollectionUtils.splitStrValsToSets(Constants.COMMA, r.exclude()));
            flag = true;
        }
        if (r.paramResources().length != 0) {
            rolesMeta.setResources(CollectionUtils.ofSet(r.paramResources()));
        }
        if (r.paramRange().length != 0) {
            rolesMeta.setRange(CollectionUtils.ofSet(r.paramRange()));
        }
        return flag ? rolesMeta : null;
    }

    public static PermRolesMeta generatePermRolesMeta(Perms p, Roles r) {
        PermRolesMeta prm  = new PermRolesMeta();
        boolean       flag = false;
        if (p != null) {
            if (p.require() != null && p.require().length != 0) {
                prm.setRequirePermissions(CollectionUtils.splitStrValsToSets(Constants.COMMA, p.require()));
            }
            if (p.exclude() != null && p.exclude().length != 0) {
                prm.setExcludePermissions(CollectionUtils.splitStrValsToSets(Constants.COMMA, p.exclude()));
            }
            flag = true;
        }
        if (r != null) {
            if (r.require() != null && r.require().length != 0) {
                prm.setRequireRoles(CollectionUtils.splitStrValsToSets(Constants.COMMA, r.require()));
            }
            if (r.exclude() != null && r.exclude().length != 0) {
                prm.setExcludeRoles(CollectionUtils.splitStrValsToSets(Constants.COMMA, r.exclude()));
            }
            flag = true;
        }
        return flag ? prm : null;
    }

    private void initHttpd(ApplicationContext applicationContext, Map<RequestMappingInfo, HandlerMethod> mapRet) {
        Map<String, Map<String, LimitMeta>> httpdLimitedMetaMap = httpd.getRateLimitMetadata();
        HashMap<String, LimitMeta>          cMap                = new HashMap<>();

        applicationContext.getBeansWithAnnotation(RateLimit.class).forEach((key, value) -> {
            Class<?>  aClass    = AopUtils.getTargetClass(value);
            RateLimit rateLimit = aClass.getAnnotation(RateLimit.class);
            if (rateLimit != null) {
                cMap.put(aClass.getName(),
                        new LimitMeta(rateLimit.window(), rateLimit.maxRequests(), rateLimit.punishmentTime(), rateLimit.minInterval(), rateLimit.associatedPatterns(), rateLimit.bannedType()));
            }
        });

        mapRet.forEach((key, value) -> {
            Set<RequestMethod> methods   = key.getMethodsCondition().getMethods();
            RateLimit          rateLimit = value.getMethodAnnotation(RateLimit.class);
            if (rateLimit != null) {
                LimitMeta limitMeta = new LimitMeta(rateLimit.window(), rateLimit.maxRequests(), rateLimit.punishmentTime(), rateLimit.minInterval(), rateLimit.associatedPatterns(), rateLimit.bannedType());
                methods.forEach(
                        method -> getPatterns(key).forEach(
                                patternValue -> httpdLimitedMetaMap.computeIfAbsent(method.toString(), r -> new HashMap<>()).put(patternValue, limitMeta))
                );
            } else {
                methods.forEach(
                        method -> {

                            getPatterns(key).forEach(
                                    patternValue -> {
                                        LimitMeta limitMeta = cMap.get(value.getBeanType().getName());
                                        if (limitMeta != null)
                                            httpdLimitedMetaMap
                                                    .computeIfAbsent(method.toString(), r -> new HashMap<>()).put(patternValue, limitMeta);
                                    });
                        });
            }

            HashMap<String, Httpd.RequestPool> requestPool = new HashMap<>();

            key.getMethodsCondition().getMethods().forEach(
                    method -> {
                        getPatterns(key)
                                .forEach(
                                        patternValue -> requestPool.put(patternValue, new Httpd.RequestPool()));
                        httpd.getRequestPools().computeIfAbsent(method.toString(), r -> new ConcurrentHashMap<>()).putAll(requestPool);
                    });
        });

        httpd.setIgnoreSuffix(properties.getIgnoreSuffix());
    }

    private void initUserDevicesDict() {
        DeviceConfig.isSupportMultiDevice                = properties.getUser().isSupportMultiDevice();
        DeviceConfig.isSupportMultiUserForSameDeviceType = properties.getUser().isSupportMultiUserForSameDeviceType();
    }

    @SneakyThrows
    private Set<String> getPatterns(RequestMappingInfo info) {
        try {
            return info.getPatternsCondition().getPatterns();
        } catch (Exception e) {
            return (Set<String>) RequestMappingInfo.class.getMethod("getPatternValues").invoke(info);
        }
    }

}
