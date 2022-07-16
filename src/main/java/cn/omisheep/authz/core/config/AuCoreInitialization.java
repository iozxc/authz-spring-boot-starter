package cn.omisheep.authz.core.config;

import cn.omisheep.authz.annotation.*;
import cn.omisheep.authz.core.*;
import cn.omisheep.authz.core.auth.DefaultPermLibrary;
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
import cn.omisheep.authz.core.codec.AuthzRSAManager;
import cn.omisheep.authz.core.msg.Message;
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
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.system.ApplicationHome;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.handler.AbstractHandlerMethodMapping;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;

import java.lang.annotation.Annotation;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@SuppressWarnings("all")
public class AuCoreInitialization implements ApplicationContextAware {

    private       ApplicationContext ctx;
    private final AuthzProperties    properties;
    private final Httpd              httpd;
    private final UserDevicesDict    userDevicesDict;
    private final PermissionDict     permissionDict;
    private final PermLibrary        permLibrary;
    private final Cache              cache;

    public AuCoreInitialization(AuthzProperties properties, Httpd httpd,
                                UserDevicesDict userDevicesDict, PermissionDict permissionDict,
                                PermLibrary permLibrary, Cache cache) {
        this.properties      = properties;
        this.httpd           = httpd;
        this.userDevicesDict = userDevicesDict;
        this.permissionDict  = permissionDict;
        this.cache           = cache;
        this.permLibrary     = permLibrary;
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) {
        ctx = applicationContext;
        AUtils.init(applicationContext);
        init();
        CallbackInit.callbackInit(applicationContext);
        chechPermLibrary();
        printBanner();
    }

    public void printBanner() {
        if (properties.isBanner()) {
            System.out.println("               _    _          ");
            System.out.println("   :)         | |  | |         ");
            System.out.println("  __ _  _   _ | |_ | |__   ____");
            System.out.println(" / _` || | | || __|| '_ \\ |_  /");
            System.out.println("| (_| || |_| || |_ | | | | / / ");
            System.out.println(" \\__,_| \\__,_| \\__||_| |_|/___|");
            System.out.println("  \t\tAuthz  v" + AuthzVersion.getVersion());
        }
    }


    public void chechPermLibrary() {
        PermLibrary bean = ctx.getBean(PermLibrary.class);
        if (bean == null || bean instanceof DefaultPermLibrary) {
            AuInit.log.warn("not configured PermLibrary，Possible error in permission acquisition. Please implements cn.omisheep.authz.core.auth.PermLibrary");
        }
    }

    @SneakyThrows
    public void init() {
        AuthzAppVersion.init(properties.getApp());
        AbstractHandlerMethodMapping<RequestMappingInfo> methodMapping =
                (AbstractHandlerMethodMapping<RequestMappingInfo>) ctx.getBean("requestMappingHandlerMapping");
        Map<RequestMappingInfo, HandlerMethod> mapRet = methodMapping.getHandlerMethods();

        // init PermissionDict
        initPermissionDict(ctx, mapRet);
        LogUtils.debug("PermissionDict init success \n");

        // init Httpd
        initHttpd(ctx, mapRet);
        LogUtils.debug("Httpd init success \n");

        // init UserDevicesDict
        initUserDevicesDict();
        LogUtils.debug("UserDevicesDict init success");

        AuthzDefender.init(userDevicesDict, permLibrary);

        // init Jobs
        AuthzRSAManager.setTime(properties.getRsa().getRsaKeyRefreshWithPeriod());
        if (properties.getRsa().isAuto() && (properties.getRsa().getCustomPrivateKey() == null || properties.getRsa().getCustomPublicKey() == null)) {
            AuthzRSAManager.setAuto(true);
        } else {
            AuthzRSAManager.setAuto(false);
            AuthzProperties.RSAConfig rsaConfig = properties.getRsa();
            AuthzRSAManager.setAuKeyPair(rsaConfig.getCustomPublicKey(), rsaConfig.getCustomPrivateKey());
        }

        if (!properties.getCache().isEnableRedis()) {
            TaskBuilder.schedule(Pelcron::activeExpireCycle, properties.getUserBufferRefreshWithPeriod());
        }
        TaskBuilder.schedule(Pelcron::GC, properties.getGcPeriod());

        AuInit.log.info("Started Authz Message id: {}", Message.uuid);

        initVersionInfo();
        if (properties.isMd5check()) {
            AuInit.log.info("project md5 => {}", AuthzAppVersion.getMd5());
        }
    }

    private void initVersionInfo() {
        try {
            AuthzAppVersion.setProjectPath(getJarPath());
            AuthzAppVersion.setMd5check(properties.isMd5check());
            if (properties.getCache().isEnableRedis()) {
                AuthzAppVersion.born();
            }
        } catch (Exception e) {
            // skip
        }
    }

    @SneakyThrows
    private String getJarPath() {
        Object o = ctx.getBeansWithAnnotation(SpringBootApplication.class).values().stream().findAny().orElse(null);
        if (o != null) {
            ApplicationHome home = new ApplicationHome(o.getClass());
            return home.getSource().getAbsolutePath();
        }
        return null;
    }

    private <A extends Annotation> A getAnnoatation(Object value, Class<A> clz) {
        A annotation = AnnotatedElementUtils.getMergedAnnotation(value.getClass(), clz);
        try {
            if (annotation == null) {
                return AnnotatedElementUtils.getMergedAnnotation(Class.forName(getTypeName(value)), clz);
            } else return annotation;
        } catch (Exception e) {
            return null;
        }
    }

    private <A extends Annotation> Set<A> getAnnoatations(Object value, Class<A> clz) {
        Set<A> annotations = AnnotatedElementUtils.getAllMergedAnnotations(value.getClass(), clz);
        try {
            if (annotations == null || annotations.isEmpty()) {
                return AnnotatedElementUtils.getAllMergedAnnotations(Class.forName(getTypeName(value)), clz);
            } else return annotations;
        } catch (Exception e) {
            return null;
        }
    }

    public String getTypeName(Object value) {
        String name = value.getClass().getTypeName();
        int    i    = name.indexOf('$');
        if (i != -1) {
            return name.substring(0, name.indexOf("$"));
        } else {
            return name;
        }
    }

    private void initPermissionDict(ApplicationContext applicationContext, Map<RequestMappingInfo, HandlerMethod> mapRet) {
        PermissionDict.setPermSeparator(Constants.COMMA);
        Set<String>                                 toBeLoadedRoles      = new HashSet<>();
        HashMap<String, Map<String, PermRolesMeta>> authzMetadata        = new HashMap<>();
        HashMap<String, Map<String, IPRangeMeta>>   ipRangeMedata        = new HashMap<>();
        Map<String, Set<String>>                    certificatedMetadata = new HashMap<>();
        Map<String, PermRolesMeta>                  pMap                 = new HashMap<>();
        Map<String, PermRolesMeta>                  rMap                 = new HashMap<>();
        Map<String, IPRangeMeta>                    iMap                 = new HashMap<>();
        LinkedList<String>                          cList                = new LinkedList<>();

        applicationContext.getBeansWithAnnotation(Roles.class).forEach((key, value) -> {
            String name  = getTypeName(value);
            Roles  roles = getAnnoatation(value, Roles.class);
            if (roles != null) rMap.put(name, generatePermRolesMeta(null, roles));
        });

        applicationContext.getBeansWithAnnotation(Perms.class).forEach((key, value) -> {
            String name  = getTypeName(value);
            Perms  perms = getAnnoatation(value, Perms.class);
            if (perms != null) pMap.put(name, generatePermRolesMeta(perms, null));
        });


        applicationContext.getBeansWithAnnotation(Certificated.class).forEach((key, value) -> {
            Certificated certificated = getAnnoatation(value, Certificated.class);
            if (certificated != null) {
                cList.add(getTypeName(value));
            }
        });

        applicationContext.getBeansWithAnnotation(IPRangeLimit.class).forEach((key, value) -> {
            IPRangeLimit ipRangeLimit = getAnnoatation(value, IPRangeLimit.class);
            iMap.put(getTypeName(value), new IPRangeMeta().setAllow(ipRangeLimit.allow()).setDeny(ipRangeLimit.deny()));
        });

        mapRet.forEach((key, value) -> {
            IPRangeMeta   iFc           = iMap.get(value.getBeanType().getName());
            PermRolesMeta pFc           = pMap.get(value.getBeanType().getName());
            PermRolesMeta rFc           = rMap.get(value.getBeanType().getName());
            PermRolesMeta permRolesMeta = generatePermRolesMeta(value.getMethodAnnotation(Perms.class), value.getMethodAnnotation(Roles.class));
            IPRangeMeta   ipRangeMeta   = new IPRangeMeta();

            // 初始化Certifecated
            Certificated certificated = AnnotatedElementUtils.getMergedAnnotation(value.getMethod(), Certificated.class);
            if (cList.contains(value.getBeanType().getTypeName()) || certificated != null) {
                key.getMethodsCondition().getMethods().forEach(method -> certificatedMetadata.computeIfAbsent(method.name(), r -> new HashSet<>()).addAll(getPatterns(key)));
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
                key.getMethodsCondition().getMethods().forEach(method -> {
                    getPatterns(key).forEach(patternValue ->
                            authzMetadata.computeIfAbsent(method.toString(), r -> new HashMap<>()).put(patternValue, finalPermRolesMeta)
                    );
                });
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
            if (ipRangeMeta.getDeny() != null && !ipRangeMeta.getDeny().isEmpty() || ipRangeMeta.getAllow() != null && !ipRangeMeta.getAllow().isEmpty()) {
                key.getMethodsCondition().getMethods().forEach(method -> {
                    getPatterns(key).forEach(patternValue ->
                            ipRangeMedata.computeIfAbsent(method.toString(), r -> new HashMap<>()).put(patternValue, ipRangeMeta)
                    );
                });
            }


            // ------------- 初始化参数权限 --------------- //
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
            permissionDict.initCertificatedMetadata(certificatedMetadata);
            permissionDict.initGlobalAllow(IPRangeMeta.parse(properties.getGlobalIpRange().getAllow()));
            permissionDict.initGlobalDeny(IPRangeMeta.parse(properties.getGlobalIpRange().getDeny()));
            permissionDict.setSupportNative(properties.getGlobalIpRange().isSupportNative());
        } catch (Exception e) {
            LogUtils.error("init permissionDict error", e);
        }
        PermissionDict.init(permissionDict);

        if (properties.getCache().isEnableRedis()) {
            Async.run(() -> {
                List<String> collect = toBeLoadedRoles.stream().collect(Collectors.toList());
                List<Set<String>> rolesPerms = RedisUtils.Obj.get(
                        collect.stream()
                                .map(role -> Constants.PERMISSIONS_BY_ROLE_KEY_PREFIX.get() + role)
                                .collect(Collectors.toList())
                );
                Iterator<String>             iterator = collect.iterator();
                HashMap<String, Set<String>> map      = new HashMap<>();
                rolesPerms.forEach(perms -> map.put(iterator.next(), perms));
                map.forEach((role, v) -> {
                    Set<String> permissions = permLibrary.getPermissionsByRole(role);
                    cache.setSneaky(Constants.PERMISSIONS_BY_ROLE_KEY_PREFIX.get() + role, permissions, Cache.INFINITE);
                });
            });
        }
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
                        new LimitMeta(rateLimit.window(),
                                rateLimit.maxRequests(),
                                rateLimit.punishmentTime(),
                                rateLimit.minInterval(),
                                rateLimit.associatedPatterns(),
                                rateLimit.checkType()));
            }
        });

        mapRet.forEach((key, value) -> {
            Set<RequestMethod> methods   = key.getMethodsCondition().getMethods();
            RateLimit          rateLimit = value.getMethodAnnotation(RateLimit.class);
            if (rateLimit != null) {
                LimitMeta limitMeta = new LimitMeta(rateLimit.window(),
                        rateLimit.maxRequests(),
                        rateLimit.punishmentTime(),
                        rateLimit.minInterval(),
                        rateLimit.associatedPatterns(),
                        rateLimit.checkType());
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

            HashMap<String, Httpd.RequestPool> userIdRequestPool = new HashMap<>();
            HashMap<String, Httpd.RequestPool> ipRequestPool     = new HashMap<>();

            key.getMethodsCondition().getMethods().forEach(
                    method -> {
                        getPatterns(key)
                                .forEach(
                                        patternValue -> {
                                            userIdRequestPool.put(patternValue, new Httpd.RequestPool());
                                            ipRequestPool.put(patternValue, new Httpd.RequestPool());
                                            httpd.setPathPattern(patternValue);
                                        });
                        httpd.getIpRequestPools().computeIfAbsent(method.toString(), r -> new ConcurrentHashMap<>()).putAll(ipRequestPool);
                        httpd.getUserIdRequestPools().computeIfAbsent(method.toString(), r -> new ConcurrentHashMap<>()).putAll(userIdRequestPool);
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
