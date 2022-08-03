package cn.omisheep.authz.core.util;

import cn.omisheep.authz.annotation.*;
import cn.omisheep.authz.core.auth.rpd.*;
import cn.omisheep.authz.core.config.Constants;
import cn.omisheep.commons.util.CollectionUtils;
import lombok.SneakyThrows;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;

import java.lang.annotation.Annotation;
import java.util.Set;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class MetaUtils {

    public static ParamPermRolesMeta generateParamMeta(AuthParam r) {
        if (r == null) return null;
        ParamPermRolesMeta meta = new ParamPermRolesMeta();
        if (r.requireRoles() != null && r.requireRoles().length != 0) {
            meta.setRequireRoles(CollectionUtils.splitStrValsToSets(Constants.COMMA, r.requireRoles()));
        }
        if (r.excludeRoles() != null && r.excludeRoles().length != 0) {
            meta.setExcludeRoles(CollectionUtils.splitStrValsToSets(Constants.COMMA, r.excludeRoles()));
        }
        if (r.requirePermissions() != null && r.requirePermissions().length != 0) {
            meta.setRequirePermissions(CollectionUtils.splitStrValsToSets(Constants.COMMA, r.requirePermissions()));
        }
        if (r.excludePermissions() != null && r.excludePermissions().length != 0) {
            meta.setExcludePermissions(CollectionUtils.splitStrValsToSets(Constants.COMMA, r.excludePermissions()));
        }
        if (r.resources() != null && r.resources().length != 0) {
            meta.setResources(CollectionUtils.ofSet(r.resources()));
        }
        if (r.range() != null && r.range().length != 0) {
            meta.setRange(CollectionUtils.ofSet(r.range()));
        }
        return meta;
    }

    public static void generateParamMeta(DataPermRolesMeta meta,
                                         AuthData r) {
        if (r.requireRoles() != null && r.requireRoles().length != 0) {
            meta.setRequireRoles(CollectionUtils.splitStrValsToSets(Constants.COMMA, r.requireRoles()));
        }
        if (r.excludeRoles() != null && r.excludeRoles().length != 0) {
            meta.setExcludeRoles(CollectionUtils.splitStrValsToSets(Constants.COMMA, r.excludeRoles()));
        }
        if (r.requirePermissions() != null && r.requirePermissions().length != 0) {
            meta.setRequirePermissions(CollectionUtils.splitStrValsToSets(Constants.COMMA, r.requirePermissions()));
        }
        if (r.excludePermissions() != null && r.excludePermissions().length != 0) {
            meta.setExcludePermissions(CollectionUtils.splitStrValsToSets(Constants.COMMA, r.excludePermissions()));
        }
    }

    public static PermRolesMeta generatePermRolesMeta(Set<Auth> auths) {
        if (auths.isEmpty()) return null;
        PermRolesMeta prm = new PermRolesMeta();
        auths.forEach(auth -> prm.merge(
                generatePermRolesMeta(auth.requireRoles(), auth.excludeRoles(), auth.requirePermissions(),
                                      auth.excludePermissions())));
        return !prm.non() ? prm : null;
    }

    public static PermRolesMeta generatePermRolesMeta(Auth auth) {
        return generatePermRolesMeta(CollectionUtils.newSet(auth));
    }

    public static <A extends Annotation> A getAnnotation(Object value,
                                                         Class<A> clz) {
        A annotation = AnnotatedElementUtils.getMergedAnnotation(value.getClass(), clz);
        try {
            if (annotation == null) {
                return AnnotatedElementUtils.getMergedAnnotation(Class.forName(getTypeName(value)), clz);
            } else {return annotation;}
        } catch (Exception e) {
            return null;
        }
    }

    public static <A extends Annotation> Set<A> getAnnotations(Object value,
                                                               Class<A> clz) {
        Set<A> annotations = AnnotatedElementUtils.getAllMergedAnnotations(value.getClass(), clz);
        try {
            if (annotations.isEmpty()) {
                return AnnotatedElementUtils.getAllMergedAnnotations(Class.forName(getTypeName(value)), clz);
            } else {return annotations;}
        } catch (Exception e) {
            return null;
        }
    }

    public static String getTypeName(Object value) {
        String name = value.getClass().getTypeName();
        int    i    = name.indexOf('$');
        if (i != -1) {
            return name.substring(0, name.indexOf("$"));
        } else {
            return name;
        }
    }

    @SuppressWarnings("all")
    @SneakyThrows
    public static Set<String> getPatterns(RequestMappingInfo info) {
        try {
            return info.getPatternsCondition().getPatterns();
        } catch (Exception e) {
            return (Set<String>) RequestMappingInfo.class.getMethod("getPatternValues").invoke(info);
        }
    }

    public static DataPermRolesMeta generateDataRolesMeta(AuthData authData) {
        DataPermRolesMeta dataPermRolesMeta = DataPermRolesMeta.of(authData.condition());
        Arg[]             conditionArgs     = authData.args();
        for (Arg arg : conditionArgs) {
            String   resource     = arg.resource();
            String[] resourceArgs = arg.args();
            dataPermRolesMeta.addArg(resource, resourceArgs);
        }
        generateParamMeta(dataPermRolesMeta, authData);
        return dataPermRolesMeta;
    }

    public static FieldDataPermRolesMeta generateDataFiledRolesMeta(String className,
                                                                    AuthField authField) {
        if (authField == null) return null;
        ParamPermRolesMeta meta = new ParamPermRolesMeta();
        if (authField.requireRoles() != null && authField.requireRoles().length != 0) {
            meta.setRequireRoles(CollectionUtils.splitStrValsToSets(Constants.COMMA, authField.requireRoles()));
        }
        if (authField.excludeRoles() != null && authField.excludeRoles().length != 0) {
            meta.setExcludeRoles(CollectionUtils.splitStrValsToSets(Constants.COMMA, authField.excludeRoles()));
        }
        if (authField.requirePermissions() != null && authField.requirePermissions().length != 0) {
            meta.setRequirePermissions(
                    CollectionUtils.splitStrValsToSets(Constants.COMMA, authField.requirePermissions()));
        }
        if (authField.excludePermissions() != null && authField.excludePermissions().length != 0) {
            meta.setExcludePermissions(
                    CollectionUtils.splitStrValsToSets(Constants.COMMA, authField.excludePermissions()));
        }

        return FieldDataPermRolesMeta.of(className, meta);
    }

    public static PermRolesMeta generatePermRolesMeta(String[] requireRoles,
                                                      String[] excludeRoles,
                                                      String[] requirePermissions,
                                                      String[] excludePermissions) {
        PermRolesMeta prm = new PermRolesMeta();
        if (requireRoles.length != 0) {
            prm.setRequireRoles(CollectionUtils.splitStrValsToSets(Constants.COMMA, requireRoles));
        }
        if (excludeRoles.length != 0) {
            prm.setExcludeRoles(CollectionUtils.splitStrValsToSets(Constants.COMMA, excludeRoles));
        }

        if (requirePermissions.length != 0) {
            prm.setRequirePermissions(CollectionUtils.splitStrValsToSets(Constants.COMMA, requirePermissions));
        }
        if (excludePermissions.length != 0) {
            prm.setExcludePermissions(CollectionUtils.splitStrValsToSets(Constants.COMMA, excludePermissions));
        }
        return !prm.non() ? prm : null;
    }

}
