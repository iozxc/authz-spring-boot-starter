package cn.omisheep.authz.core.util;

import cn.omisheep.authz.annotation.Perms;
import cn.omisheep.authz.annotation.Roles;
import cn.omisheep.authz.core.auth.rpd.PermRolesMeta;
import cn.omisheep.authz.core.config.Constants;
import cn.omisheep.commons.util.CollectionUtils;
import org.springframework.core.annotation.AnnotatedElementUtils;

import java.lang.annotation.Annotation;
import java.util.Set;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class MetaUtils {
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

    public static <A extends Annotation> A getAnnoatation(Object value, Class<A> clz) {
        A annotation = AnnotatedElementUtils.getMergedAnnotation(value.getClass(), clz);
        try {
            if (annotation == null) {
                return AnnotatedElementUtils.getMergedAnnotation(Class.forName(getTypeName(value)), clz);
            } else return annotation;
        } catch (Exception e) {
            return null;
        }
    }

    public static <A extends Annotation> Set<A> getAnnoatations(Object value, Class<A> clz) {
        Set<A> annotations = AnnotatedElementUtils.getAllMergedAnnotations(value.getClass(), clz);
        try {
            if (annotations.isEmpty()) {
                return AnnotatedElementUtils.getAllMergedAnnotations(Class.forName(getTypeName(value)), clz);
            } else return annotations;
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

}