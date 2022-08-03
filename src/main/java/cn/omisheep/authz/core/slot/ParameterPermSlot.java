package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.rpd.ParamMetadata;
import cn.omisheep.authz.core.auth.rpd.ParamPermRolesMeta;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.util.ValueMatcher;
import cn.omisheep.commons.util.CollectionUtils;
import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerMapping;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static cn.omisheep.authz.core.util.LogUtils.logs;


/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Order(400)
@SuppressWarnings("all")
public class ParameterPermSlot implements Slot {

    private final PermLibrary permLibrary;

    public ParameterPermSlot(PermLibrary permLibrary) {
        this.permLibrary = permLibrary;
    }

    @Override
    public void chain(HttpMeta httpMeta,
                      HandlerMethod handler,
                      Error error) {
        if (!httpMeta.isHasParamAuth()) return;
        Map<String, ParamMetadata> paramPeMap = PermissionDict.getParamPermission()
                .get(httpMeta.getApi())
                .get(httpMeta.getMethod());

        Set<String> roles       = null;
        Set<String> permissions = null;

        Map<String, String> pathVariables = (Map<String, String>) httpMeta.getRequest().getAttribute(
                HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);

        for (MethodParameter parameter : handler.getMethodParameters()) {
            RequestParam requestParam = AnnotationUtils.getAnnotation(parameter.getParameter(), RequestParam.class);
            PathVariable pathVariable = AnnotationUtils.getAnnotation(parameter.getParameter(), PathVariable.class);

            String   paramName = parameter.getParameter().getName();
            Class<?> paramType = parameter.getParameter().getType();

            ParamMetadata.ParamType type  = null;
            String                  value = null;

            // 找到参数的类型和值
            if (pathVariable != null) {
                type = ParamMetadata.ParamType.PATH_VARIABLE;
                if (!pathVariable.name().equals("")) paramName = pathVariable.name();
                value = pathVariables.get(paramName);
            } else if (requestParam != null) {
                type = ParamMetadata.ParamType.REQUEST_PARAM;
                if (!requestParam.name().equals("")) paramName = requestParam.name();
                value = httpMeta.getRequest().getParameter(paramName);
            }

            // 类型匹配
            if (type == null) continue;

            if (value == null) continue; // value不为空

            ParamMetadata paramMetadata = null;
            try {
                paramMetadata = paramPeMap.get(paramName);
                if (paramMetadata.getParamType().equals(type)) continue;
            } catch (Exception e) {
                continue;
            }
            if (paramMetadata == null) continue; // 且需要保护

            List<ParamPermRolesMeta> paramMetaList = paramMetadata.getParamMetaList();
            if (paramMetaList == null || paramMetaList.isEmpty()) continue;

            if (!httpMeta.hasToken()) {
                logs("Require Login", httpMeta);
                error.error(ExceptionStatus.REQUIRE_LOGIN);
                return;
            }

            if (roles == null) roles = httpMeta.getRoles();
            if (permissions == null) permissions = httpMeta.getPermissions();

            List<ParamPermRolesMeta> resourcesMeta = paramMetaList.stream().filter(
                    meta -> meta.getResources() != null).collect(Collectors.toList());
            List<ParamPermRolesMeta> rangeMeta = paramMetaList.stream().filter(
                    meta -> meta.getRange() != null).collect(Collectors.toList());

            boolean next_resources = true;
            boolean next_range     = true;

            label_resources:
            for (ParamPermRolesMeta meta : resourcesMeta) {
                if (ValueMatcher.match(meta.getResources(), value, paramType)) { // 值是否匹配，若匹配上
                    if (!CollectionUtils.containsSub(meta.getRequireRoles(), roles)
                            || CollectionUtils.containsSub(meta.getExcludeRoles(), roles)
                            || !CollectionUtils.containsSub(meta.getRequirePermissions(), permissions)
                            || CollectionUtils.containsSub(meta.getExcludePermissions(), permissions)) { // 判断是否权限匹配
                        // 但是如果值匹配上但没有对应role，则不让通过
                        next_resources = false;
                        break label_resources;
                    }
                }
            }

            boolean flag = false;
            label_range:
            for (ParamPermRolesMeta meta : rangeMeta) {
                if (CollectionUtils.containsSub(meta.getRequireRoles(), roles)
                        || !CollectionUtils.containsSub(meta.getExcludeRoles(), roles)
                        || CollectionUtils.containsSub(meta.getRequirePermissions(), permissions)
                        || !CollectionUtils.containsSub(meta.getExcludePermissions(), permissions)) { // 判断是否权限匹配
                    next_range = false; // 如果有匹配上过role，那么就不能无损通过，则需要判断值是否在内
                    if (ValueMatcher.match(meta.getRange(), value, paramType)) {
                        flag = true; // 有一个匹配上就让过
                        break label_range;
                    }
                }
            }

            if (!next_resources || !(next_range || !next_range && flag)) {
                logs("Forbid : permissions exception by request parameter", httpMeta);
                error.error(ExceptionStatus.PERM_EXCEPTION);
                return;
            }

        }
    }


}
