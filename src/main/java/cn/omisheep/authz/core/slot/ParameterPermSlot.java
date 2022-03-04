package cn.omisheep.authz.core.slot;

import cn.omisheep.authz.core.ExceptionStatus;
import cn.omisheep.authz.core.auth.PermLibrary;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.rpd.ParamMetadata;
import cn.omisheep.authz.core.auth.rpd.PermRolesMeta;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.util.ValueMatcher;
import cn.omisheep.commons.util.CollectionUtils;
import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerMapping;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static cn.omisheep.authz.core.auth.rpd.AuthzDefender.logs;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Order(40)
@SuppressWarnings("all")
public class ParameterPermSlot implements Slot {

    private final PermissionDict permissionDict;
    private final PermLibrary permLibrary;

    public ParameterPermSlot(PermissionDict permissionDict, PermLibrary permLibrary) {
        this.permissionDict = permissionDict;
        this.permLibrary = permLibrary;
    }

    @Override
    public boolean chain(HttpMeta httpMeta, HandlerMethod handler) throws Exception {
        PermRolesMeta permRolesMeta = permissionDict.getAuthzMetadata().get(httpMeta.getMethod()).get(httpMeta.getApi());
        Set<String> roles = null;
        Set<String> permissions = new HashSet<>();

        for (MethodParameter parameter : handler.getMethodParameters()) {
            RequestParam requestParam = AnnotationUtils.getAnnotation(parameter.getParameter(), RequestParam.class);
            PathVariable pathVariable = AnnotationUtils.getAnnotation(parameter.getParameter(), PathVariable.class);

            String paramName = parameter.getParameter().getName();
            Class<?> paramType = parameter.getParameter().getType();
            ParamMetadata.ParamType type = null;
            String value = null;
            if (pathVariable != null) {
                type = ParamMetadata.ParamType.PATH_VARIABLE;
                if (!pathVariable.name().equals("")) paramName = pathVariable.name();

                Map<String, String> pathVariables = (Map<String, String>) httpMeta.getRequest().getAttribute(
                        HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
                value = pathVariables.get(paramName);
            } else if (requestParam != null) {
                type = ParamMetadata.ParamType.REQUEST_PARAM;
                if (!requestParam.name().equals("")) paramName = requestParam.name();
                value = httpMeta.getRequest().getParameter(paramName);
            }
            // 类型匹配上了
            if (type != null) {
                if (value == null) continue; // value不为空

                ParamMetadata paramMetadata = null;
                try {
                    paramMetadata = permRolesMeta.getParamPermissionsMetadata().get(type).get(paramName);
                } catch (Exception e) {
                    continue;
                }
                if (paramMetadata == null) continue; // 且需要保护

                List<PermRolesMeta.Meta> rolesMetaList = paramMetadata.getRolesMetaList();

                rolesMetaCheck:
                if (rolesMetaList != null && !rolesMetaList.isEmpty()) {
                    if (httpMeta.getToken() == null) {
                        logs("Require Login", httpMeta, permRolesMeta);
                        httpMeta.error(ExceptionStatus.REQUIRE_LOGIN);
                        return false;
                    }
                    roles = permLibrary.getRolesByUserId(httpMeta.getToken().getUserId());
                    boolean next = false;
                    label:
                    for (PermRolesMeta.Meta meta : rolesMetaList) {
                        if (ValueMatcher.match(meta.getResources(), value, paramType)) { // 值是否匹配，若匹配上
                            if (CollectionUtils.containsSub(meta.getRequire(), roles)) { // 判断是否权限匹配
                                // 匹配失败继续看后面的是否有匹配上的，如果都匹配失败，则返回权限不足
                                // 匹配成功则直接过
                                next = true;
                                break label;
                            }
                        }
                    }
                    if (!next) {
                        if (rolesMetaList.stream().filter(meta -> meta.getResources().contains("*")).count() == 0) {
                            // 如果没有带*的匹配，那么如果值不属于其中，默认通过
                            String finalValue = value;
                            if (!rolesMetaList.stream().anyMatch(meta -> ValueMatcher.match(meta.getResources(), finalValue, paramType))) {
                                break rolesMetaCheck;
                            }
                        }
                        logs("Forbid : permissions exception by request parameter", httpMeta, permRolesMeta);
                        httpMeta.error(ExceptionStatus.PERM_EXCEPTION);
                        return false;
                    }
                }

                List<PermRolesMeta.Meta> permissionsMetaList = paramMetadata.getPermissionsMetaList();
                permMetaCheck:
                if (permissionsMetaList != null && !permissionsMetaList.isEmpty()) {
                    if (httpMeta.getToken() == null) {
                        logs("Require Login", httpMeta, permRolesMeta);
                        httpMeta.error(ExceptionStatus.REQUIRE_LOGIN);
                        return false;
                    }
                    if (roles == null) {
                        roles = permLibrary.getRolesByUserId(httpMeta.getToken().getUserId());
                    }
                    for (String role : roles) {
                        Set<String> permissionsByRole = permLibrary.getPermissionsByRole(role);
                        permissions.addAll(permissionsByRole);
                    }

                    boolean next = false;
                    label:
                    for (PermRolesMeta.Meta meta : permissionsMetaList) {
                        if (ValueMatcher.match(meta.getResources(), value, paramType)) { // 值是否匹配，若匹配上
                            if (CollectionUtils.containsSub(meta.getRequire(), permissions)) { // 判断是否权限匹配
                                // 匹配失败继续看后面的是否有匹配上的，如果都匹配失败，则返回权限不足
                                // 匹配成功则直接过
                                next = true;
                                break label;
                            }
                        }
                    }

                    if (!next) {
                        if (permissionsMetaList.stream().filter(meta -> meta.getResources().contains("*")).count() == 0) {
                            // 如果没有带*的匹配，那么如果值不属于其中，默认通过
                            String finalValue = value;
                            if (!permissionsMetaList.stream().anyMatch(meta -> ValueMatcher.match(meta.getResources(), finalValue, paramType))) {
                                break permMetaCheck;
                            }
                        }
                        logs("Forbid : permissions exception by request parameter", httpMeta, permRolesMeta);
                        httpMeta.error(ExceptionStatus.PERM_EXCEPTION);
                        return false;
                    }
                }
            }
        }
        return true;
    }


}
