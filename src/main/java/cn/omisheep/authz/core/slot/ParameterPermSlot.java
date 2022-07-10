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

import java.util.*;
import java.util.stream.Collectors;

import static cn.omisheep.authz.core.auth.rpd.AuthzDefender.logs;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Order(400)
@SuppressWarnings("all")
public class ParameterPermSlot implements Slot {

    private final PermissionDict permissionDict;
    private final PermLibrary    permLibrary;

    public ParameterPermSlot(PermissionDict permissionDict, PermLibrary permLibrary) {
        this.permissionDict = permissionDict;
        this.permLibrary    = permLibrary;
    }

    @Override
    public void chain(HttpMeta httpMeta, HandlerMethod handler, Error error) {
        if (!httpMeta.isRequireProtect()) return;
        PermRolesMeta permRolesMeta = permissionDict.getRolePermission().get(httpMeta.getMethod()).get(httpMeta.getApi());
        if (permRolesMeta.getParamPermissionsMetadata() == null) return;
        Set<String> roles       = null;
        Set<String> permissions = null;

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

                Map<String, String> pathVariables = (Map<String, String>) httpMeta.getRequest().getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
                value = pathVariables.get(paramName);
            } else if (requestParam != null) {
                type = ParamMetadata.ParamType.REQUEST_PARAM;
                if (!requestParam.name().equals("")) paramName = requestParam.name();
                value = httpMeta.getRequest().getParameter(paramName);
            }

            // 类型匹配上
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
                        error.error(ExceptionStatus.REQUIRE_LOGIN);
                        return;
                    }

                    roles = Optional.ofNullable(httpMeta.getRoles()).orElse(permLibrary.getRolesByUserId(httpMeta.getToken().getUserId()));
                    httpMeta.setRoles(roles);

                    List<PermRolesMeta.Meta> resourcesMeta  = rolesMetaList.stream().filter(meta -> meta.getResources() != null).collect(Collectors.toList());
                    List<PermRolesMeta.Meta> rangeMeta      = rolesMetaList.stream().filter(meta -> meta.getRange() != null).collect(Collectors.toList());
                    boolean                  next_resources = true; // 默认让过，但是如果值匹配上但没有对应role，则不让通过
                    boolean                  next_range     = true; // 默认让过。但是如果某个用户有对应的role。则看这些角色里面是否能拿出一个让过。如果都不让过。则不通过。反之通过
                    label_resources:
                    for (PermRolesMeta.Meta meta : resourcesMeta) {
                        if (ValueMatcher.match(meta.getResources(), value, paramType)) { // 值是否匹配，若匹配上
                            if (!CollectionUtils.containsSub(meta.getRequire(), roles)) { // 判断是否权限匹配
                                // 但是如果值匹配上但没有对应role，则不让通过
                                next_resources = false;
                                break label_resources;
                            }
                        }
                    }
                    boolean flag = false;
                    for (PermRolesMeta.Meta meta : rangeMeta) {
                        if (CollectionUtils.containsSub(meta.getRequire(), roles)) { // 如果这个meta匹配上了。则判断value是否在内
                            next_range = false; // 如果有匹配上过role，那么就不能无损通过，则需要判断值是否在内
                            if (ValueMatcher.match(meta.getRange(), value, paramType)) {
                                flag = true; // 有一个匹配上就让过
                            }
                        }
                    }
                    if (!next_resources || !(next_range || !next_range && flag)) {
                        logs("Forbid : permissions exception by request parameter", httpMeta, permRolesMeta);
                        error.error(ExceptionStatus.PERM_EXCEPTION);
                        return;
                    }
                }

                List<PermRolesMeta.Meta> permissionsMetaList = paramMetadata.getPermissionsMetaList();
                permMetaCheck:
                if (permissionsMetaList != null && !permissionsMetaList.isEmpty()) {
                    if (httpMeta.getToken() == null) {
                        logs("Require Login", httpMeta, permRolesMeta);
                        error.error(ExceptionStatus.REQUIRE_LOGIN);
                        return;
                    }
                    if (roles == null) {
                        roles = Optional.ofNullable(httpMeta.getRoles()).orElse(permLibrary.getRolesByUserId(httpMeta.getToken().getUserId()));
                        httpMeta.setRoles(roles);
                    }

                    Set<String> perms = httpMeta.getPermissions();

                    if (perms != null) permissions = perms;
                    else {
                        permissions = new HashSet<>();
                        for (String role : roles) {
                            Set<String> permissionsByRole = permLibrary.getPermissionsByRole(role);
                            permissions.addAll(permissionsByRole);
                        }
                        httpMeta.setPermissions(permissions);
                    }

                    List<PermRolesMeta.Meta> resourcesMeta  = permissionsMetaList.stream().filter(meta -> meta.getResources() != null).collect(Collectors.toList());
                    List<PermRolesMeta.Meta> rangeMeta      = permissionsMetaList.stream().filter(meta -> meta.getRange() != null).collect(Collectors.toList());
                    boolean                  next_resources = true; // 默认让过，但是如果值匹配上但没有对应perm，则不让通过
                    boolean                  next_range     = true;  // 默认让过。但是如果某个用户有对应的perm。则看这些角色里面是否能拿出一个让过。如果都不让过。则不通过。反之通过
                    label_resources:
                    for (PermRolesMeta.Meta meta : resourcesMeta) {
                        if (!ValueMatcher.match(meta.getResources(), value, paramType)) { // 值是否匹配，若匹配上
                            if (CollectionUtils.containsSub(meta.getRequire(), permissions)) { // 判断是否权限匹配
                                // 但是如果值匹配上但没有对应perm，则不让通过
                                next_resources = false;
                                break label_resources;
                            }
                        }
                    }
                    boolean flag = false;
                    for (PermRolesMeta.Meta meta : rangeMeta) {
                        if (CollectionUtils.containsSub(meta.getRequire(), permissions)) { // 如果这个meta匹配上了。则判断value是否在内
                            next_range = false; // 如果有匹配上过role，那么就不能无损通过，则需要判断值是否在内
                            if (ValueMatcher.match(meta.getRange(), value, paramType)) {
                                flag = true; // 有一个匹配上就让过
                            }
                        }
                    }
                    if (!next_resources || !(next_range || !next_range && flag)) {
                        logs("Forbid : permissions exception by request parameter", httpMeta, permRolesMeta);
                        error.error(ExceptionStatus.PERM_EXCEPTION);
                        return;
                    }
                }
            }
        }
    }


}
