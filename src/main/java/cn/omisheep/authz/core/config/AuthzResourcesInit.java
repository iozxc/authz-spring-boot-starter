package cn.omisheep.authz.core.config;

import cn.omisheep.authz.annotation.*;
import cn.omisheep.authz.core.auth.rpd.ArgsMeta;
import cn.omisheep.authz.core.auth.rpd.DataPermRolesMeta;
import cn.omisheep.authz.core.auth.rpd.FieldDataPermRolesMeta;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.authz.core.util.MetaUtils;
import cn.omisheep.authz.core.util.ScanUtils;
import cn.omisheep.commons.util.ClassUtils;
import cn.omisheep.commons.util.CollectionUtils;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.lang.NonNull;

import java.lang.reflect.Field;
import java.util.*;
import java.util.stream.Collectors;

import static cn.omisheep.authz.core.util.MetaUtils.generateDataFiledRolesMeta;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class AuthzResourcesInit implements ImportSelector {

    private Object[] dataPerm(String className) {
        try {
            Class<?>       aClass        = Class.forName(className);
            List<AuthData> authDataList  = new ArrayList<>();
            AuthData       authData      = AnnotationUtils.getAnnotation(aClass, AuthData.class);
            BatchAuthData  batchAuthData = AnnotationUtils.getAnnotation(aClass, BatchAuthData.class);
            authDataList.add(authData);
            if (batchAuthData != null) {
                authDataList.addAll(Arrays.asList(batchAuthData.value()));
            }

            List<DataPermRolesMeta> dataPermRolesMetaList = authDataList.stream()
                    .filter(Objects::nonNull)
                    .map(MetaUtils::generateDataRolesMeta)
                    .collect(Collectors.toList());
            return new Object[]{className, dataPermRolesMetaList};
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }


    @NonNull
    @Override
    @SuppressWarnings("all")
    public String[] selectImports(AnnotationMetadata annotationMetadata) {
        Map<String, Object> annotationAttributes = annotationMetadata.getAnnotationAttributes(
                AuthzResourcesScan.class.getName());
        String[] entityBasePackages = new String[0];
        if (annotationAttributes != null) entityBasePackages = (String[]) annotationAttributes.get("entity");
        Set<String> entityClasses = CollectionUtils.newSet(ScanUtils.scan(Object.class, entityBasePackages));

        HashMap<String, List<DataPermRolesMeta>> map = new HashMap<>();
        entityClasses.stream()
                .map(this::dataPerm)
                .filter(Objects::nonNull)
                .forEach(o -> map.put((String) o[0], (List<DataPermRolesMeta>) o[1]));

        String[] argsBasePackages = new String[0];
        if (annotationAttributes != null) argsBasePackages = (String[]) annotationAttributes.get("args");
        HashMap<String, ArgsMeta> argMap = new HashMap<>();
        Arrays.stream(argsBasePackages)
                .forEach(basePackage -> ClassUtils.getClassSet(basePackage)
                        .forEach(type -> Arrays.stream(type.getMethods())
                                .filter(method -> method.isAnnotationPresent(ArgResource.class))
                                .forEach(method -> {
                                    ArgResource argResource = AnnotationUtils.getAnnotation(method, ArgResource.class);
                                    String      name        = argResource.name();
                                    if (Objects.equals(name, "")) name = method.getName();
                                    argMap.put(name,
                                               ArgsMeta.of(type, method).setDescription(argResource.description()));
                                })));
        PermissionDict.initArgs(entityClasses, ge(entityClasses), map, argMap);
        return new String[0];
    }


    private Map<String, Map<String, FieldDataPermRolesMeta>> ge(Set<String> entityClasses) {
        Map<String, Map<String, FieldDataPermRolesMeta>> map = new HashMap<>();
        for (String clz : entityClasses) {
            try {
                Class<?>                            aClass = Class.forName(clz);
                Map<String, FieldDataPermRolesMeta> fmap   = map.computeIfAbsent(clz, r -> new HashMap<>());

                for (Field field : aClass.getDeclaredFields()) {
                    AuthField authField = AnnotationUtils.getAnnotation(field, AuthField.class);
                    if (authField == null) continue;
                    FieldDataPermRolesMeta fieldDataPermRolesMeta = generateDataFiledRolesMeta(
                            field.getType().getTypeName(),
                            authField);
                    if (fieldDataPermRolesMeta == null) continue;
                    fmap.put(field.getName(), fieldDataPermRolesMeta);
                }

            } catch (Exception ignored) {
            }
        }
        return map;
    }
}
