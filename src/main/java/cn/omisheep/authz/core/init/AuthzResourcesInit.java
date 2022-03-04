package cn.omisheep.authz.core.init;

import cn.omisheep.authz.annotation.*;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.rpd.DataPermMeta;
import cn.omisheep.authz.core.auth.rpd.PermissionDict;
import cn.omisheep.commons.util.ClassUtils;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.core.type.filter.AssignableTypeFilter;
import org.springframework.lang.NonNull;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public class AuthzResourcesInit implements ImportSelector {

    private DataPermMeta generateDataPermMeta(Perms perms) {
        DataPermMeta dataPermMeta = DataPermMeta.of(perms.condition());
        Arg[] conditionArgs = perms.conditionArgs();
        for (Arg arg : conditionArgs) {
            String resource = arg.resource();
            String[] resourceArgs = arg.args();
            dataPermMeta.addArg(resource, resourceArgs);
        }
        dataPermMeta.setPermissions(AuCoreInitialization.generatePermMeta(perms, false).setResources(null));
        return dataPermMeta;
    }

    private DataPermMeta generateDataRolesMeta(Roles roles) {
        DataPermMeta dataPermMeta = DataPermMeta.of(roles.condition());
        Arg[] conditionArgs = roles.conditionArgs();
        for (Arg arg : conditionArgs) {
            String resource = arg.resource();
            String[] resourceArgs = arg.args();
            dataPermMeta.addArg(resource, resourceArgs);
        }
        dataPermMeta.setRoles(AuCoreInitialization.generateRolesMeta(roles, false).setResources(null));
        return dataPermMeta;
    }

    private Object[] dataPerm(String className) {
        try {
            Class<?> aClass = Class.forName(className);
            List<Roles> rolesList = new ArrayList<>();
            List<Perms> permsList = new ArrayList<>();
            Roles roles = AnnotationUtils.getAnnotation(aClass, Roles.class);
            Perms perms = AnnotationUtils.getAnnotation(aClass, Perms.class);
            BatchAuthority batchAuthority = AnnotationUtils.getAnnotation(aClass, BatchAuthority.class);
            rolesList.add(roles);
            permsList.add(perms);
            if (batchAuthority != null) {
                rolesList.addAll(Arrays.asList(batchAuthority.roles()));
                permsList.addAll(Arrays.asList(batchAuthority.perms()));
            }

            List<DataPermMeta> dataPermMetaList = Stream.concat(
                    rolesList.stream().filter(Objects::nonNull).map(this::generateDataRolesMeta),
                    permsList.stream().filter(Objects::nonNull).map(this::generateDataPermMeta)
            ).collect(Collectors.toList());
            return new Object[]{className, dataPermMetaList};
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }


    @NonNull
    @Override
    @SuppressWarnings("all")
    public String[] selectImports(AnnotationMetadata annotationMetadata) {
        Map<String, Object> annotationAttributes = annotationMetadata.getAnnotationAttributes(AuthzResourcesScan.class.getName());
        String[] entityBasePackages = new String[0];
        if (annotationAttributes != null) entityBasePackages = (String[]) annotationAttributes.get("entity");
        ClassPathScanningCandidateComponentProvider scannerEntity = new ClassPathScanningCandidateComponentProvider(false);
        scannerEntity.addIncludeFilter(new AssignableTypeFilter(Object.class));
        Set<String> entityClasses = new HashSet<>();
        Arrays.stream(entityBasePackages).forEach(basePackage -> scannerEntity.findCandidateComponents(basePackage).stream().map(BeanDefinition::getBeanClassName).forEach(entityClasses::add));
        PermissionDict.addAuthzResourcesNames(entityClasses);

        HashMap<String, List<DataPermMeta>> map = new HashMap<>();
        entityClasses.stream().map(this::dataPerm)
                .filter(Objects::nonNull)
                .forEach(o -> map.put((String) o[0], (List<DataPermMeta>) o[1]));
        PermissionDict.initDataPerm(map);

        String[] argsBasePackages = new String[0];
        if (annotationAttributes != null) argsBasePackages = (String[]) annotationAttributes.get("args");
        HashMap<String, PermissionDict.ArgsMeta> argMap = new HashMap<>();
        Arrays.stream(argsBasePackages).forEach(basePackage ->
                ClassUtils.getClassSet(basePackage).forEach(type ->
                        Arrays.stream(type.getMethods())
                                .filter(method -> method.isAnnotationPresent(ArgResource.class))
                                .forEach(method -> {
                                    String name = AnnotationUtils.getAnnotation(method, ArgResource.class).name();
                                    if (Objects.equals(name, "")) name = method.getName();
                                    argMap.put(name, PermissionDict.ArgsMeta.of(type, method));
                                })
                )
        );
        argMap.put("token", PermissionDict.ArgsMeta.of(HttpMeta.class, "currentToken"));
        argMap.put("userId", PermissionDict.ArgsMeta.of(HttpMeta.class, "currentUserId"));
        PermissionDict.initArgs(argMap);


        return new String[0];
    }

}
