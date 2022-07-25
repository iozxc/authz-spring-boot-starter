package cn.omisheep.authz.support.http;

import cn.omisheep.authz.core.util.ScanUtils;
import cn.omisheep.authz.support.http.annotation.ApiSupportScan;
import cn.omisheep.authz.support.http.annotation.Mapping;
import cn.omisheep.authz.support.http.handler.ApiHandler;
import cn.omisheep.commons.util.ClassUtils;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.lang.NonNull;

import java.util.Arrays;
import java.util.Map;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class ApiSupportImport implements ImportSelector {

    @NonNull
    @Override
    public String[] selectImports(@NonNull AnnotationMetadata annotationMetadata) {
        Map<String, Object> annotationAttributes = annotationMetadata.getAnnotationAttributes(ApiSupportScan.class.getName());
        String[]            packages             = new String[0];
        if (annotationAttributes != null) packages = (String[]) annotationAttributes.get("packages");
        String[] v = ScanUtils.scan(ApiSupport.class, packages);
        Arrays.stream(packages)
                .forEach(pkg -> ClassUtils.getClassSet(pkg)
                        .forEach(type -> Arrays.stream(type.getMethods())
                                .forEach(method -> {
                                    Mapping tMapping = AnnotatedElementUtils.getMergedAnnotation(type, Mapping.class);
                                    Mapping mMapping = AnnotatedElementUtils.getMergedAnnotation(method, Mapping.class);
                                    String  path     = "";
                                    boolean rel      = false;
                                    if (tMapping != null) {
                                        path = tMapping.path();
                                        rel  = tMapping.requireLogin();
                                    }
                                    if (mMapping == null) return;
                                    path += mMapping.path();
                                    rel = rel || mMapping.requireLogin();
                                    ApiHandler.getApi().put(path, new ApiHandler.ApiInfo().setRequireLogin(rel).setDesc(mMapping.desc()).setInvoke(method).setMethod(mMapping.type()));
                                })
                        )
                );
        return v;
    }
}
