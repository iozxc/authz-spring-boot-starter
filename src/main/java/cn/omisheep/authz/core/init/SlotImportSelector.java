package cn.omisheep.authz.core.init;

import cn.omisheep.authz.core.slot.Slot;
import cn.omisheep.authz.core.slot.SlotScan;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.core.type.filter.AssignableTypeFilter;
import org.springframework.lang.NonNull;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public class SlotImportSelector implements ImportSelector {

    @NonNull
    @Override
    public String[] selectImports(AnnotationMetadata importingClassMetadata) {
        Map<String, Object> annotationAttributes = importingClassMetadata.getAnnotationAttributes(SlotScan.class.getName());
        String[] basePackages = new String[0];
        if (annotationAttributes != null) basePackages = (String[]) annotationAttributes.get("basePackages");
        ClassPathScanningCandidateComponentProvider scanner = new ClassPathScanningCandidateComponentProvider(false);
        scanner.addIncludeFilter(new AssignableTypeFilter(Slot.class));
        Set<String> classes = new HashSet<>();
        Arrays.stream(basePackages).forEach(basePackage -> scanner.findCandidateComponents(basePackage).stream().map(BeanDefinition::getBeanClassName).forEach(classes::add));
        return classes.toArray(new String[0]);
    }

}