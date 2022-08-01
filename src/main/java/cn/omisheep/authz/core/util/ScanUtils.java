package cn.omisheep.authz.core.util;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.type.filter.AssignableTypeFilter;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class ScanUtils {
    public static String[] scan(Class<?> clz,
                                String... packages) {
        ClassPathScanningCandidateComponentProvider scanner = new ClassPathScanningCandidateComponentProvider(false);
        scanner.addIncludeFilter(new AssignableTypeFilter(clz));
        Set<String> classes = new HashSet<>();
        Arrays.stream(packages)
                .forEach(basePackage -> scanner.findCandidateComponents(basePackage)
                        .stream()
                        .map(BeanDefinition::getBeanClassName)
                        .forEach(classes::add));
        return classes.toArray(new String[0]);
    }
}
