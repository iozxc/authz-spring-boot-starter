package cn.omisheep.authz.core.schema;

import com.fasterxml.classmate.TypeResolver;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class ModelParser {
    private static final TypeResolver typeResolver = new TypeResolver();

    public static String simpleQualifiedTypeName(Class<?> type) {
        return ResolvedTypes.simpleQualifiedTypeName(typeResolver.resolve(type));
    }

    public static String simpleTypeName(Class<?> type) {
        return ResolvedTypes.simpleTypeName(typeResolver.resolve(type));
    }

}
