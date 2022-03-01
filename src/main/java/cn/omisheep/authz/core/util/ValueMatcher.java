package cn.omisheep.authz.core.util;

import org.apache.commons.lang.ObjectUtils;

import java.util.Set;

import static cn.omisheep.authz.core.Constants.WILDCARD;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public class ValueMatcher {

    public enum ValueType {
        RANGE, // int long double float short chart
        EQUALS, // boolean,  String
        OTHER
    }

    public static boolean match(Set<String> resources, String rawValue, Class<?> valueType) {
        return resources.stream().anyMatch(resource -> match(resource, rawValue, valueType));
    }

    @SuppressWarnings({"all"})
    public static boolean match(String resources, String rawValue, Class<?> valueType) {
        if (resources == null) return false;
        if (resources.equals(WILDCARD)) return true;
        try {
            ValueType type = checkType(valueType);
            if (type.equals(ValueType.EQUALS)) {
                return ObjectUtils.equals(resources, parse(rawValue, valueType));
            } else if (type.equals(ValueType.RANGE)) {
                String[] split = resources.split("-");
                if (split.length > 2) {
                    return false;
                } else if (split.length == 2) {
                    Object value = parse(rawValue, valueType);
                    Comparable left = (Comparable) parse(split[0], valueType);
                    Comparable right = (Comparable) parse(split[1], valueType);
                    if (left.compareTo(value) <= 0 && right.compareTo(value) >= 0) {
                        return true;
                    }
                } else if (split.length == 1) {
                    return ObjectUtils.equals(parse(split[0], valueType), parse(rawValue, valueType));
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private static Object parse(String value, Class<?> type) {
        if (type.equals(String.class)) return value;
        if (type.equals(Integer.class) || type.equals(Integer.TYPE)) {
            return new Integer(value);
        } else if (type.equals(Long.class) || type.equals(Long.TYPE)) {
            return new Long(value);
        } else if (type.equals(Short.class) || type.equals(Short.TYPE)) {
            return new Short(value);
        } else if (type.equals(Double.class) || type.equals(Double.TYPE)) {
            return new Double(value);
        } else if (type.equals(Float.class) || type.equals(Float.TYPE)) {
            return new Float(value);
        } else if (type.equals(Character.class) || type.equals(Character.TYPE)) {
            return value.charAt(0);
        } else if (type.equals(Boolean.class) || type.equals(Boolean.TYPE)) {
            return Boolean.valueOf(value);
        } return null;
    }

    public static ValueType checkType(Class<?> type) {
        if (type.equals(String.class) || type.equals(Boolean.class) || type.equals(boolean.class))
            return ValueType.EQUALS;

        if (type.equals(Integer.class) || type.equals(Integer.TYPE)
                || type.equals(Long.class) || type.equals(Long.TYPE)
                || type.equals(Short.class) || type.equals(Short.TYPE)
                || type.equals(Double.class) || type.equals(Double.TYPE)
                || type.equals(Float.class) || type.equals(Float.TYPE)
                || type.equals(Character.class) || type.equals(Character.TYPE))
            return ValueType.RANGE;

        return ValueType.OTHER;
    }
}
