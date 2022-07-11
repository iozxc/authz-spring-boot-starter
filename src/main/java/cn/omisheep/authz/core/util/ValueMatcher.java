package cn.omisheep.authz.core.util;

import org.apache.commons.lang.ObjectUtils;
import org.springframework.lang.NonNull;

import java.util.Collection;
import java.util.Set;

import static cn.omisheep.authz.core.Constants.WILDCARD;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public abstract class ValueMatcher {

    public enum ValueType {
        RANGE, // int long double float short chart
        EQUALS, // boolean,  String
        OTHER;

        public boolean isOther() {
            return this == OTHER;
        }

        public boolean notOther() {
            return this != OTHER;
        }
    }

    public static boolean match(Set<String> resources, String rawValue, Class<?> valueType) {
        return resources.stream().anyMatch(resource -> match(resource, rawValue, valueType));
    }

    @SuppressWarnings({"all"})
    private static boolean matchArg(Object obj, Object rawValue, Class<?> valueType) {
        if (obj instanceof Collection) {
            return ((Collection) obj).stream().anyMatch(o->
                ObjectUtils.equals(o, parse(rawValue.toString(), valueType)));
        } else {
            return ObjectUtils.equals(obj, parse(rawValue.toString(), valueType));
        }
    }

    @SuppressWarnings({"all"})
    public static boolean match(String resources, String rawValue, Class<?> valueType) {
        if (resources == null) return false;
        if (resources.equals(WILDCARD)) return true;
        try {

            ValueType type = checkType(valueType);
            if (type.equals(ValueType.EQUALS)) {
                return matchArg(ArgsParser.parse(resources), rawValue, valueType);
            } else if (type.equals(ValueType.RANGE)) {
                String[] split = resources.split("-");
                if (split.length > 2) {
                    return false;
                } else if (split.length == 2) {
                    Object value = parse(rawValue, valueType);
                    Object v1    = ArgsParser.parse(split[0], () -> parse((String) split[0], valueType));
                    Object v2    = ArgsParser.parse(split[1], () -> parse((String) split[1], valueType));
                    if (v1 == null || v2 == null || v1 instanceof Collection
                            || v2 instanceof Collection
                            || checkType(v1) != ValueType.RANGE
                            || checkType(v2) != ValueType.RANGE) {
                        return false;
                    }
                    Comparable left  = (Comparable) v1;
                    Comparable right = (Comparable) v2;
                    if (left.compareTo(value) <= 0 && right.compareTo(value) >= 0) {
                        return true;
                    }
                } else if (split.length == 1) {
                    return matchArg(ArgsParser.parse(split[0]), parse(rawValue, valueType), valueType);
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private static Object parse(String value, Class<?> type) {
        if (type.equals(String.class)) return value;
        if (type.equals(Integer.class) || type.equals(int.class)) {
            return new Integer(value);
        } else if (type.equals(Long.class) || type.equals(long.class)) {
            return new Long(value);
        } else if (type.equals(Short.class) || type.equals(short.class)) {
            return new Short(value);
        } else if (type.equals(Double.class) || type.equals(double.class)) {
            return new Double(value);
        } else if (type.equals(Float.class) || type.equals(float.class)) {
            return new Float(value);
        } else if (type.equals(Character.class) || type.equals(char.class)) {
            return value.charAt(0);
        } else if (type.equals(Boolean.class) || type.equals(boolean.class)) {
            return Boolean.valueOf(value);
        }
        return null;
    }

    public static Class<?> getType(String type) {
        if (type.equals(String.class.getTypeName())) return String.class;
        if (type.equals(Integer.class.getTypeName()) || type.equals(int.class.getTypeName())) {
            return Integer.class;
        } else if (type.equals(Long.class.getTypeName()) || type.equals(long.class.getTypeName())) {
            return Long.class;
        } else if (type.equals(Short.class.getTypeName()) || type.equals(short.class.getTypeName())) {
            return Short.class;
        } else if (type.equals(Double.class.getTypeName()) || type.equals(double.class.getTypeName())) {
            return Double.class;
        } else if (type.equals(Float.class.getTypeName()) || type.equals(float.class.getTypeName())) {
            return Float.class;
        } else if (type.equals(Character.class.getTypeName()) || type.equals(char.class.getTypeName())) {
            return Character.class;
        } else if (type.equals(Boolean.class.getTypeName()) || type.equals(boolean.class.getTypeName())) {
            return Boolean.class;
        }
        try {
            return Class.forName(type);
        } catch (ClassNotFoundException e) {
            return null;
        }
    }

    public static ValueType checkType(String type) {
        try {
            return checkType(Class.forName(type));
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
            return ValueType.OTHER;
        }
    }

    public static ValueType checkType(@NonNull Object obj) {
        return checkType(obj.getClass());
    }

    public static ValueType checkType(Class<?> type) {
        if (type.equals(String.class) || type.equals(Boolean.class) || type.equals(boolean.class))
            return ValueType.EQUALS;

        if (type.equals(Integer.class) || type.equals(int.class)
                || type.equals(Long.class) || type.equals(long.class)
                || type.equals(Short.class) || type.equals(short.class)
                || type.equals(Double.class) || type.equals(double.class)
                || type.equals(Float.class) || type.equals(float.class)
                || type.equals(Character.class) || type.equals(char.class))
            return ValueType.RANGE;

        return ValueType.OTHER;
    }
}
