package cn.omisheep.authz.core.util;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.google.common.collect.ImmutableMap;
import lombok.SneakyThrows;
import org.apache.commons.lang.ObjectUtils;
import org.springframework.lang.NonNull;

import java.util.Collection;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static cn.omisheep.authz.core.config.Constants.WILDCARD;
import static cn.omisheep.authz.core.util.ValueMatcher.ValueType.EQUALS;
import static cn.omisheep.authz.core.util.ValueMatcher.ValueType.RANGE;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class ValueMatcher {

    private ValueMatcher() {
        throw new UnsupportedOperationException();
    }

    public enum ValueType {
        RANGE, // Comparable
        EQUALS, // equals
        OTHER;

        @JsonValue
        public String getValue() {
            return name().toLowerCase(Locale.ROOT);
        }

        @JsonCreator
        public ValueType create(String name) {
            return valueOf(name.toUpperCase(Locale.ROOT));
        }

        public boolean isOther() {
            return this == OTHER;
        }

        public boolean notOther() {
            return this != OTHER;
        }
    }

    private static final Map<Object, Object> typesMapper;
    private static final Map<Object, Object> valueTypesMapper;

    static {
        typesMapper = ImmutableMap.builder()
                .put(String.class.getTypeName(), String.class)
                .put(Integer.class.getTypeName(), Integer.class)
                .put(int.class.getTypeName(), Integer.class)
                .put(Long.class.getTypeName(), Long.class)
                .put(long.class.getTypeName(), Long.class)
                .put(Short.class.getTypeName(), Short.class)
                .put(short.class.getTypeName(), Short.class)
                .put(Double.class.getTypeName(), Double.class)
                .put(double.class.getTypeName(), Double.class)
                .put(Float.class.getTypeName(), Float.class)
                .put(float.class.getTypeName(), Float.class)
                .put(Character.class.getTypeName(), Character.class)
                .put(char.class.getTypeName(), Character.class)
                .put(Boolean.class.getTypeName(), Boolean.class)
                .put(boolean.class.getTypeName(), Boolean.class)
                .build();

        valueTypesMapper = ImmutableMap.builder()
                .put(String.class, EQUALS)
                .put(Character.class, EQUALS)
                .put(char.class, EQUALS)
                .put(Boolean.class, EQUALS)
                .put(boolean.class, EQUALS)
                .put(Integer.class, RANGE)
                .put(int.class, RANGE)
                .put(Long.class, RANGE)
                .put(long.class, RANGE)
                .put(Short.class, RANGE)
                .put(short.class, RANGE)
                .put(Double.class, RANGE)
                .put(double.class, RANGE)
                .put(Float.class, RANGE)
                .put(float.class, RANGE)
                .build();
    }

    public static boolean match(Set<String> resources,
                                String rawValue,
                                String valueTypeName,
                                ValueType valueType) {
        return resources.stream().anyMatch(resource -> match(resource, rawValue, valueTypeName, valueType));
    }

    @SuppressWarnings({"all"})
    private static boolean matchArg(Object obj,
                                    Object rawValue,
                                    String valueTypeName) {
        if (obj instanceof Collection) {
            return ((Collection) obj).stream().anyMatch(o -> ObjectUtils.equals(o, parse(rawValue.toString(),
                                                                                         valueTypeName)));
        } else {
            return ObjectUtils.equals(obj, parse(rawValue.toString(), valueTypeName));
        }
    }

    @SuppressWarnings("all")
    public static boolean match(String resources,
                                String rawValue,
                                String valueTypeName,
                                ValueType valueType) {
        if (resources == null) return false;
        if (resources.equals(WILDCARD)) return true;
        try {

            if (valueType.equals(EQUALS)) {
                return matchArg(ArgsParser.parse(resources), rawValue, valueTypeName);
            } else if (valueType.equals(ValueType.RANGE)) {
                String[] split = resources.split("-");
                if (split.length > 2) {
                    return false;
                } else if (split.length == 2) {
                    Object value = parse(rawValue, valueTypeName);
                    Object v1    = ArgsParser.parse(split[0], () -> parse(split[0], valueTypeName));
                    Object v2    = ArgsParser.parse(split[1], () -> parse(split[1], valueTypeName));
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
                    return matchArg(ArgsParser.parse(split[0]), parse(rawValue, valueTypeName), valueTypeName);
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    @SneakyThrows
    private static Object parse(String value,
                                String valueTypeName) {
        Class<?> clz = (Class<?>) typesMapper.get(valueTypeName);
        if (clz != null) {
            return clz.getConstructor(String.class).newInstance(value);
        } else {
            return null;
        }
    }

    public static Class<?> getType(String type) {
        Class<?> clz = (Class<?>) typesMapper.get(type);
        if (clz != null) return clz;
        try {
            return Class.forName(type);
        } catch (ClassNotFoundException e) {
            return null;
        }
    }

    public static ValueType checkTypeByName(String valueTypeName) {
        try {
            Object o = typesMapper.get(valueTypeName);
            if (o == null) {return ValueType.OTHER;} else {
                ValueType type = (ValueType) valueTypesMapper.get(o);
                if (type == null) return ValueType.OTHER;
                return type;
            }
        } catch (Exception e) {
            LogUtils.error(e);
            return ValueType.OTHER;
        }
    }

    public static ValueType checkType(@NonNull Object obj) {
        return checkTypeByClass(obj.getClass());
    }

    public static ValueType checkTypeByClass(Class<?> type) {
        ValueType valueType = (ValueType) valueTypesMapper.get(type);
        if (valueType == null) return ValueType.OTHER;
        return valueType;
    }
}
