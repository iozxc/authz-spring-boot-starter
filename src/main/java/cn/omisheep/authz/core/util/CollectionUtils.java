package cn.omisheep.authz.core.util;

import java.util.*;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
public class CollectionUtils {

    /**
     * list == null || list.isEmpty()
     *
     * @param list 目标集合
     * @param <T>  此集合中元素的类型
     * @return 目标集合为null或者为空 则返回true
     */
    public static <T> boolean isEmpty(Collection<T> list) {
        return list == null || list.isEmpty();
    }

    /**
     * @param list 目标集合
     * @param <T>  此集合中元素的类型
     * @return 目标集合不为null且不为空 则返回true
     */
    public static <T> boolean isNotEmpty(Collection<T> list) {
        return !isEmpty(list);
    }

    public static Set<String> newSet(String... vals) {
        HashSet<String> strings = new HashSet<>();
        for (String val : vals) {
            strings.add(val.trim());
        }
        return strings;
    }

    public static String resolveSingletonSet(Set<String> set) {
        if (set == null || set.isEmpty()) {
            return null;
        }
        return set.iterator().next();
    }

    public static Set<String> singletonSet(String val) {
        return new HashSet<>(Collections.singletonList(val));
    }

    /**
     * @param separator 字符串分割符号

     * @return 一个经过去重的集合列表，该集合元素是去重集合
     */
    public static Set<Set<String>> splitStrValsToSets(String separator, String... value) {
        Set<Set<String>> ret = new HashSet<>();
        for (String val : newSet(value)) {
            ret.add(newSet(val.split(separator)));
        }
        return ret.size() > 0 ? ret : null;
    }

    public static <T> boolean containsSub(Set<Set<T>> sets, List<T> list) {
        if (list == null) return false;
        return containsSub(sets, new HashSet<>(list));
    }

    /**
     * 判断目标集合是否是源集合的子集或者源集合的任意一项的子集
     *
     * @param sets 源集合
     * @param set  目标集合
     * @param <T>  此集合中元素的类型
     * @return 目标集合是否是源集合的子集或者源集合的任意一项的子集
     */
    public static <T> boolean containsSub(Set<Set<T>> sets, Set<T> set) {
        if (set == null) return false;
        return Objects.requireNonNull(sets).stream().anyMatch(s -> {
                    for (T t : s) {
                        if (!set.contains(t)) {
                            return false;
                        }
                    }
                    return true;
                }
        );
    }

}
