package cn.omisheep.authz.core.auth.deviced;

import com.google.common.base.Objects;

import java.util.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class AuthzMap implements Map<Object, Object> {
    private final Map<Object, Object> map;

    public AuthzMap() {
        this(new LinkedHashMap<>());
    }

    public AuthzMap(Map<Object, Object> map) {
        this.map = map;
    }

    protected String getString(String name) {
        Object v = get(name);
        return v != null ? String.valueOf(v) : null;
    }

    protected void setValue(String name, String v) {
        if (v == null) {
            map.remove(name);
        } else {
            map.put(name, v);
        }
    }

    protected Date getDate(String name) {
        try {
            long millis = Long.parseLong((String) map.get(name));
            return new Date(millis);
        } catch (Exception e) {
            return null;
        }
    }

    protected Long getLong(String name) {
        try {
            return Long.parseLong((String) map.get(name));
        } catch (Exception e) {
            return null;
        }
    }

    protected void setDate(String name, Date d) {
        if (d == null) {
            map.remove(name);
        } else {
            map.put(name, d.getTime() + "");
        }
    }

    @Override
    public int size() {
        return map.size();
    }

    @Override
    public boolean isEmpty() {
        return map.isEmpty();
    }

    @Override
    public boolean containsKey(Object o) {
        return map.containsKey(o);
    }

    @Override
    public boolean containsValue(Object o) {
        return map.containsValue(o);
    }

    @Override
    public Object get(Object o) {
        return map.get(o);
    }

    @Override
    public Object put(Object s, Object o) {
        if (o == null) {
            return map.remove(s);
        } else {
            return map.put(s, o);
        }
    }

    @Override
    public Object remove(Object o) {
        return map.remove(o);
    }

    @SuppressWarnings("NullableProblems")
    @Override
    public void putAll(Map<?, ?> m) {
        if (m == null) {
            return;
        }
        for (Object s : m.keySet()) {
            map.put(s, m.get(s));
        }
    }

    @Override
    public void clear() {
        map.clear();
    }

    @Override
    public Set<Object> keySet() {
        return map.keySet();
    }

    @Override
    public Collection<Object> values() {
        return map.values();
    }

    @Override
    public Set<Entry<Object, Object>> entrySet() {
        return map.entrySet();
    }

    @Override
    public String toString() {
        return map.toString();
    }

    @Override
    public int hashCode() {
        return map.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AuthzMap)) return false;
        AuthzMap auMap = (AuthzMap) o;
        return Objects.equal(map, auMap.map);
    }
}
