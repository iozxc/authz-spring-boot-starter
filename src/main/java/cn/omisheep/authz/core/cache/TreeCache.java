package cn.omisheep.authz.core.cache;

import cn.omisheep.commons.util.Utils;
import lombok.Data;

import java.util.*;
import java.util.stream.Collectors;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 2022-01-30
 */
@SuppressWarnings("rawtypes")
public abstract class TreeCache implements Cache {

    private final Node root = new Node();
    private static final Set<String> PRESENT = Collections.unmodifiableSet(new HashSet<>());

    @Data
    private static class Node {
        private String path;
        private HashMap<String, Node> child;

        public Node(String path) {
            this.path = path;
        }

        public Node() {
        }
    }

    protected Set<String> treeKeys(String pattern) {
        return listKeysMatched(pattern);
    }

    private Set<String> listKeysMatched(int level, String[] patterns, Node node) {
        if (level >= patterns.length) return PRESENT;
        String curPattern = patterns[level];
        if (node != null && node.child != null && node.child.size() > 0) {
            Set<String> curMatchKeys =
                    curPattern.equals(ALL)
                            ? node.child.keySet()
                            : node.child.keySet().stream().filter(k -> Utils.stringMatch(curPattern, k, true)).collect(Collectors.toSet());
            if (curMatchKeys.size() == 0) return PRESENT;
            Set<String> s = new HashSet<>();
            if (level != patterns.length - 1) {
                curMatchKeys.forEach(curMatchKey -> s.addAll(listKeysMatched(level + 1, patterns, node.child.get(curMatchKey))));
            } else {
                curMatchKeys.forEach(curMatchKey -> {
                    String path = node.child.get(curMatchKey).path;
                    if (path != null) s.add(path);
                });
            }
            return s;
        }
        return PRESENT;
    }

    private Set<String> listKeysMatched(String pattern) {
        String[] p = pattern.split(SEPARATOR);
        Set<String> listKeysMatched = listKeysMatched(0, p, root);
        return listKeysMatched.equals(PRESENT) ? new HashSet<>() : listKeysMatched;
    }

    protected void putKey(String key) {
        String[] fields = key.split(SEPARATOR);
        Node node = root;
        Iterator<String> iterator = Arrays.stream(fields).iterator();

        while (iterator.hasNext()) {
            String field = iterator.next();
            if (node.child == null) {
                node.child = new HashMap<>();
            }
            if (!iterator.hasNext()) {
                if (!node.child.containsKey(field))
                    node.child.put(field, new Node(key));
                else node.child.get(field).path = key;
            }
            if (iterator.hasNext()) {
                node = node.child.computeIfAbsent(field, k -> new Node());
            }
        }
    }

    protected void removeKey(String key) {
        String[] fields = key.split(SEPARATOR);
        Node node = root;
        Iterator<String> iterator = Arrays.stream(fields).iterator();
        while (iterator.hasNext()) {
            String field = iterator.next();
            if (node == null) return;
            if (!iterator.hasNext()) {
                if (node.child == null) return;
                Node cNode = node.child.get(field);
                if (cNode.path != null) cNode.path = null;
                if (cNode.child == null) node.child.remove(field);
                if (node.child.isEmpty()) node.child = null;
            }
            if (node.child != null && node.child.containsKey(field)) {
                node = node.child.get(field);
            }
        }
    }
}
