package cn.omisheep.authz.core.auth.ipf;

import cn.omisheep.authz.annotation.RateLimit;
import cn.omisheep.authz.core.config.Constants;
import cn.omisheep.commons.util.TimeUtils;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.google.common.base.Objects;
import lombok.Data;
import lombok.Getter;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class LimitMeta {
    @Getter
    private final long                    window;
    @Getter
    private final int                     maxRequests;
    @Getter
    private final long                    minInterval;
    @Getter
    private final RateLimit.CheckType     checkType;
    private final List<AssociatedPattern> associatedPatterns;
    private final List<Long>              punishmentTime = new ArrayList<>();

    public LimitMeta(String window,
                     int maxRequests,
                     String[] punishmentTime,
                     String minInterval,
                     String[] associatedPatterns,
                     RateLimit.CheckType checkType) {
        this.window      = TimeUtils.parseTimeValue(window);
        this.maxRequests = maxRequests;
        this.checkType   = checkType;
        Arrays.stream(punishmentTime).forEach(val -> this.punishmentTime.add(TimeUtils.parseTimeValue(val)));
        Collections.sort(this.punishmentTime);
        this.minInterval = TimeUtils.parseTimeValue(minInterval);
        if (associatedPatterns.length > 0) {
            ArrayList<AssociatedPattern> ap = new ArrayList<>();
            for (String info : associatedPatterns) {
                AssociatedPattern associatedPattern = AssociatedPattern.of(info);
                if (associatedPattern == null) continue;
                int i = ap.indexOf(associatedPattern);
                if (i == -1) {ap.add(associatedPattern);} else {
                    AssociatedPattern existedAssociatedPattern = ap.get(i);
                    existedAssociatedPattern.mergeMethods(associatedPattern);
                }
            }
            if (!ap.isEmpty()) {
                this.associatedPatterns = ap;
            } else {
                this.associatedPatterns = null;
            }
        } else {this.associatedPatterns = null;}
    }

    public List<AssociatedPattern> _getAssociatedPatterns() {
        if (associatedPatterns == null) return null;
        return Collections.unmodifiableList(associatedPatterns);
    }

    public Set<String> getAssociatedPatterns() {
        if (associatedPatterns == null) return null;
        return associatedPatterns.stream()
                .flatMap(a -> a.methods.stream().map(m -> m + " " + a.pattern))
                .collect(Collectors.toSet());
    }

    public List<Long> getPunishmentTime() {
        return Collections.unmodifiableList(punishmentTime);
    }

    @Getter
    @Data
    public static class AssociatedPattern {
        private final Set<String> methods;
        private final String      pattern;

        public static AssociatedPattern of(String info) {
            String      pattern;
            Set<String> methods;
            String[]    split = info.split(Constants.BLANK);
            if (split.length > 1) {
                pattern = split[split.length - 1];
                if (!pattern.endsWith("*")) {
                    ConcurrentHashMap<String, Httpd.RequestPool> map = Httpd.getIpRequestPools().get(pattern);
                    if (map == null) return null;
                    methods = new HashSet<>(map.keySet());
                } else {
                    methods = getMethods(pattern);
                }
                if (methods == null || methods.isEmpty()) return null;
            } else {
                pattern = split[0];
                methods = getMethods(pattern);
                if (methods == null) return null;
            }
            return new AssociatedPattern(methods, pattern);
        }

        private static Set<String> getMethods(String pattern) {
            String _p = pattern.substring(0, pattern.lastIndexOf("*"));

            Map<String, ConcurrentHashMap<String, Httpd.RequestPool>> map = Httpd.getIpRequestPools();
            Set<String> collect = Httpd.getIpRequestPools().keySet()
                    .stream()
                    .filter(v -> v.startsWith(_p))
                    .flatMap(v -> map.get(v).keySet().stream())
                    .collect(Collectors.toSet());
            if (collect.isEmpty()) return null;
            return new HashSet<>(collect);
        }

        public static String[] mtsFn(String mts) {
            if (mts.equals("*")) {return Constants.METHODS;} else return new String[]{mts};
        }

        public void mergeMethods(AssociatedPattern other) {
            this.methods.addAll(other.methods);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            AssociatedPattern that = (AssociatedPattern) o;
            return Objects.equal(pattern, that.pattern);
        }

        @Override
        public int hashCode() {
            return Objects.hashCode(pattern);
        }
    }
}