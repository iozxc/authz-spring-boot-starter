package cn.omisheep.authz.core.auth.ipf;

import cn.omisheep.authz.annotation.RateLimit;
import cn.omisheep.authz.core.config.Constants;
import cn.omisheep.commons.util.CollectionUtils;
import cn.omisheep.commons.util.TimeUtils;
import com.google.common.base.Objects;
import lombok.Getter;

import java.util.*;
import java.util.stream.Collectors;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */

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
            this.associatedPatterns = new ArrayList<>();
            for (String info : associatedPatterns) {
                AssociatedPattern associatedPattern = new AssociatedPattern(info);
                int               i                 = this.associatedPatterns.indexOf(associatedPattern);
                if (i == -1) this.associatedPatterns.add(associatedPattern);
                else {
                    AssociatedPattern existedAssociatedPattern = this.associatedPatterns.get(i);
                    existedAssociatedPattern.mergeMethods(associatedPattern);
                }
            }
        } else this.associatedPatterns = null;
    }

    public List<AssociatedPattern> getAssociatedPatterns() {
        if (associatedPatterns == null) return null;
        return Collections.unmodifiableList(associatedPatterns);
    }

    public List<Long> getPunishmentTime() {
        return Collections.unmodifiableList(punishmentTime);
    }

    @Getter
    public static class AssociatedPattern {
        private final Set<String> methods;
        private final String      pattern;

        public AssociatedPattern(String info) {
            String[] split = info.split(Constants.BLANK);
            if (split.length > 1) {
                this.pattern = split[split.length - 1];
                this.methods = Arrays.stream(Arrays.copyOf(split, split.length - 1))
                        .map(String::toUpperCase)
                        .map(this::mtsFn)
                        .flatMap(Arrays::stream)
                        .collect(Collectors.toSet());
            } else {
                this.pattern = split[0];
                this.methods = CollectionUtils.ofSet("GET");
            }

        }

        public String[] mtsFn(String mts) {
            if (mts.equals("*")) return Constants.METHODS;
            else return new String[]{mts};
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