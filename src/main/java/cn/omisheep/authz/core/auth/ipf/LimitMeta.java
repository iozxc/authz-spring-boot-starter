package cn.omisheep.authz.core.auth.ipf;

import cn.omisheep.authz.annotation.BannedType;
import cn.omisheep.authz.core.Constants;
import cn.omisheep.commons.util.CollectionUtils;
import cn.omisheep.commons.util.TimeUtils;
import com.google.common.base.Objects;
import lombok.Getter;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */

public class LimitMeta {
    @Getter
    private final long window;
    @Getter
    private final int maxRequests;
    @Getter
    private final long punishmentTime;
    @Getter
    private final long minInterval;
    @Getter
    private final List<AssociatedPattern> associatedPatterns;
    @Getter
    private final BannedType bannedType;
    @Getter
    private final List<Httpd.IpPool> associatedIpPools = new ArrayList<>();

    public LimitMeta(String window,
                     int maxRequests,
                     String punishmentTime,
                     String minInterval,
                     String[] associatedPatterns,
                     BannedType bannedType) {
        this.window = TimeUtils.parseTimeValue(window);
        this.maxRequests = maxRequests;
        this.punishmentTime = TimeUtils.parseTimeValue(punishmentTime);
        this.minInterval = TimeUtils.parseTimeValue(minInterval);
        this.bannedType = bannedType;

        if (associatedPatterns.length > 0) {
            this.associatedPatterns = new ArrayList<>();
            for (String info : associatedPatterns) {
                AssociatedPattern associatedPattern = new AssociatedPattern(info);
                int i = this.associatedPatterns.indexOf(associatedPattern);
                if (i == -1) this.associatedPatterns.add(associatedPattern);
                else {
                    AssociatedPattern existedAssociatedPattern = this.associatedPatterns.get(i);
                    existedAssociatedPattern.mergeMethods(associatedPattern);
                }
            }
        } else this.associatedPatterns = null;
    }

    @Getter
    static class AssociatedPattern {
        private final Set<String> methods;
        private final String pattern;

        public AssociatedPattern(String info) {
            String[] split = info.split(Constants.BLANK);
            if (split.length > 1) {
                this.pattern = split[split.length - 1];
                split[split.length - 1] = null;
                this.methods = CollectionUtils.newSet(split);
            } else {
                this.pattern = split[0];
                this.methods = CollectionUtils.newSet("GET");
            }

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