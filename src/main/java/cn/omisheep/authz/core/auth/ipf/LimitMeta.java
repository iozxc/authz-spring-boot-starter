package cn.omisheep.authz.core.auth.ipf;

import cn.omisheep.authz.annotation.BannedType;
import cn.omisheep.commons.util.TimeUtils;
import lombok.Getter;

/**
 * @author zhou xin chen
 */

@Getter
public class LimitMeta {
    private final long window;
    private final int maxRequests;
    private final long punishmentTime;
    private final long minInterval;
    private final BannedType bannedType;

    public LimitMeta(String window, int maxRequests, String punishmentTime, String minInterval, BannedType bannedType) {
        this.window = TimeUtils.parseTimeValue(window);
        this.maxRequests = maxRequests;
        this.punishmentTime = TimeUtils.parseTimeValue(punishmentTime);
        this.minInterval = TimeUtils.parseTimeValue(minInterval);
        this.bannedType = bannedType;
    }
}