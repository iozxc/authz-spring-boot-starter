package cn.omisheep.authz.core.auth.ipf;

import cn.omisheep.authz.annotation.BannedType;
import cn.omisheep.authz.core.util.TimeUtils;
import lombok.Getter;

/**
 * @author zhou xin chen
 */

@Getter
public class LimitMeta {
    private final long time;
    private final int maxCount;
    private final long relieveTime;
    private final long interval;
    private final BannedType bannedType;

    public LimitMeta(String time, int maxCount, String relieveTime, String interval, BannedType bannedType) {
        this.time = TimeUtils.parseTimeValue(time);
        this.maxCount = maxCount;
        this.relieveTime = TimeUtils.parseTimeValue(relieveTime);
        this.interval = TimeUtils.parseTimeValue(interval);
        this.bannedType = bannedType;
    }
}