package cn.omisheep.authz.support.util;

import lombok.Data;

import java.util.HashSet;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Data
public class IPRangeMeta {
    private HashSet<IPRange> allow;
    private HashSet<IPRange> deny;

    public IPRangeMeta setAllow(HashSet<IPRange> allow) {
        this.allow = allow;
        return this;
    }

    public IPRangeMeta setDeny(HashSet<IPRange> deny) {
        this.deny = deny;
        return this;
    }

    public IPRangeMeta setAllow(String allow) {
        this.allow = parse(allow);
        return this;
    }

    public IPRangeMeta setDeny(String deny) {
        this.deny = parse(deny);
        return this;
    }

    public static HashSet<IPRange> parse(String info) {
        if (info != null && info.trim().length() != 0) {
            HashSet<IPRange> ipRanges = new HashSet<>();
            info = info.trim();
            String[] items = info.split(",");

            for (String item : items) {
                if (item == null || item.length() == 0) {
                    continue;
                }

                IPRange ipRange = new IPRange(item);
                ipRanges.add(ipRange);
            }
            return ipRanges;
        }
        return new HashSet<>();
    }


}
