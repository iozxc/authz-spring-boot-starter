package cn.omisheep.authz.core.auth.ipf;

import cn.omisheep.authz.core.AuthzManager;
import cn.omisheep.authz.core.msg.AuthzModifier;
import cn.omisheep.authz.core.tk.Token;
import cn.omisheep.authz.support.util.IPAddress;
import cn.omisheep.authz.support.util.IPRange;
import cn.omisheep.commons.util.TimeUtils;
import cn.omisheep.web.entity.Result;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import orestes.bloomfilter.CountingBloomFilter;
import orestes.bloomfilter.FilterBuilder;
import org.apache.commons.lang.StringUtils;
import org.springframework.lang.Nullable;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.1.0
 */
public class Blacklist {

    private static final List<IP>                    ipBlacklist            = new CopyOnWriteArrayList<>();
    private static final CountingBloomFilter<String> ipBlacklistBloomFilter = new FilterBuilder(1000, 0.001).countingBits(8).buildCountingBloomFilter();

    private static final List<User>                  userBlacklist            = new CopyOnWriteArrayList<>();
    private static final CountingBloomFilter<String> userBlacklistBloomFilter = new FilterBuilder(1000, 0.001).countingBits(8).buildCountingBloomFilter();

    private static final List<IPRangeDeny> ipRangeBlacklist = new CopyOnWriteArrayList<>();

    public static boolean check(String ip, Object userId, @Nullable String deviceType, @Nullable String deviceId) {
        return IP.check(ip) && IPRangeDeny.check(ip) && User.check(userId, deviceType, deviceId);
    }

    public static boolean check(String ip, @Nullable Token token) {
        if (token == null) return check(ip);
        return IP.check(ip) && IPRangeDeny.check(ip) && User.check(token.getUserId(), token.getDeviceType(), token.getDeviceId());
    }

    public static boolean check(String ip) {
        return IP.check(ip) && IPRangeDeny.check(ip);
    }

    @Data
    public static class User {
        final Object   userId;
        @Nullable
        @JsonInclude(JsonInclude.Include.NON_NULL)
        final String   deviceType;
        @Nullable
        @JsonInclude(JsonInclude.Include.NON_NULL)
        final String   deviceId;
        final TimeMeta timeMeta;

        public User(Object userId, @Nullable String deviceType, @Nullable String deviceId, TimeMeta timeMeta) {
            this.userId     = userId;
            this.deviceId   = deviceId;
            this.deviceType = deviceType;
            this.timeMeta   = timeMeta;
        }

        private static void _add(Object userId, @Nullable String deviceType, @Nullable String deviceId, String time, long now) {
            User user = new User(userId, deviceType, deviceId, TimeMeta.of(time, now));
            userBlacklist.add(user);
            userBlacklistBloomFilter.add(userId.toString());
        }

        public static void add(Object userId, @Nullable String deviceType, @Nullable String deviceId, String time) {
            long                        nowTime       = TimeUtils.nowTime();
            AuthzModifier.BlacklistInfo blacklistInfo = new AuthzModifier.BlacklistInfo().setType(AuthzModifier.BlacklistInfo.TYPE.USER).setOp(AuthzModifier.BlacklistInfo.OP.ADD).setUserId(userId).setDeviceType(deviceType).setDeviceId(deviceId).setTime(time).setStart(nowTime);
            AuthzModifier               authzModifier = new AuthzModifier().setTarget(AuthzModifier.Target.BLACKLIST).setBlacklistInfo(blacklistInfo);
            AuthzManager.operate(authzModifier);
        }

        private static void _change(Object userId, @Nullable String deviceType, @Nullable String deviceId, String time) {
            Optional<User> v = userBlacklist.stream().filter(u -> u.userId.equals(userId) && StringUtils.equals(u.deviceType, deviceType) && StringUtils.equals(u.deviceId, deviceId)).findFirst();
            if (v.isPresent()) {
                User user = v.get();
                user.timeMeta.changeTime(time);
            }
        }

        public static void change(Object userId, @Nullable String deviceType, @Nullable String deviceId, String time) {
            AuthzModifier.BlacklistInfo blacklistInfo = new AuthzModifier.BlacklistInfo().setType(AuthzModifier.BlacklistInfo.TYPE.USER).setOp(AuthzModifier.BlacklistInfo.OP.CHANGE).setUserId(userId).setDeviceType(deviceType).setDeviceId(deviceId).setTime(time);
            AuthzModifier               authzModifier = new AuthzModifier().setTarget(AuthzModifier.Target.BLACKLIST).setBlacklistInfo(blacklistInfo);
            AuthzManager.operate(authzModifier);
        }

        private static void _remove(Object userId, @Nullable String deviceType, @Nullable String deviceId) {
            userBlacklist.removeIf(u -> u.userId.equals(userId) && StringUtils.equals(u.deviceType, deviceType) && StringUtils.equals(u.deviceId, deviceId));
            if (userBlacklist.stream().noneMatch(u -> u.userId.equals(userId))) {
                userBlacklistBloomFilter.remove(userId.toString());
            }
        }

        public static void remove(Object userId, @Nullable String deviceType, @Nullable String deviceId) {
            AuthzModifier.BlacklistInfo blacklistInfo = new AuthzModifier.BlacklistInfo().setType(AuthzModifier.BlacklistInfo.TYPE.USER).setOp(AuthzModifier.BlacklistInfo.OP.REMOVE).setUserId(userId).setDeviceType(deviceType).setDeviceId(deviceId);
            AuthzModifier               authzModifier = new AuthzModifier().setTarget(AuthzModifier.Target.BLACKLIST).setBlacklistInfo(blacklistInfo);
            AuthzManager.operate(authzModifier);
        }

        @Nullable
        public static User get(Object userId, @Nullable String deviceType, @Nullable String deviceId) {
            return userBlacklist.stream().filter(u -> u.userId.equals(userId) && StringUtils.equals(u.deviceType, deviceType) && StringUtils.equals(u.deviceId, deviceId)).findFirst().orElse(null);
        }

        public static List<User> list(Object userId) {
            ArrayList<User> users = new ArrayList<>();
            userBlacklist.removeIf(u -> {
                if (u.userId.equals(userId)) users.add(u);
                return u.timeMeta.relive();
            });
            return users;
        }

        public static List<User> list() {
            return Collections.unmodifiableList(userBlacklist);
        }

        public static boolean check(Object userId, @Nullable String deviceType, @Nullable String deviceId) {
            if (userBlacklistBloomFilter.contains(userId.toString())) {
                List<User> list = list(userId);
                boolean hit = list.stream().anyMatch(user -> {
                    if (user.timeMeta.relive()) return false;
                    if (user.deviceType == null && user.deviceId == null) {
                        return true;
                    } else if (user.deviceType != null && user.deviceId != null) {
                        return StringUtils.equals(user.deviceType, deviceType) && StringUtils.equals(user.deviceId, deviceId);
                    } else if (user.deviceType != null) {
                        return StringUtils.equals(user.deviceType, deviceType);
                    }
                    return false;
                });
                for (User user : list) {
                    if (user.timeMeta.relive()) {
                        userBlacklist.remove(user);
                    }
                }
                if (list.isEmpty()) userBlacklistBloomFilter.remove(userId.toString());
                return !hit;
            }
            return true;
        }

    }

    @Data
    public static class IP {
        private final String   ip;
        private final TimeMeta timeMeta;

        public IP(String ip, TimeMeta timeMeta) {
            this.ip       = ip;
            this.timeMeta = timeMeta;
        }

        private static void _add(String ip, String time, long now) {
            ipBlacklist.add(new IP(ip, TimeMeta.of(time, now)));
            ipBlacklistBloomFilter.add(ip);
        }

        public static void add(String ip, String time) {
            long                        nowTime       = TimeUtils.nowTime();
            AuthzModifier.BlacklistInfo blacklistInfo = new AuthzModifier.BlacklistInfo().setType(AuthzModifier.BlacklistInfo.TYPE.IP).setOp(AuthzModifier.BlacklistInfo.OP.ADD).setIp(ip).setTime(time).setStart(nowTime);
            AuthzModifier               authzModifier = new AuthzModifier().setTarget(AuthzModifier.Target.BLACKLIST).setBlacklistInfo(blacklistInfo);
            AuthzManager.operate(authzModifier);
        }

        private static void _change(String ip, String time) {
            Optional<IP> v = ipBlacklist.stream().filter(o -> o.ip.equals(ip)).findFirst();
            if (v.isPresent()) {
                IP i = v.get();
                i.timeMeta.changeTime(time);
            }
        }

        public static void change(String ip, String time) {
            AuthzModifier.BlacklistInfo blacklistInfo = new AuthzModifier.BlacklistInfo().setType(AuthzModifier.BlacklistInfo.TYPE.IP).setOp(AuthzModifier.BlacklistInfo.OP.CHANGE).setIp(ip).setTime(time);
            AuthzModifier               authzModifier = new AuthzModifier().setTarget(AuthzModifier.Target.BLACKLIST).setBlacklistInfo(blacklistInfo);
            AuthzManager.operate(authzModifier);
        }

        private static void _remove(String ip) {
            ipBlacklist.removeIf(o -> o.ip.equals(ip));
            ipBlacklistBloomFilter.remove(ip);
        }

        public static void remove(String ip) {
            AuthzModifier.BlacklistInfo blacklistInfo = new AuthzModifier.BlacklistInfo().setType(AuthzModifier.BlacklistInfo.TYPE.IP).setOp(AuthzModifier.BlacklistInfo.OP.REMOVE).setIp(ip);
            AuthzModifier               authzModifier = new AuthzModifier().setTarget(AuthzModifier.Target.BLACKLIST).setBlacklistInfo(blacklistInfo);
            AuthzManager.operate(authzModifier);
        }

        @Nullable
        public static IP get(String ip) {
            AtomicReference<IP> i = new AtomicReference<>();
            ipBlacklist.removeIf(o -> {
                if (o.ip.equals(ip)) i.set(o);
                return o.timeMeta.relive();
            });
            return i.get();
        }

        public static boolean check(String ip) {
            if (ipBlacklistBloomFilter.contains(ip)) {
                IP _ip = get(ip);
                if (_ip == null) return true;
                else {
                    if (_ip.timeMeta.relive()) {
                        ipBlacklistBloomFilter.remove(ip);
                        ipBlacklist.remove(_ip);
                        return true;
                    } else {
                        return false;
                    }
                }
            }
            return true;
        }

        public static List<IP> list() {
            return Collections.unmodifiableList(ipBlacklist);
        }
    }

    @Data
    public static class IPRangeDeny {
        @JsonIgnore
        private final String   value;
        private final IPRange  ipRange;
        private final TimeMeta timeMeta;

        public IPRangeDeny(String ipRange, TimeMeta timeMeta) {
            this.value    = ipRange;
            this.ipRange  = new IPRange(ipRange);
            this.timeMeta = timeMeta;
        }

        private static void _add(String ipRange, String time, long now) {
            ipRangeBlacklist.add(new IPRangeDeny(ipRange, TimeMeta.of(time, now)));
        }

        public static void add(String ipRange, String time) {
            long                        nowTime       = TimeUtils.nowTime();
            AuthzModifier.BlacklistInfo blacklistInfo = new AuthzModifier.BlacklistInfo().setType(AuthzModifier.BlacklistInfo.TYPE.IP_RANGE).setOp(AuthzModifier.BlacklistInfo.OP.ADD).setIpRange(ipRange).setTime(time).setStart(nowTime);
            AuthzModifier               authzModifier = new AuthzModifier().setTarget(AuthzModifier.Target.BLACKLIST).setBlacklistInfo(blacklistInfo);
            AuthzManager.operate(authzModifier);
        }

        private static void _change(String ipRange, String time) {
            Optional<IPRangeDeny> v = ipRangeBlacklist.stream().filter(o -> o.value.equals(ipRange)).findFirst();
            if (v.isPresent()) {
                IPRangeDeny i = v.get();
                i.timeMeta.changeTime(time);
            }
        }

        public static void change(String ipRange, String time) {
            AuthzModifier.BlacklistInfo blacklistInfo = new AuthzModifier.BlacklistInfo().setType(AuthzModifier.BlacklistInfo.TYPE.IP_RANGE).setOp(AuthzModifier.BlacklistInfo.OP.CHANGE).setIpRange(ipRange).setTime(time);
            AuthzModifier               authzModifier = new AuthzModifier().setTarget(AuthzModifier.Target.BLACKLIST).setBlacklistInfo(blacklistInfo);
            AuthzManager.operate(authzModifier);
        }

        private static void _remove(String ipRange) {
            ipRangeBlacklist.removeIf(o -> o.value.equals(ipRange));
        }

        public static void remove(String ipRange) {
            AuthzModifier.BlacklistInfo blacklistInfo = new AuthzModifier.BlacklistInfo().setType(AuthzModifier.BlacklistInfo.TYPE.IP_RANGE).setOp(AuthzModifier.BlacklistInfo.OP.REMOVE).setIpRange(ipRange);
            AuthzModifier               authzModifier = new AuthzModifier().setTarget(AuthzModifier.Target.BLACKLIST).setBlacklistInfo(blacklistInfo);
            AuthzManager.operate(authzModifier);
        }

        public static boolean check(String ip) {
            AtomicBoolean hit = new AtomicBoolean(false);
            ipRangeBlacklist.removeIf(v -> {
                boolean relive = v.timeMeta.relive();
                if (!relive && v.ipRange.isIPAddressInRange(new IPAddress(ip))) {
                    hit.set(true);
                }
                return relive;
            });
            return !hit.get();
        }

        public static List<IPRangeDeny> list() {
            return Collections.unmodifiableList(ipRangeBlacklist);
        }
    }

    public static class TimeMeta {
        private final long start;
        private       long end;
        private       long time;

        @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
        public Date getStart() {
            return new Date(start);
        }

        public String getTime() {
            return TimeUtils.parseTime(time);
        }

        @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
        public Date getEnd() {
            return new Date(end);
        }

        private TimeMeta(String time, long now) {
            this.start = now;
            this.time  = TimeUtils.parseTimeValue(time);
            this.end   = this.start + this.time;
        }

        private static TimeMeta of(String time, long now) {
            return new TimeMeta(time, now);
        }

        private void changeTime(String time) {
            this.time = TimeUtils.parseTimeValue(time);
            this.end  = this.start + this.time;
        }

        private boolean relive() {
            return TimeUtils.nowTime() >= this.end;
        }
    }

    public static Map<String, Object> readAll() {
        HashMap<String, Object> map = new HashMap<>();
        map.put("ipBlacklist", ipBlacklist);
        map.put("userBlacklist", userBlacklist);
        map.put("ipRangeBlacklist", ipRangeBlacklist);
        return Collections.unmodifiableMap(map);
    }

    public static Object modify(AuthzModifier modifier) {
        AuthzModifier.BlacklistInfo blacklistInfo = modifier.getBlacklistInfo();
        String                      time          = blacklistInfo.getTime();
        Long                        start         = blacklistInfo.getStart();
        switch (blacklistInfo.getType()) {
            case IP:
                String ip = blacklistInfo.getIp();
                switch (blacklistInfo.getOp()) {
                    case ADD:
                        IP._add(ip, time, start);
                        break;
                    case CHANGE:
                        IP._change(ip, time);
                        break;
                    case REMOVE:
                        IP.remove(ip);
                        break;
                    case READ:
                        return Result.SUCCESS.data(ipBlacklist);
                }
                break;
            case IP_RANGE:
                String ipRange = blacklistInfo.getIpRange();
                switch (blacklistInfo.getOp()) {
                    case ADD:
                        IPRangeDeny._add(ipRange, time, start);
                        break;
                    case CHANGE:
                        IPRangeDeny._change(ipRange, time);
                        break;
                    case REMOVE:
                        IPRangeDeny.remove(ipRange);
                        break;
                    case READ:
                        return Result.SUCCESS.data(ipRangeBlacklist);
                }
                break;
            case USER:
                Object userId = blacklistInfo.getUserId();
                String deviceType = blacklistInfo.getDeviceType();
                String deviceId = blacklistInfo.getDeviceId();
                switch (blacklistInfo.getOp()) {
                    case ADD:
                        User._add(userId, deviceType, deviceId, time, start);
                        break;
                    case CHANGE:
                        User._change(userId, deviceType, deviceId, time);
                        break;
                    case REMOVE:
                        User._remove(userId, deviceType, deviceId);
                        break;
                    case READ:
                        return Result.SUCCESS.data(userBlacklist);
                }
                break;
        }
        return Result.SUCCESS;
    }

}
