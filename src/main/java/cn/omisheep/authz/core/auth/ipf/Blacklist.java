package cn.omisheep.authz.core.auth.ipf;

import cn.omisheep.authz.core.AuthzManager;
import cn.omisheep.authz.core.msg.AuthzModifier;
import cn.omisheep.authz.core.tk.AccessToken;
import cn.omisheep.authz.support.util.IPAddress;
import cn.omisheep.authz.support.util.IPRange;
import cn.omisheep.commons.util.TimeUtils;
import cn.omisheep.web.entity.Result;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import orestes.bloomfilter.CountingBloomFilter;
import orestes.bloomfilter.FilterBuilder;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

import java.text.ParseException;
import java.util.*;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static cn.omisheep.authz.core.msg.AuthzModifier.BlacklistInfo.OP.REMOVE;
import static cn.omisheep.authz.core.msg.AuthzModifier.BlacklistInfo.OP.UPDATE;
import static cn.omisheep.authz.core.msg.AuthzModifier.BlacklistInfo.TYPE.IP_RANGE;
import static cn.omisheep.authz.core.msg.AuthzModifier.BlacklistInfo.TYPE.USER;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.1.0
 */
public class Blacklist {

    private static final Set<IP>                     ipBlacklist            = new CopyOnWriteArraySet<>();
    private static final CountingBloomFilter<String> ipBlacklistBloomFilter = new FilterBuilder(1000,
                                                                                                0.001).countingBits(8)
            .buildCountingBloomFilter();

    private static final Set<User>                   userBlacklist            = new CopyOnWriteArraySet<>();
    private static final CountingBloomFilter<String> userBlacklistBloomFilter = new FilterBuilder(1000,
                                                                                                  0.001).countingBits(8)
            .buildCountingBloomFilter();

    private static final Set<IPRangeDeny> ipRangeBlacklist = new CopyOnWriteArraySet<>();

    public static boolean check(@NonNull String ip,
                                @Nullable Object userId,
                                @Nullable String deviceType,
                                @Nullable String deviceId) {
        return IP.check(ip) && IPRangeDeny.check(ip) && User.check(userId, deviceType, deviceId);
    }

    public static boolean check(@NonNull String ip,
                                @Nullable AccessToken accessToken) {
        if (accessToken == null) return check(ip);
        return IP.check(ip)
                && IPRangeDeny.check(ip)
                && User.check(accessToken.getUserId(),
                              accessToken.getDeviceType(),
                              accessToken.getDeviceId());
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

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;

            if (!(o instanceof User)) return false;

            User user = (User) o;

            return new EqualsBuilder().append(getUserId(), user.getUserId())
                    .append(getDeviceType(), user.getDeviceType())
                    .append(getDeviceId(), user.getDeviceId())
                    .isEquals();
        }

        @Override
        public int hashCode() {
            return new HashCodeBuilder(17, 37).append(getUserId())
                    .append(getDeviceType())
                    .append(getDeviceId())
                    .toHashCode();
        }

        public User(Object userId,
                    @Nullable String deviceType,
                    @Nullable String deviceId,
                    TimeMeta timeMeta) {
            this.userId     = userId;
            this.deviceId   = deviceId;
            this.deviceType = deviceType;
            this.timeMeta   = timeMeta;
        }

        private static void _update(Object userId,
                                    @Nullable String deviceType,
                                    @Nullable String deviceId,
                                    long time) {
            User _user = new User(userId, deviceType, deviceId, TimeMeta.of(time));
            userBlacklist.remove(_user);
            userBlacklist.add(_user);
            userBlacklistBloomFilter.add(userId.toString());
        }

        private static void _update(Object userId,
                                    @Nullable String deviceType,
                                    @Nullable String deviceId,
                                    Date endDate) {
            User _user = new User(userId, deviceType, deviceId, TimeMeta.of(endDate));
            userBlacklist.remove(_user);
            userBlacklist.add(_user);
            userBlacklistBloomFilter.add(userId.toString());
        }

        public static void update(Object userId,
                                  @Nullable String deviceType,
                                  @Nullable String deviceId,
                                  long time) {
            _op(_createUser(userId, deviceType, deviceId, UPDATE)
                        .setTime(time));
        }

        public static void update(Object userId,
                                  @Nullable String deviceType,
                                  @Nullable String deviceId,
                                  Date endDate) {
            _op(_createUser(userId, deviceType, deviceId, UPDATE)
                        .setDate(TimeUtils.format(endDate)));
        }

        private static AuthzModifier.BlacklistInfo _createUser(Object userId,
                                                               @Nullable String deviceType,
                                                               @Nullable String deviceId,
                                                               AuthzModifier.BlacklistInfo.OP op) {
            return _create(USER, op)
                    .setUserId(userId)
                    .setDeviceType(deviceType)
                    .setDeviceId(deviceId);
        }

        private static void _remove(Object userId,
                                    @Nullable String deviceType,
                                    @Nullable String deviceId) {
            userBlacklist.remove(new User(userId, deviceType, deviceId, null));
            userBlacklistBloomFilter.remove(userId.toString());
        }

        public static void remove(Object userId,
                                  @Nullable String deviceType,
                                  @Nullable String deviceId) {
            _op(_create(USER, REMOVE)
                        .setUserId(userId)
                        .setDeviceType(deviceType)
                        .setDeviceId(deviceId));
        }

        @Nullable
        public static User getDevice(Object userId,
                                     @Nullable String deviceType,
                                     @Nullable String deviceId) {
            return userBlacklist.stream()
                    .filter(u -> u.userId.equals(userId)
                            && StringUtils.equals(u.deviceType, deviceType) && StringUtils.equals(
                            u.deviceId, deviceId))
                    .findFirst()
                    .orElse(null);
        }

        public static User getUser(Object userId) {
            return list(userId).stream()
                    .filter(v -> v.getDeviceType() == null && v.getDeviceId() == null).findAny().orElse(null);
        }

        public static Set<User> list(Object userId) {
            HashSet<User> users = new HashSet<>();
            userBlacklist.removeIf(u -> {
                if (u.timeMeta.relive()) {
                    return true;
                } else {
                    if (u.userId.equals(userId)) {
                        users.add(u);
                    }
                    return false;
                }
            });
            return users;
        }

        public static Set<User> list() {
            return Collections.unmodifiableSet(userBlacklist);
        }

        public static boolean check(@Nullable Object userId,
                                    @Nullable String deviceType,
                                    @Nullable String deviceId) {
            if (userId == null) return true;
            if (userBlacklistBloomFilter.contains(userId.toString())) {
                Set<User> list = list(userId);
                boolean hit = list.stream().anyMatch(user -> {
                    if (user.timeMeta.relive()) return false;
                    if (user.deviceType == null && user.deviceId == null) {
                        return true;
                    } else if (user.deviceType != null && user.deviceId != null) {
                        return StringUtils.equals(user.deviceType, deviceType) && StringUtils.equals(user.deviceId,
                                                                                                     deviceId);
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

        public IP(String ip,
                  TimeMeta timeMeta) {
            this.ip       = ip;
            this.timeMeta = timeMeta;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;

            if (!(o instanceof IP)) return false;

            IP ip1 = (IP) o;

            return new EqualsBuilder().append(getIp(), ip1.getIp()).isEquals();
        }

        @Override
        public int hashCode() {
            return new HashCodeBuilder(17, 37).append(getIp()).toHashCode();
        }

        private static void _update(String ip,
                                    long time) {
            IP _ip = new IP(ip, TimeMeta.of(time));
            ipBlacklist.remove(_ip);
            ipBlacklist.add(_ip);
            ipBlacklistBloomFilter.add(ip);
        }

        private static void _update(String ip,
                                    Date endDate) {
            IP _ip = new IP(ip, TimeMeta.of(endDate));
            ipBlacklist.remove(_ip);
            ipBlacklist.add(_ip);
            ipBlacklistBloomFilter.add(ip);
        }

        public static void update(String ip,
                                  long time) {
            _op(_create(AuthzModifier.BlacklistInfo.TYPE.IP, UPDATE)
                        .setIp(ip)
                        .setTime(time));
        }

        public static void update(String ip,
                                  Date endDate) {
            _op(_create(AuthzModifier.BlacklistInfo.TYPE.IP, UPDATE)
                        .setIp(ip)
                        .setDate(TimeUtils.format(endDate)));
        }

        private static void _remove(String ip) {
            ipBlacklist.remove(new IP(ip, null));
            ipBlacklistBloomFilter.remove(ip);
        }

        public static void remove(String ip) {
            _op(_create(AuthzModifier.BlacklistInfo.TYPE.IP, REMOVE).setIp(ip));
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
                if (_ip == null) {return true;} else {
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

        public static Set<IP> list() {
            return Collections.unmodifiableSet(ipBlacklist);
        }
    }

    @Data
    public static class IPRangeDeny {
        @JsonIgnore
        private final String   value;
        private final IPRange  ipRange;
        private final TimeMeta timeMeta;

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;

            if (!(o instanceof IPRangeDeny)) return false;

            IPRangeDeny that = (IPRangeDeny) o;

            return new EqualsBuilder().append(getValue(), that.getValue()).isEquals();
        }

        @Override
        public int hashCode() {
            return new HashCodeBuilder(17, 37).append(getValue()).toHashCode();
        }

        public IPRangeDeny(String ipRange,
                           TimeMeta timeMeta) {
            this.value    = ipRange;
            this.ipRange  = new IPRange(ipRange);
            this.timeMeta = timeMeta;
        }

        private static void _update(String ipRange,
                                    Date endDate) {
            IPRangeDeny _ipRange = new IPRangeDeny(ipRange, TimeMeta.of(endDate));
            ipRangeBlacklist.remove(_ipRange);
            ipRangeBlacklist.add(_ipRange);
        }

        private static void _update(String ipRange,
                                    long time) {
            IPRangeDeny _ipRange = new IPRangeDeny(ipRange, TimeMeta.of(time));
            ipRangeBlacklist.remove(_ipRange);
            ipRangeBlacklist.add(_ipRange);
        }

        public static void update(String ipRange,
                                  long time) {
            _op(_create(IP_RANGE, UPDATE).setTime(time).setIpRange(ipRange));
        }

        public static void update(String ipRange,
                                  Date endDate) {
            _op(_create(IP_RANGE, UPDATE).setDate(TimeUtils.format(endDate)).setIpRange(ipRange));
        }

        private static void _remove(String ipRange) {
            ipRangeBlacklist.remove(new IPRangeDeny(ipRange, null));
        }

        public static void remove(String ipRange) {
            _op(_create(IP_RANGE, REMOVE).setIpRange(ipRange));
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

        public static Set<IPRangeDeny> list() {
            return Collections.unmodifiableSet(ipRangeBlacklist);
        }
    }

    public static class TimeMeta {
        private final long _end;
        private final long _time;

        public String getTime() {
            return TimeUtils.parseTime(_time);
        }

        public String getEnd() {
            return TimeUtils.format(new Date(_end));
        }

        private TimeMeta(long time) {
            this._time = time;
            this._end  = TimeUtils.nowTime() + this._time;
        }

        private TimeMeta(Date endDate) {
            this._time = endDate.getTime() - TimeUtils.nowTime();
            this._end  = endDate.getTime();
        }

        private static TimeMeta of(long time) {
            return new TimeMeta(time);
        }

        private static TimeMeta of(Date endDate) {
            return new TimeMeta(endDate);
        }

        private boolean relive() {
            return TimeUtils.nowTime() >= this._end;
        }
    }

    public static Map<String, Object> readAll() {
        HashMap<String, Object> map = new HashMap<>();
        map.put("ipBlacklist", ipBlacklist);
        map.put("userBlacklist", userBlacklist);
        map.put("ipRangeBlacklist", ipRangeBlacklist);
        return Collections.unmodifiableMap(map);
    }

    public static Object modify(AuthzModifier modifier) throws ParseException {
        AuthzModifier.BlacklistInfo blacklistInfo = modifier.getBlacklistInfo();
        long                        time          = blacklistInfo.getTime();

        switch (blacklistInfo.getType()) {
            case IP:
                String ip = blacklistInfo.getIp();
                switch (blacklistInfo.getOp()) {
                    case UPDATE:
                        Date date = TimeUtils.formatParse(blacklistInfo.getDate());
                        if (date == null) {IP._update(ip, time);} else IP._update(ip, date);
                        break;
                    case REMOVE:
                        IP._remove(ip);
                        break;
                    case READ:
                        return Result.SUCCESS.data(ipBlacklist);
                }
                break;
            case IP_RANGE:
                String ipRange = blacklistInfo.getIpRange();
                switch (blacklistInfo.getOp()) {
                    case UPDATE:
                        Date date = TimeUtils.formatParse(blacklistInfo.getDate());
                        if (date == null) {IPRangeDeny._update(ipRange, time);} else IPRangeDeny._update(ipRange, date);
                        break;
                    case REMOVE:
                        IPRangeDeny._remove(ipRange);
                        break;
                    case READ:
                        return Result.SUCCESS.data(ipRangeBlacklist);
                }
                break;
            case USER:
            case DEVICE:
                Object userId = blacklistInfo.getUserId();
                String deviceType = blacklistInfo.getDeviceType();
                String deviceId = blacklistInfo.getDeviceId();
                switch (blacklistInfo.getOp()) {
                    case UPDATE:
                        Date date = TimeUtils.formatParse(blacklistInfo.getDate());
                        if (date == null) {User._update(userId, deviceType, deviceId, time);} else {
                            User._update(userId,
                                         deviceType,
                                         deviceId,
                                         date);
                        }
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

    private Blacklist() {
        throw new UnsupportedOperationException();
    }


    private static AuthzModifier.BlacklistInfo _create(AuthzModifier.BlacklistInfo.TYPE type,
                                                       AuthzModifier.BlacklistInfo.OP op) {
        return new AuthzModifier.BlacklistInfo().setType(
                type).setOp(op);
    }

    private static void _op(AuthzModifier.BlacklistInfo blacklistInfo) {
        AuthzModifier authzModifier = new AuthzModifier().setTarget(AuthzModifier.Target.BLACKLIST)
                .setBlacklistInfo(blacklistInfo);
        AuthzManager.operate(authzModifier);
    }
}
