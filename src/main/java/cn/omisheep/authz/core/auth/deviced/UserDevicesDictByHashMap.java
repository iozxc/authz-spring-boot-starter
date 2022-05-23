package cn.omisheep.authz.core.auth.deviced;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.tk.Token;
import cn.omisheep.authz.core.tk.TokenPair;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.commons.util.TimeUtils;
import lombok.Getter;
import org.apache.commons.lang.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public class UserDevicesDictByHashMap extends DeviceConfig implements UserDevicesDict {

    private final AuthzProperties properties;

    @Getter
    private final Map<Object, Map<String, AccessInfo>>  usersAccessInfoHeap  = new ConcurrentHashMap<>();
    @Getter
    private final Map<Object, Map<String, RefreshInfo>> usersRefreshInfoHeap = new ConcurrentHashMap<>();

    public UserDevicesDictByHashMap(AuthzProperties properties) {
        this.properties = properties;
    }

    @Override
    public int userStatus(Object userId, String deviceType, String deviceId, String accessTokenId) {
        inertDeletion(userId);

        // 1） 验证userId 若不存在则需重新登录 此时token正确，但是系统不存在，意味着系统重启了，或者redis重启了）
        Map<String, AccessInfo>  accessInfoHeap  = usersAccessInfoHeap.get(userId);
        Map<String, RefreshInfo> refreshInfoHeap = usersRefreshInfoHeap.get(userId);

        boolean hasTargetDeviceInfo = false;
        if (refreshInfoHeap != null) {
            hasTargetDeviceInfo = refreshInfoHeap.entrySet().stream().anyMatch(entry -> {
                Device device = entry.getValue();
                return (StringUtils.equals(deviceId, device.getId())
                        && StringUtils.equals(deviceType, device.getType()));
            });
        }

        if (accessInfoHeap == null || accessInfoHeap.isEmpty()) {
            if (refreshInfoHeap == null || !hasTargetDeviceInfo) return 2;
            return ACCESS_TOKEN_OVERDUE;
        }

        // 2） 验证device 若不存在，但是userId存在，也是重新登录 如果不允许多设备登录 那么此时也是 账号在别处登录
        Map.Entry<String, AccessInfo> d = accessInfoHeap.entrySet().stream().filter(
                entry -> {
                    String refreshTokenId = entry.getValue().getRefreshTokenId();
                    if (refreshInfoHeap != null) {
                        Device device = refreshInfoHeap.get(refreshTokenId);
                        return (StringUtils.equals(deviceId, device.getId())
                                && StringUtils.equals(deviceType, device.getType()));
                    }
                    return false;
                }).findFirst().orElse(null);
        if (d == null) { // 如果没有这个设备
            if (!isSupportMultiDevice) {
                return LOGIN_EXCEPTION;
            } else {
                if (!hasTargetDeviceInfo) return REQUIRE_LOGIN;
                return ACCESS_TOKEN_OVERDUE;
            }
        }

        // 3）如果设备存在，但是tokenId不是自己的，则在别处登录
        if (!StringUtils.equals(d.getKey(), accessTokenId)) {
            return LOGIN_EXCEPTION;
        }
        return SUCCESS;
    }

    @Override
    public boolean addUser(Object userId, TokenPair tokenPair, String deviceType, String deviceId, HttpMeta httpMeta) {
        inertDeletion(userId);
        Map<String, AccessInfo>  accessInfoHeap  = usersAccessInfoHeap.computeIfAbsent(userId, k -> new ConcurrentHashMap<>());
        Map<String, RefreshInfo> refreshInfoHeap = usersRefreshInfoHeap.computeIfAbsent(userId, k -> new ConcurrentHashMap<>());
        DefaultDevice            device          = new DefaultDevice();
        device.setType(deviceType).setId(deviceId).setLastRequestTime(TimeUtils.now()).setIp(httpMeta.getIp());

        if (!isSupportMultiDevice) {
            accessInfoHeap.clear();
            refreshInfoHeap.clear();
        } else {
            if (!isSupportMultiUserForSameDeviceType) {
                accessInfoHeap.entrySet().removeIf(entry -> StringUtils.equals(getRefreshInfo(refreshInfoHeap, entry.getValue()).getType(), device.getType()));
                refreshInfoHeap.entrySet().removeIf(entry -> StringUtils.equals(entry.getValue().getType(), device.getType()));
            }

            accessInfoHeap.entrySet().removeIf(entry -> StringUtils.equals(getRefreshInfo(refreshInfoHeap, entry.getValue()).getId(), device.getId()));
            refreshInfoHeap.entrySet().removeIf(entry -> StringUtils.equals(entry.getValue().getId(), device.getId()));
        }

        Token accessToken  = tokenPair.getAccessToken();
        Token refreshToken = tokenPair.getRefreshToken();

        accessInfoHeap.put(accessToken.getTokenId(),
                new AccessInfo().setRefreshTokenId(refreshToken.getTokenId()).setExpiration(accessToken.getExpiredTime()));
        refreshInfoHeap.put(refreshToken.getTokenId(),
                new RefreshInfo().setDevice(device).setExpiration(TimeUtils.datePlus(refreshToken.getExpiredTime(), properties.getToken().getLiveTime())));
        return true;
    }

    @Override
    public boolean refreshUser(TokenPair tokenPair) {
        if (tokenPair == null) return false;
        Token accessToken = tokenPair.getAccessToken();
        inertDeletion(accessToken.getUserId());

        Token                    refreshToken    = tokenPair.getRefreshToken();
        Map<String, RefreshInfo> refreshInfoHeap = usersRefreshInfoHeap.computeIfAbsent(accessToken.getUserId(), k -> new ConcurrentHashMap<>());

        /* refresh 可用性判断 */
        if (!refreshInfoHeap.containsKey(refreshToken.getTokenId())) return false;

        Map<String, AccessInfo> accessInfoHeap = usersAccessInfoHeap.computeIfAbsent(accessToken.getUserId(), k -> new ConcurrentHashMap<>());

        /* refresh可用 */
        Map.Entry<String, AccessInfo> d = accessInfoHeap.entrySet().stream().filter(
                entry -> {
                    Device device = refreshInfoHeap.get(entry.getValue().getRefreshTokenId());
                    return (StringUtils.equals(accessToken.getDeviceId(), device.getId())
                            && StringUtils.equals(accessToken.getDeviceType(), device.getType()));
                }).findFirst().orElse(null);

        HttpMeta httpMeta = (HttpMeta) ((ServletRequestAttributes) (RequestContextHolder.currentRequestAttributes())).getRequest().getAttribute("AU_HTTP_META");

        RefreshInfo refreshInfo = refreshInfoHeap.get(tokenPair.getRefreshToken().getTokenId());
        if (refreshInfo != null) {
            refreshInfo.setIp(httpMeta.getIp());
            refreshInfo.setLastRequestTime(TimeUtils.now());
        }
        if (d != null) {
            accessInfoHeap.remove(d.getKey());
        }
        accessInfoHeap.put(accessToken.getTokenId(), new AccessInfo().setExpiration(accessToken.getExpiredTime()).setRefreshTokenId(refreshToken.getTokenId()));
        return true;
    }

    public void removeDeviceByUserIdAndAccessTokenId(Object userId, String accessTokenId) {
        Map<String, AccessInfo> accessInfoHeap = usersAccessInfoHeap.get(userId);
        if (accessInfoHeap != null) {
            accessInfoHeap.remove(accessTokenId);
        }
        inertDeletion(userId);
    }

    @Override
    public void removeAllDeviceByUserId(Object userId) {
        usersAccessInfoHeap.remove(userId);
        usersRefreshInfoHeap.remove(userId);
    }

    @Override
    public void removeDeviceByUserIdAndDeviceType(Object userId, String deviceType) {
        removeDevice(userId, deviceType);
    }

    @Override
    public void removeDeviceByUserIdAndDeviceTypeAndDeviceId(Object userId, String deviceType, String deviceId) {
        removeDevice(userId, deviceType, deviceId);
    }

    @Override
    public void removeAllDeviceFromCurrentUser() {
        try {
            removeAllDeviceByUserId(AUtils.getCurrentHttpMeta().getToken().getUserId());
        } catch (Exception ignored) {
        }
    }

    @Override
    public void removeCurrentDeviceFromCurrentUser() {
        try {
            Token token = AUtils.getCurrentHttpMeta().getToken();
            removeDevice(token.getUserId(), token.getDeviceType(), token.getDeviceId());
        } catch (Exception ignored) {
        }
    }

    @Override
    public void removeDeviceFromCurrentUserByDeviceType(String deviceType) {
        try {
            removeDevice(AUtils.getCurrentHttpMeta().getToken().getUserId(), deviceType);
        } catch (Exception ignored) {
        }
    }

    @Override
    public void removeDeviceFromCurrentUserByDeviceTypeAndDeviceId(String deviceType, String deviceId) {
        try {
            removeDevice(AUtils.getCurrentHttpMeta().getToken().getUserId(), deviceType, deviceId);
        } catch (Exception ignored) {
        }
    }

    private void removeDevice(Object userId, String deviceType) {
        Map<String, AccessInfo>  accessInfoHeap  = usersAccessInfoHeap.computeIfAbsent(userId, k -> new ConcurrentHashMap<>());
        Map<String, RefreshInfo> refreshInfoHeap = usersRefreshInfoHeap.computeIfAbsent(userId, k -> new ConcurrentHashMap<>());

        if (deviceType != null) {
            accessInfoHeap.entrySet().removeIf(entry -> StringUtils.equals(getRefreshInfo(refreshInfoHeap, entry.getValue()).getType(), deviceType));
            refreshInfoHeap.entrySet().removeIf(entry -> StringUtils.equals(entry.getValue().getType(), deviceType));
        }

        inertDeletion(userId);
    }

    private void removeDevice(Object userId, String deviceType, String deviceId) {
        Map<String, AccessInfo>  accessInfoHeap  = usersAccessInfoHeap.computeIfAbsent(userId, k -> new ConcurrentHashMap<>());
        Map<String, RefreshInfo> refreshInfoHeap = usersRefreshInfoHeap.computeIfAbsent(userId, k -> new ConcurrentHashMap<>());

        if (deviceType != null) {
            accessInfoHeap.entrySet().removeIf(entry ->
                    StringUtils.equals(getRefreshInfo(refreshInfoHeap, entry.getValue()).getType(), deviceType) &&
                            StringUtils.equals(getRefreshInfo(refreshInfoHeap, entry.getValue()).getId(), deviceId));
            refreshInfoHeap.entrySet().removeIf(entry -> StringUtils.equals(entry.getValue().getType(), deviceType)
                    && StringUtils.equals(entry.getValue().getId(), deviceId));
        }

        inertDeletion(userId);
    }

    @Override
    public Device getDevice(Object userId, String deviceType, String deviceId) {
        Map<String, AccessInfo>  accessInfoHeap  = usersAccessInfoHeap.get(userId);
        Map<String, RefreshInfo> refreshInfoHeap = usersRefreshInfoHeap.get(userId);
        if (!inertDeletion(userId)) return null;
        Map.Entry<String, AccessInfo> d = accessInfoHeap.entrySet().stream().filter(
                entry -> {
                    Device device = getRefreshInfo(refreshInfoHeap, entry.getValue());
                    return (StringUtils.equals(deviceId, device.getId())
                            && StringUtils.equals(deviceType, device.getType()));
                }).findFirst().orElse(null);
        if (d != null) return getRefreshInfo(refreshInfoHeap, d.getValue());
        return null;
    }

    @Override
    public List<Object> listUserId() {
        return new ArrayList<>(usersAccessInfoHeap.keySet());
    }

    @Override
    public List<Device> listDevicesByUserId(Object userId) {
        if (!inertDeletion(userId)) return new ArrayList<>();
        Map<String, RefreshInfo> refreshInfoHeap = usersRefreshInfoHeap.get(userId);
        if (refreshInfoHeap == null) return new ArrayList<>();
        return usersAccessInfoHeap.get(userId).values().stream().map(v -> (Device) refreshInfoHeap.get(v.getRefreshTokenId())).collect(Collectors.toList());
    }

    @Override
    public List<Device> listDevicesForCurrentUser() {
        try {
            return listDevicesByUserId(AUtils.getCurrentHttpMeta().getToken().getUserId());
        } catch (Exception ignored) {
            return new ArrayList<>();
        }
    }

    @Override
    public List<Object> listActiveUsers(long ms) {
        long now = TimeUtils.nowTime();

        return usersRefreshInfoHeap.keySet().stream()
                .filter(userId ->
                        usersRefreshInfoHeap.get(userId).values().stream().anyMatch(device -> (now - device.getLastRequestTime().getTime()) < ms)
                ).collect(Collectors.toList());
    }

    @Override
    public List<Device> listActiveUserDevices(Object userId, long ms) {
        long now = TimeUtils.nowTime();

        Map<String, RefreshInfo> refreshInfoHeap = usersRefreshInfoHeap.get(userId);
        if (refreshInfoHeap == null) return new ArrayList<>();

        return refreshInfoHeap.values().stream()
                .filter(refreshInfo -> (now - refreshInfo.getLastRequestTime().getTime()) < ms)
                .map(RefreshInfo::getDevice)
                .collect(Collectors.toList());
    }

    @Override
    public void request() {
        try {
            HttpMeta   currentHttpMeta = AUtils.getCurrentHttpMeta();
            Token      token           = currentHttpMeta.getToken();
            AccessInfo accessInfo      = usersAccessInfoHeap.get(token.getUserId()).get(token.getTokenId());
            Device     device          = usersRefreshInfoHeap.get(token.getUserId()).get(accessInfo.getRefreshTokenId());
            if (device != null) {
                device.setLastRequestTime(TimeUtils.now());
                device.setIp(currentHttpMeta.getIp());
            }
        } catch (Exception ignored) {

        }
    }

    public void cleanCycle() {
        long now = TimeUtils.nowTime();
        usersAccessInfoHeap.entrySet().removeIf(entry -> {
            Map<String, AccessInfo> value = entry.getValue();
            if (value == null) return true;
            value.entrySet().removeIf(device -> device.getValue().getExpirationVal() < now);
            return value.isEmpty();
        });

        usersRefreshInfoHeap.entrySet().removeIf(entry -> {
            Map<String, RefreshInfo> value = entry.getValue();
            if (value == null) return true;
            value.entrySet().removeIf(device -> device.getValue().getExpirationVal() < now);
            return value.isEmpty();
        });
    }

    /**
     * 惰性删除accessToken,refreshToken
     *
     * @param userId 用户id
     * @return 删除后是否还存在用户设备列表
     */
    private boolean inertDeletion(Object userId) {
        Map<String, AccessInfo>  accessInfoHeap  = usersAccessInfoHeap.get(userId);
        Map<String, RefreshInfo> refreshInfoHeap = usersRefreshInfoHeap.get(userId);
        long                     now             = TimeUtils.nowTime();

        if (refreshInfoHeap == null || refreshInfoHeap.isEmpty()) {
            usersRefreshInfoHeap.remove(userId);
        } else {
            refreshInfoHeap.entrySet().removeIf(entry -> entry.getValue().getExpirationVal() < now);
            if (refreshInfoHeap.isEmpty()) usersRefreshInfoHeap.remove(userId);
        }

        if (accessInfoHeap == null || accessInfoHeap.isEmpty()) {
            usersAccessInfoHeap.remove(userId);
            return false;
        }

        accessInfoHeap.entrySet().removeIf(entry -> entry.getValue().getExpirationVal() < now);
        if (accessInfoHeap.isEmpty()) {
            usersAccessInfoHeap.remove(userId);
            return false;
        }
        return true;
    }

    private RefreshInfo getRefreshInfo(Map<String, RefreshInfo> refreshInfoHeap, AccessInfo accessInfo) {
        if (refreshInfoHeap == null) return new RefreshInfo();
        return refreshInfoHeap.getOrDefault(accessInfo.getRefreshTokenId(), new RefreshInfo());
    }
}
