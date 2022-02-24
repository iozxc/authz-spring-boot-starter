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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
public class UserDevicesDictByHashMap extends DeviceConfig implements UserDevicesDict {

    private final AuthzProperties properties;

    @Getter
    private final Map<Object, Map<String, AccessInfo>> usersAccessInfoHeap = new ConcurrentHashMap<>();
    @Getter
    private final Map<Object, Map<String, RefreshInfo>> usersRefreshInfoHeap = new ConcurrentHashMap<>();

    public UserDevicesDictByHashMap(AuthzProperties properties) {
        this.properties = properties;
    }

    @Override
    public int userStatus(Object userId, String deviceType, String deviceId, String accessTokenId) {
        inertDeletion(userId);

        // 1） 验证userId 若不存在则需重新登录 此时token正确，但是系统不存在，意味着系统重启了，或者redis重启了）
        Map<String, AccessInfo> accessInfoHeap = usersAccessInfoHeap.get(userId);
        Map<String, RefreshInfo> refreshInfoHeap = usersRefreshInfoHeap.get(userId);

        boolean hasTargetDeviceInfo = false;
        if (refreshInfoHeap != null) {
            hasTargetDeviceInfo = refreshInfoHeap.entrySet().stream().anyMatch(entry -> {
                Device device = entry.getValue();
                return (StringUtils.equals(deviceId, device.getId())
                        && StringUtils.equals(deviceType, device.getType()));
            });
        }

        if (accessInfoHeap == null || accessInfoHeap.isEmpty()) { // 没有accessToken
            if (refreshInfoHeap == null || !hasTargetDeviceInfo) return 2; // refreshToken不存在，或者不存在对应的设备，则返回需要登录
            return 1; // refreshToken存在 对应type和id设备的refreshToken存在，返回accessToken过期 虽然此时不一定是这次登录的
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
            if (!isSupportMultiDevice) { // 如果不允许多设备登录，说明现在存在其他设备。
                return 3;
            } else {
                if (!hasTargetDeviceInfo) return 2; // 如果允许多设备登录 则说明不存在该设备 返回重新登录
                return 1;
            }
        }

        // 3）如果设备存在，但是tokenId不是自己的，则在别处登录
        if (!StringUtils.equals(d.getKey(), accessTokenId)) {
            return 3;
        }
        return 0;
    }

    @Override
    public boolean addUser(Object userId, TokenPair tokenPair, Device device) {
        inertDeletion(userId);
        Map<String, AccessInfo> accessInfoHeap = usersAccessInfoHeap.computeIfAbsent(userId, k -> new ConcurrentHashMap<>());
        Map<String, RefreshInfo> refreshInfoHeap = usersRefreshInfoHeap.computeIfAbsent(userId, k -> new ConcurrentHashMap<>());

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

        Token accessToken = tokenPair.getAccessToken();
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

        Token refreshToken = tokenPair.getRefreshToken();
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

    @Override
    public void removeAllDeviceByUserId(Object userId) {
        usersAccessInfoHeap.remove(userId);
        usersRefreshInfoHeap.remove(userId);
    }

    @Override
    public void removeAllDeviceByCurrentUser() {
        try {
            removeAllDeviceByUserId(AUtils.getCurrentHttpMeta().getToken().getUserId());
        } catch (Exception ignored) {
        }
    }

    @Override
    public void removeDeviceByUserIdAndAccessTokenId(Object userId, String accessTokenId) {
        Map<String, AccessInfo> accessInfoHeap = usersAccessInfoHeap.get(userId);
        if (accessInfoHeap != null) {
            accessInfoHeap.remove(accessTokenId);
        }
        inertDeletion(userId);
    }

    @Override
    public void removeDeviceByCurrentUserAndAccessTokenId(String accessTokenId) {
        try {
            removeDeviceByUserIdAndAccessTokenId(AUtils.getCurrentHttpMeta().getToken().getUserId(), accessTokenId);
        } catch (Exception ignored) {
        }

    }

    private void removeUser(Object userId, String deviceId, String deviceType) {
        Map<String, AccessInfo> accessInfoHeap = usersAccessInfoHeap.computeIfAbsent(userId, k -> new ConcurrentHashMap<>());
        Map<String, RefreshInfo> refreshInfoHeap = usersRefreshInfoHeap.computeIfAbsent(userId, k -> new ConcurrentHashMap<>());

        if (deviceId != null) {
            accessInfoHeap.entrySet().removeIf(entry -> StringUtils.equals(getRefreshInfo(refreshInfoHeap, entry.getValue()).getId(), deviceId));
            refreshInfoHeap.entrySet().removeIf(entry -> StringUtils.equals(entry.getValue().getId(), deviceId));
        }
        if (deviceType != null) {
            accessInfoHeap.entrySet().removeIf(entry -> StringUtils.equals(getRefreshInfo(refreshInfoHeap, entry.getValue()).getType(), deviceType));
            refreshInfoHeap.entrySet().removeIf(entry -> StringUtils.equals(entry.getValue().getType(), deviceType));
        }
        inertDeletion(userId);
    }

    @Override
    public void removeDeviceByUserIdAndDeviceType(Object userId, String deviceType) {
        removeUser(userId, null, deviceType);
    }

    @Override
    public void removeDeviceByCurrentUserAndDeviceType(String deviceType) {
        try {
            removeDeviceByUserIdAndDeviceType(AUtils.getCurrentHttpMeta().getToken().getUserId(), deviceType);
        } catch (Exception ignored) {
        }

    }

    @Override
    public void removeDeviceByUserIdAndDeviceId(Object userId, String deviceId) {
        removeUser(userId, deviceId, null);
    }

    @Override
    public void removeDeviceByCurrentUserAndDeviceId(String deviceId) {
        try {
            removeDeviceByUserIdAndDeviceId(AUtils.getCurrentHttpMeta().getToken().getUserId(), deviceId);
        } catch (Exception ignored) {
        }
    }

    @Override
    public Device getDevice(Object userId, String deviceType, String deviceId) {
        Map<String, AccessInfo> accessInfoHeap = usersAccessInfoHeap.get(userId);
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
    public Object[] listUserId() {
        return usersAccessInfoHeap.keySet().toArray();
    }

    @Override
    public Device[] listDevicesByUserId(Object userId) {
        if (!inertDeletion(userId)) return null;
        Map<String, RefreshInfo> refreshInfoHeap = usersRefreshInfoHeap.get(userId);
        if (refreshInfoHeap == null) return null;
        return usersAccessInfoHeap.get(userId).values().stream().map(v -> (Device) refreshInfoHeap.get(v.getRefreshTokenId())).toArray(Device[]::new);
    }

    @Override
    public Device[] listDevicesForCurrentUser() {
        try {
            return listDevicesByUserId(AUtils.getCurrentHttpMeta().getToken().getUserId());
        } catch (Exception ignored) {
            return new Device[0];
        }
    }

    @Override
    public Object[] listActiveUsers(long ms) {
        long now = TimeUtils.nowTime();

        return usersRefreshInfoHeap.keySet().stream()
                .filter(userId ->
                        usersRefreshInfoHeap.get(userId).values().stream().anyMatch(device -> (now - device.getLastRequestTime().getTime()) < ms)
                ).toArray();
    }

    @Override
    public Device[] listActiveUserDevices(Object userId, long ms) {
        long now = TimeUtils.nowTime();

        Map<String, RefreshInfo> refreshInfoHeap = usersRefreshInfoHeap.get(userId);
        if (refreshInfoHeap == null) return new Device[0];

        return refreshInfoHeap.values().stream()
                .filter(refreshInfo -> (now - refreshInfo.getLastRequestTime().getTime()) < ms)
                .map(RefreshInfo::getDevice)
                .toArray(Device[]::new);
    }

    @Override
    public void request() {
        try {
            HttpMeta currentHttpMeta = AUtils.getCurrentHttpMeta();
            Token token = currentHttpMeta.getToken();
            AccessInfo accessInfo = usersAccessInfoHeap.get(token.getUserId()).get(token.getTokenId());
            Device device = usersRefreshInfoHeap.get(token.getUserId()).get(accessInfo.getRefreshTokenId());
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
        Map<String, AccessInfo> accessInfoHeap = usersAccessInfoHeap.get(userId);
        Map<String, RefreshInfo> refreshInfoHeap = usersRefreshInfoHeap.get(userId);
        long now = TimeUtils.nowTime();

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
