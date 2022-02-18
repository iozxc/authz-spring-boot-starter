package cn.omisheep.authz.core.auth.deviced;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.tk.Token;
import cn.omisheep.authz.core.tk.TokenPair;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.authz.core.util.TimeUtils;
import cn.omisheep.commons.util.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Set;
import java.util.concurrent.TimeUnit;

import static cn.omisheep.authz.core.auth.deviced.DeviceConfig.isSupportMultiDevice;
import static cn.omisheep.authz.core.auth.deviced.DeviceConfig.isSupportMultiUserForSameDeviceType;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
public class UserDevicesDictByCache implements UserDevicesDict {

    private final AuthzProperties properties;
    private final Cache cache;

    public UserDevicesDictByCache(AuthzProperties properties, Cache cache) {
        this.properties = properties;
        this.cache = cache;
    }

    @Override
    public int userStatus(Object userId, String deviceType, String deviceId, String accessTokenId) {
        Set<String> accessInfoKeys = cache.keys(acKey(userId, "*"));
        Set<String> refreshInfoKeys = cache.keys(rfKey(userId, "*"));

        boolean hasTargetDeviceInfo = false;
        if (!refreshInfoKeys.isEmpty()) {
            hasTargetDeviceInfo = refreshInfoKeys.stream().anyMatch(rfKey -> {
                Device deviceInfo = (Device) cache.get(rfKey);
                return equalsDeviceByTypeAndId(deviceInfo, deviceType, deviceId);
            });
        }
        if (accessInfoKeys.isEmpty()) {
            if (refreshInfoKeys.isEmpty() || !hasTargetDeviceInfo) return 2;
            return 1;
        }

        // 于登录设备同类型，同ID的设备acID
        String acKey = accessInfoKeys.stream().filter(key -> {
            AccessInfo accessInfo = (AccessInfo) cache.get(key);
            if (accessInfo == null) return true;
            return equalsDeviceByTypeAndId((Device) cache.get(rfKey(userId, accessInfo.getRefreshTokenId())), deviceType, deviceId);
        }).findFirst().orElse(null);

        if (acKey == null) { // 如果没有这个设备
            if (!isSupportMultiDevice) { // 如果不允许多设备登录，说明现在存在其他设备。
                return 3;
            } else {
                if (!hasTargetDeviceInfo) return 2; // 如果允许多设备登录 则说明不存在该设备 返回重新登录
                return 1;
            }
        }

        // 3）如果设备存在，但是tokenId不是自己的，则在别处登录
        if (!StringUtils.equals(acKey, acKey(userId, accessTokenId))) {
            return 3;
        }
        return 0;
    }

    @Override
    public void addUser(Object userId, TokenPair tokenPair, Device device) {
        Set<String> accessInfoKeys = cache.keys(acKey(userId, "*"));
        Set<String> refreshInfoKeys = cache.keys(rfKey(userId, "*"));

        if (!isSupportMultiDevice) {
            cache.del(accessInfoKeys);
            cache.del(refreshInfoKeys);
        } else {
            if (!isSupportMultiUserForSameDeviceType) {
                accessInfoKeys.removeIf(key -> {
                    AccessInfo accessInfo = (AccessInfo) cache.get(key);
                    if (accessInfo == null) return true;
                    String rtid = accessInfo.getRefreshTokenId();
                    if (rtid != null) {
                        String rfKey = rfKey(userId, rtid);
                        Device deviceInfo = (Device) cache.get(rfKey);
                        if (deviceInfo == null || equalsDeviceByTypeOrId(deviceInfo, device)) {
                            cache.del(key);
                            cache.del(rfKey);
                            refreshInfoKeys.remove(rfKey);
                            return true;
                        }
                    }
                    return false;
                });

                refreshInfoKeys.removeIf(key -> {
                    Device deviceInfo = (Device) cache.get(key);
                    if (deviceInfo == null || equalsDeviceByTypeOrId(deviceInfo, device)) {
                        cache.del(key);
                        return true;
                    }
                    return false;
                });
            } else {
                accessInfoKeys.removeIf(key -> {
                    AccessInfo accessInfo = (AccessInfo) cache.get(key);
                    if (accessInfo == null) return true;
                    String rtid = accessInfo.getRefreshTokenId();
                    if (rtid != null) {
                        String rfKey = rfKey(userId, rtid);
                        Device deviceInfo = (Device) cache.get(rfKey);
                        if (deviceInfo == null || equalsDeviceById(deviceInfo, device)) {
                            cache.del(key);
                            cache.del(rfKey);
                            refreshInfoKeys.remove(rfKey);
                            return true;
                        }
                    }
                    return false;
                });

                refreshInfoKeys.removeIf(key -> {
                    Device deviceInfo = (Device) cache.get(key);
                    if (deviceInfo == null || equalsDeviceById(deviceInfo, device)) {
                        cache.del(key);
                        return true;
                    }
                    return false;
                });
            }
        }

        AccessInfo accessInfo = new AccessInfo().setRefreshTokenId(tokenPair.getRefreshToken().getTokenId());
        RefreshInfo refreshInfo = new RefreshInfo().setDevice(device);

        long l = TimeUtils.parseTimeValueTotal(properties.getToken().getLiveTime(), properties.getToken().getRefreshTime(), "10s");
        cache.set(acKey(userId, tokenPair), accessInfo, properties.getToken().getLiveTime());
        cache.set(rfKey(userId, tokenPair), refreshInfo, l, TimeUnit.MILLISECONDS);
    }

    @Override
    public boolean refreshUser(TokenPair tokenPair) {
        if (tokenPair == null) return false;
        Token accessToken = tokenPair.getAccessToken();
        Object userId = accessToken.getUserId();
        String rfKey = rfKey(userId, tokenPair);
        if (!cache.hasKey(rfKey)) return false;

        Set<String> accessInfoKeys = cache.keys(acKey(userId, "*"));
        String k = null;
        for (String key : accessInfoKeys) {
            Device deviceInfo = getDeviceOe(userId, key);
            if (deviceInfo == null) continue;
            if (StringUtils.equals(accessToken.getDeviceType(), deviceInfo.getType())
                    && StringUtils.equals(accessToken.getDeviceId(), deviceInfo.getId())) {
                k = key;
                break;
            }
        }

        if (k != null) cache.del(k);
        Device de = (Device) cache.get(rfKey);
        if (de != null) {
            HttpMeta httpMeta = (HttpMeta) ((ServletRequestAttributes) (RequestContextHolder.currentRequestAttributes())).getRequest().getAttribute("AU_HTTP_META");
            de.setIp(httpMeta.getIp());
            de.setLastRequestTime(TimeUtils.now());
            cache.set(rfKey, de);
        }
        AccessInfo accessInfo = new AccessInfo().setRefreshTokenId(tokenPair.getRefreshToken().getTokenId());
        cache.set(acKey(userId, tokenPair), accessInfo, properties.getToken().getLiveTime());
        return true;
    }

    @Override
    public void removeAllDeviceByUserId(Object userId) {
        Set<String> acKeys = cache.keys(acKey(userId, "*"));
        Set<String> rfKeys = cache.keys(rfKey(userId, "*"));
        cache.del(acKeys);
        cache.del(rfKeys);
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
        cache.del(acKey(userId, accessTokenId));
    }

    @Override
    public void removeDeviceByCurrentUserAndAccessTokenId(String accessTokenId) {
        try {
            removeDeviceByUserIdAndAccessTokenId(AUtils.getCurrentHttpMeta().getToken().getUserId(), accessTokenId);
        } catch (Exception ignored) {
        }
    }

    private void removeUser(Object userId, String deviceId, String deviceType) {
        Set<String> acKeys = cache.keys(acKey(userId, "*"));
        Set<String> rfKeys = cache.keys(rfKey(userId, "*"));

        if (deviceId != null) {
            acKeys.removeIf(acKey -> {
                Device deviceOe = getDeviceOe(userId, acKey);
                if (deviceOe != null) {
                    if (equalsDeviceById(deviceOe, deviceId)) {
                        cache.del(acKey);
                        return true;
                    } else {
                        return false;
                    }
                }
                return true;
            });
            rfKeys.removeIf(rfKey -> {
                Device device = (Device) cache.get(rfKey);
                if (!device.isEmpty()) {
                    if (equalsDeviceById(device, deviceId)) {
                        cache.del(rfKey);
                        return true;
                    } else {
                        return false;
                    }
                }
                return true;
            });
        }

        if (deviceType != null) {
            acKeys.removeIf(acKey -> {
                Device deviceOe = getDeviceOe(userId, acKey);
                if (deviceOe != null) {
                    if (equalsDeviceByType(deviceOe, deviceType)) {
                        cache.del(acKey);
                        return true;
                    } else {
                        return false;
                    }
                }
                return true;
            });
            rfKeys.removeIf(rfKey -> {
                Device device = (Device) cache.get(rfKey);
                if (!device.isEmpty()) {
                    if (equalsDeviceByType(device, deviceType)) {
                        cache.del(rfKey);
                        return true;
                    } else {
                        return false;
                    }
                }
                return true;
            });
        }
    }

    private Device getDeviceOe(Object userId, String acKey) {
        AccessInfo accessInfo = (AccessInfo) cache.get(acKey);
        String rtid = accessInfo.getRefreshTokenId();
        if (rtid != null) {
            String rfKey = rfKey(userId, rtid);
            return (Device) cache.get(rfKey);
        }
        return null;
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
        Set<String> acKeys = cache.keys(acKey(userId, "*"));

        if (CollectionUtils.isNotEmpty(acKeys)) {
            for (String acKey : acKeys) {
                Device deviceOe = getDeviceOe(userId, acKey);
                if (deviceOe != null) {
                    if (equalsDeviceByTypeAndId(deviceOe, deviceType, deviceId)) {
                        return deviceOe;
                    }
                }
            }
        }
        return null;
    }

    @Override
    public Object[] listUserId() {
        Set<String> keys = cache.keys(acKey("*", "*"));
        return keys.stream().map(key -> key.split(":")[2]).distinct().toArray();
    }

    @Override
    public Device[] listDevicesByUserId(Object userId) {
        Set<String> keys = cache.keys(acKey(userId, "*"));
        return keys.stream().map(key -> getDeviceOe(userId, key)).toArray(Device[]::new);
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
        Set<String> rfKeys = cache.keys(rfKey("*", "*"));
        return rfKeys.stream().filter(rfKey -> {
            Device device = (Device) cache.get(rfKey);
            if (device != null) return (now - device.getLastRequestTime().getTime()) < ms;
            return false;
        }).map(key -> key.split(":")[2]).distinct().toArray();
    }

    @Override
    public Device[] listActiveUserDevices(Object userId, long ms) {
        long now = TimeUtils.nowTime();
        Set<String> rfKeys = cache.keys(rfKey(userId, "*"));
        return rfKeys.stream().map(rfKey -> (Device) cache.get(rfKey))
                .filter(device -> (now - device.getLastRequestTime().getTime()) < ms)
                .toArray(Device[]::new);
    }

    @Override
    public void request() {
        try {
            HttpMeta currentHttpMeta = AUtils.getCurrentHttpMeta();
            Token token = currentHttpMeta.getToken();
            String acKey = acKey(token.getUserId(), token.getTokenId());
            Object o = cache.get(acKey);
            if (o == null) return;
            String rtid = ((AccessInfo) o).getRefreshTokenId();
            if (rtid != null) {
                String rfKey = rfKey(token.getUserId(), rtid);
                Device device = (Device) cache.get(rfKey);
                if (!device.isEmpty()) {
                    device.setIp(currentHttpMeta.getIp());
                    device.setLastRequestTime(TimeUtils.now());
                    cache.set(rfKey, device);
                }
            }
        } catch (Exception ignored) {
        }
    }

    private String acKey(Object userId, String tokenId) {
        return "au:usersAccessInfo:" + userId + ":" + tokenId;
    }

    private String rfKey(Object userId, String tokenId) {
        return "au:usersRefreshInfo:" + userId + ":" + tokenId;
    }

    private String acKey(Object userId, TokenPair tokenPair) {
        return acKey(userId, tokenPair.getAccessToken().getTokenId());
    }

    private String rfKey(Object userId, TokenPair tokenPair) {
        return rfKey(userId, tokenPair.getRefreshToken().getTokenId());
    }

    private boolean equalsDeviceByTypeOrId(Device device, Device otherDevice) {
        return StringUtils.equals(device.getType(), otherDevice.getType())
                || (device.getId() != null && StringUtils.equals(device.getId(), otherDevice.getId())); // null时不参与匹配
    }

    private boolean equalsDeviceByTypeAndId(Device device, String deviceType, String deviceId) {
        return StringUtils.equals(device.getType(), deviceType)
                && StringUtils.equals(device.getId(), deviceId);
    }

    private boolean equalsDeviceById(Device device, Device otherDevice) {
        return equalsDeviceById(device, otherDevice.getId());
    }

    private boolean equalsDeviceById(Device device, String deviceId) {
        return device.getId() != null && StringUtils.equals(device.getId(), deviceId);
    }

    private boolean equalsDeviceByType(Device device, String deviceType) {
        return StringUtils.equals(device.getType(), deviceType);
    }

}
