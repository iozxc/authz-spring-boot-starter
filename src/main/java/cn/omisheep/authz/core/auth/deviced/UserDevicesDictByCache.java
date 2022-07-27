package cn.omisheep.authz.core.auth.deviced;

import cn.omisheep.authz.AuHelper;
import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.config.Constants;
import cn.omisheep.authz.core.tk.Token;
import cn.omisheep.authz.core.tk.TokenPair;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.commons.util.Async;
import cn.omisheep.commons.util.CollectionUtils;
import cn.omisheep.commons.util.TimeUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Slf4j
public class UserDevicesDictByCache implements UserDevicesDict {

    private final AuthzProperties properties;
    private final Cache           cache;

    public UserDevicesDictByCache(AuthzProperties properties, Cache cache) {
        this.properties = properties;
        this.cache      = cache;
    }

    @Override
    public int userStatus(Token accessToken) {
        Object userId        = accessToken.getUserId();
        String deviceType    = accessToken.getDeviceType();
        String deviceId      = accessToken.getDeviceId();
        String accessTokenId = accessToken.getTokenId();
        String clientId      = accessToken.getClientId();

        Set<String> refreshInfoKeys = cache.keysAndLoad(rfKey(userId, Constants.WILDCARD));

        CompletableFuture<AccessInfo> acSupply = Async.supply(
                () -> cache.get(acKey(userId, accessTokenId), AccessInfo.class));

        boolean hasTargetDeviceInfo = false;
        if (!refreshInfoKeys.isEmpty()) {
            Map<String, RefreshInfo> refreshInfoMap = cache.get(refreshInfoKeys, RefreshInfo.class);
            hasTargetDeviceInfo = refreshInfoMap.entrySet().stream()
                    .anyMatch(e -> equalsDeviceByTypeAndId(e.getValue().getDevice(), deviceType, deviceId));

        }
        if (!hasTargetDeviceInfo) return REQUIRE_LOGIN;

        AccessInfo accessInfo = acSupply.join();
        if (accessInfo == null) return LOGIN_EXCEPTION;

        return SUCCESS;
    }

    @Override
    public boolean addUser(TokenPair tokenPair, HttpMeta httpMeta) {
        if (tokenPair == null || tokenPair.getAccessToken() == null || tokenPair.getRefreshToken() == null)
            return false;

        Token                      accessToken = tokenPair.getAccessToken();
        Object                     userId      = accessToken.getUserId();
        String                     deviceType  = accessToken.getDeviceType();
        String                     deviceId    = accessToken.getDeviceId();
        String                     clientId    = tokenPair.getAccessToken().getClientId();
        AuthzProperties.UserConfig userConfig  = usersConfig.getOrDefault(userId, properties.getUser());

        Device      device      = new DefaultDevice().setDeviceType(deviceType).setDeviceId(deviceId);
        AccessInfo  accessInfo  = new AccessInfo().setRefreshTokenId(tokenPair.getRefreshToken().getTokenId());
        RefreshInfo refreshInfo = new RefreshInfo().setDevice(device);
        refreshInfo.setIp(httpMeta.getIp()).setLastRequestTime(httpMeta.getNow());

        long rfLiveTime = TimeUtils.parseTimeValueTotal(properties.getToken().getAccessTime(),
                                                        properties.getToken().getRefreshTime(), "10s");
        String acKey = acKey(userId, tokenPair);
        String rfKey = rfKey(userId, tokenPair);
        boolean b = Async.joinAndCheck(Async.combine(
                () -> cache.set(acKey, accessInfo, properties.getToken().getAccessTime()),
                () -> cache.set(rfKey, refreshInfo, rfLiveTime, TimeUnit.MILLISECONDS)));

        if (!b) return false;

        Async.run(() -> { // @since 1.2.0 优化了登录逻辑，略微提速

            Set<String> delKeys         = new HashSet<>();
            Set<String> accessInfoKeys  = new HashSet<>();
            Set<String> refreshInfoKeys = new HashSet<>();
            Async.combine(() -> accessInfoKeys.addAll(cache.keysAndLoad(acKey(userId, Constants.WILDCARD))),
                          () -> refreshInfoKeys.addAll(cache.keysAndLoad(rfKey(userId, Constants.WILDCARD))))
                    .join(); // 获得所有的key access和refresh

            Map<String, RefreshInfo> refreshInfoMap = cache.get(refreshInfoKeys, RefreshInfo.class);
            Map<String, AccessInfo>  accessInfoMap  = cache.get(accessInfoKeys, AccessInfo.class);

            // 删除同type同id
            d(Integer.MIN_VALUE, refreshInfoMap, accessInfoMap, delKeys,
              e -> StringUtils.equals(deviceType, e.getValue().getDeviceType())
                      && StringUtils.equals(deviceId, e.getValue().getDeviceId()));

            // 登录设备总数
            if (userConfig.getMaximumTotalDevice() != -1 && userConfig.getMaximumTotalDevice() > 0 && refreshInfoKeys.size() > userConfig.getMaximumTotalDevice()) {
                d(userConfig.getMaximumTotalDevice(), refreshInfoMap, accessInfoMap, delKeys, e -> true);
            }

            // 同类型设备最大登录数量
            if (userConfig.getMaximumSameTypeDeviceCount() != -1) {
                d(userConfig.getMaximumSameTypeDeviceCount(), refreshInfoMap, accessInfoMap, delKeys,
                  e -> StringUtils.equals(e.getValue().getDevice().getDeviceType(), deviceType));
            }

            List<DeviceCountInfo> typesTotal = userConfig.getTypesTotal();
            // 每[一种、多种]设备类型设置[共同]的最大登录数（最小为1）
            if (typesTotal != null && !typesTotal.isEmpty()) {
                for (DeviceCountInfo deviceCountInfo : typesTotal) {
                    if (deviceCountInfo.getTypes().isEmpty()) continue;
                    d(deviceCountInfo.getTotal(), refreshInfoMap, accessInfoMap, delKeys,
                      e -> deviceCountInfo.getTypes().contains(e.getValue().getDeviceType()));
                }
            }

            if (!delKeys.isEmpty()) {
                delKeys.remove(rfKey);
                delKeys.remove(acKey);
                cache.del(delKeys);
                cache.del(acKey(userId, Constants.WILDCARD));
                cache.del(rfKey(userId, Constants.WILDCARD));
            }
        });

        return true;
    }


    private void d(int max, Map<String, RefreshInfo> refreshInfoMap, Map<String, AccessInfo> accessInfoMap,
                   Set<String> delKeys, Predicate<? super Map.Entry<String, RefreshInfo>> predicate) {
        HashSet<String> _del = new HashSet<>();
        List<Map.Entry<String, RefreshInfo>> arr1 = refreshInfoMap.entrySet().stream().filter(predicate).sorted(
                (v1, v2) -> Math.toIntExact(
                        v1.getValue().getLastRequestTimeLong() - v2.getValue().getLastRequestTimeLong())).collect(
                Collectors.toList());
        int deleteCount = arr1.size() - max;
        if (deleteCount <= 0) return;

        for (Map.Entry<String, RefreshInfo> v : arr1.subList(0, Math.min(deleteCount, arr1.size()))) {
            refreshInfoMap.remove(v.getKey());
            delKeys.add(v.getKey());
            _del.add(v.getKey().substring(v.getKey().lastIndexOf(":") + 1));
        }

        accessInfoMap.entrySet().removeIf(e -> {
            boolean b = _del.stream().anyMatch(v -> v.equals(e.getValue().getRefreshTokenId()));
            if (b) delKeys.add(e.getKey());
            return b;
        });
    }

    @Override
    public boolean refreshUser(TokenPair tokenPair) {
        if (tokenPair == null) return false;
        Token  accessToken = tokenPair.getAccessToken();
        Object userId      = accessToken.getUserId();
        String rfKey       = rfKey(userId, tokenPair);
        if (cache.notKey(rfKey)) return false;

        String k = null;
        for (String key : cache.keysAndLoad(acKey(userId, Constants.WILDCARD))) {
            Device deviceInfo = getDeviceOe(userId, key);
            if (deviceInfo == null) continue;
            if (StringUtils.equals(accessToken.getDeviceType(), deviceInfo.getDeviceType()) && StringUtils.equals(
                    accessToken.getDeviceId(), deviceInfo.getDeviceId())) {
                k = key;
                break;
            }
        }

        if (k != null) cache.del(k);

        AccessInfo accessInfo = new AccessInfo().setRefreshTokenId(tokenPair.getRefreshToken().getTokenId());
        Async.run(() -> {
            cache.del(acKey(userId, Constants.WILDCARD));
            cache.del(rfKey(userId, Constants.WILDCARD));
        });
        cache.set(acKey(userId, tokenPair), accessInfo, properties.getToken().getAccessTime());
        return true;
    }

    @Override
    public void removeDeviceByUserIdAndAccessTokenId(Object userId, String accessTokenId) {
        cache.del(acKey(userId, accessTokenId), acKey(userId, Constants.WILDCARD));
    }

    @Override
    public void removeAllDeviceByUserId(Object userId) {
        HashSet<String> keys = new HashSet<>();
        keys.addAll(cache.keys(acKey(userId, Constants.WILDCARD)));
        keys.addAll(cache.keys(rfKey(userId, Constants.WILDCARD)));
        keys.add(acKey(userId, Constants.WILDCARD));
        keys.add(rfKey(userId, Constants.WILDCARD));
        cache.del(keys);
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
        Set<String>     acKeys = cache.keysAndLoad(acKey(userId, Constants.WILDCARD));
        Set<String>     rfKeys = cache.keysAndLoad(rfKey(userId, Constants.WILDCARD));
        HashSet<String> keys   = new HashSet<>();
        keys.add(acKey(userId, Constants.WILDCARD));
        keys.add(rfKey(userId, Constants.WILDCARD));

        if (deviceType != null) {
            acKeys.removeIf(acKey -> {
                Device deviceOe = getDeviceOe(userId, acKey);
                if (deviceOe != null) {
                    if (equalsDeviceByType(deviceOe, deviceType)) {
                        keys.add(acKey);
                        return true;
                    } else {
                        return false;
                    }
                }
                return true;
            });
            rfKeys.removeIf(rfKey -> {
                Device device = (Device) cache.get(rfKey);
                if (device == null || !device.isEmpty()) {
                    if (equalsDeviceByType(device, deviceType)) {
                        keys.add(rfKey);
                        return true;
                    } else {
                        return false;
                    }
                }
                return true;
            });
        }

        cache.del(keys);
    }

    private void removeDevice(Object userId, String deviceType, String deviceId) {
        Set<String>     acKeys = cache.keysAndLoad(acKey(userId, Constants.WILDCARD));
        Set<String>     rfKeys = cache.keysAndLoad(rfKey(userId, Constants.WILDCARD));
        HashSet<String> keys   = new HashSet<>();
        keys.add(acKey(userId, Constants.WILDCARD));
        keys.add(rfKey(userId, Constants.WILDCARD));

        if (deviceType != null) {
            acKeys.removeIf(acKey -> {
                Device deviceOe = getDeviceOe(userId, acKey);
                if (deviceOe != null) {
                    if (equalsDeviceByTypeAndId(deviceOe, deviceType, deviceId)) {
                        keys.add(acKey);
                        return true;
                    } else {
                        return false;
                    }
                }
                return true;
            });
            rfKeys.removeIf(rfKey -> {
                Device device = (Device) cache.get(rfKey);
                if (device == null || !device.isEmpty()) {
                    if (equalsDeviceByTypeAndId(device, deviceType, deviceId)) {
                        keys.add(rfKey);
                        return true;
                    } else {
                        return false;
                    }
                }
                return true;
            });
        }

        cache.del(keys);
    }

    private Device getDeviceOe(Object userId, String acKey) {
        AccessInfo accessInfo = (AccessInfo) cache.get(acKey);
        if (accessInfo == null) return null;
        String rtid = accessInfo.getRefreshTokenId();
        if (rtid != null) {
            String rfKey = rfKey(userId, rtid);
            return (Device) cache.get(rfKey);
        }
        return null;
    }

    @Override
    public Device getDevice(Object userId, String deviceType, String deviceId) {
        Set<String> acKeys = cache.keysAndLoad(acKey(userId, Constants.WILDCARD));

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
    public List<Object> listUserId() {
        Set<String> keys = cache.keys(acKey(Constants.WILDCARD, Constants.WILDCARD));
        return keys.stream().map(key -> key.split(Constants.SEPARATOR)[2]).distinct().collect(Collectors.toList());
    }

    @Override
    public List<Device> listDevicesByUserId(Object userId) {
        Set<String> keys = cache.keysAndLoad(acKey(userId, Constants.WILDCARD));
        return keys.stream().map(key -> getDeviceOe(userId, key)).collect(Collectors.toList());
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
        long        now    = TimeUtils.nowTime();
        Set<String> rfKeys = cache.keysAndLoad(rfKey(Constants.WILDCARD, Constants.WILDCARD));
        return rfKeys.stream().filter(rfKey -> {
            Device device = (Device) cache.get(rfKey);
            if (device != null) return (now - device.getLastRequestTime().getTime()) < ms;
            return false;
        }).map(key -> key.split(Constants.SEPARATOR)[2]).distinct().collect(Collectors.toList());
    }

    @Override
    public List<Device> listActiveUserDevices(Object userId, long ms) {
        long        now    = TimeUtils.nowTime();
        Set<String> rfKeys = cache.keysAndLoad(rfKey(userId, Constants.WILDCARD));
        return rfKeys.stream().map(rfKey -> (Device) cache.get(rfKey)).filter(
                device -> device != null && ((now - device.getLastRequestTime().getTime()) < ms)).collect(
                Collectors.toList());
    }

    @Override
    public void request() {
        try {
            HttpMeta currentHttpMeta = AUtils.getCurrentHttpMeta();
            Token    token           = currentHttpMeta.getToken();
            String   acKey           = acKey(token.getUserId(), token.getTokenId());
            Object   o               = cache.get(acKey);
            if (o == null) return;
            String rtid = ((AccessInfo) o).getRefreshTokenId();
            if (rtid != null) {
                Async.run(() -> {
                    String rfKey = rfKey(token.getUserId(), rtid);
                    Device d     = (Device) cache.get(rfKey);
                    if (d != null) {
                        d.setLastRequestTime(currentHttpMeta.getNow());
                        d.setIp(currentHttpMeta.getIp());
                        cache.set(rfKey, d);
                    }
                });
            }
        } catch (Exception ignored) {
        }
    }

    @Override
    public void deviceClean(Object userId) {
        String  retainAcKey = null;
        String  retainRfKey = null;
        boolean ok          = false;
        if (AuHelper.isLogin()) {
            Token      token      = AuHelper.getToken();
            String     acKey      = acKey(userId, token.getTokenId());
            AccessInfo accessInfo = cache.get(acKey, AccessInfo.class);
            if (accessInfo != null) {
                retainAcKey = acKey;
                retainRfKey = rfKey(userId, accessInfo.getRefreshTokenId());
                ok          = true;
            }
        }
        boolean finalOk          = ok;
        String  finalRetainAcKey = retainAcKey;
        String  finalRetainRfKey = retainRfKey;
        Async.run(() -> {
            AuthzProperties.UserConfig userConfig = usersConfig.getOrDefault(userId, properties.getUser());

            Set<String> delKeys         = new HashSet<>();
            Set<String> accessInfoKeys  = new HashSet<>();
            Set<String> refreshInfoKeys = new HashSet<>();
            Async.combine(() -> accessInfoKeys.addAll(cache.keysAndLoad(acKey(userId, Constants.WILDCARD))),
                          () -> refreshInfoKeys.addAll(cache.keysAndLoad(rfKey(userId, Constants.WILDCARD))))
                    .join(); // 获得所有的key access和refresh

            if (finalOk) {
                accessInfoKeys.remove(finalRetainAcKey);
                refreshInfoKeys.remove(finalRetainRfKey);
            }
            Map<String, RefreshInfo> refreshInfoMap = cache.get(refreshInfoKeys, RefreshInfo.class);
            Map<String, AccessInfo>  accessInfoMap  = cache.get(accessInfoKeys, AccessInfo.class);

            List<String> deviceTypes = refreshInfoMap.values().stream().map(DefaultDevice::getDeviceType).collect(
                    Collectors.toList());
            // 登录设备总数
            if (userConfig.getMaximumTotalDevice() != -1 && userConfig.getMaximumTotalDevice() > 0 && refreshInfoKeys.size() > userConfig.getMaximumTotalDevice()) {
                int max = userConfig.getMaximumTotalDevice();
                if (finalOk) max--;
                d(max, refreshInfoMap, accessInfoMap, delKeys, e -> true);
            }

            // 同类型设备最大登录数量
            if (userConfig.getMaximumSameTypeDeviceCount() != -1) {
                int max = userConfig.getMaximumSameTypeDeviceCount();
                if (finalOk) max--;
                for (String deviceType : deviceTypes) {
                    d(max, refreshInfoMap, accessInfoMap, delKeys,
                      e -> StringUtils.equals(e.getValue().getDevice().getDeviceType(), deviceType));
                }
            }

            List<DeviceCountInfo> typesTotal = userConfig.getTypesTotal();
            // 每[一种、多种]设备类型设置[共同]的最大登录数（最小为1）
            if (typesTotal != null && !typesTotal.isEmpty()) {
                for (DeviceCountInfo deviceCountInfo : typesTotal) {
                    if (deviceCountInfo.getTypes().isEmpty()) continue;
                    int max = deviceCountInfo.getTotal();
                    if (finalOk) max--;
                    d(max, refreshInfoMap, accessInfoMap, delKeys,
                      e -> deviceCountInfo.getTypes().contains(e.getValue().getDeviceType()));
                }
            }

            if (!delKeys.isEmpty()) {
                cache.del(delKeys);
                cache.del(acKey(userId, Constants.WILDCARD));
                cache.del(rfKey(userId, Constants.WILDCARD));
            }
        });
    }

    private String requestKey(Object userId, String rfKey) {
        return Constants.DEVICE_REQUEST_INFO_KEY_PREFIX.get() + userId + Constants.SEPARATOR + rfKey.split(
                Constants.SEPARATOR)[3];
    }

    private String acKey(Object userId, String tokenId) {
        return Constants.ACCESS_INFO_KEY_PREFIX.get() + userId + Constants.SEPARATOR + tokenId;
    }

    private String rfKey(Object userId, String tokenId) {
        return Constants.REFRESH_INFO_KEY_PREFIX.get() + userId + Constants.SEPARATOR + tokenId;
    }

    private String acKey(Object userId, TokenPair tokenPair) {
        return acKey(userId, tokenPair.getAccessToken().getTokenId());
    }

    private String rfKey(Object userId, TokenPair tokenPair) {
        return rfKey(userId, tokenPair.getRefreshToken().getTokenId());
    }

    private boolean equalsDeviceByTypeOrId(Device device, Device otherDevice) {
        if (device == null) return false;
        return StringUtils.equals(device.getDeviceType(),
                                  otherDevice.getDeviceType()) || (device.getDeviceId() != null && StringUtils.equals(
                device.getDeviceId(), otherDevice.getDeviceId())); // null时不参与匹配
    }

    private boolean equalsDeviceByTypeAndId(Device device, String deviceType, String deviceId) {
        if (device == null) return false;
        return StringUtils.equals(device.getDeviceType(), deviceType) && StringUtils.equals(device.getDeviceId(),
                                                                                            deviceId);
    }

    private boolean equalsDeviceById(Device device, Device otherDevice) {
        if (device == null) return false;
        return equalsDeviceById(device, otherDevice.getDeviceId());
    }

    private boolean equalsDeviceById(Device device, String deviceId) {
        if (device == null) return false;
        return device.getDeviceId() != null && StringUtils.equals(device.getDeviceId(), deviceId);
    }

    private boolean equalsDeviceByType(Device device, String deviceType) {
        if (device == null) return false;
        return StringUtils.equals(device.getDeviceType(), deviceType);
    }

}
