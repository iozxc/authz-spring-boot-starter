package cn.omisheep.authz.core.auth.deviced;

import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.config.Constants;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.tk.Token;
import cn.omisheep.authz.core.tk.TokenPair;
import cn.omisheep.authz.core.util.AUtils;
import cn.omisheep.commons.util.Async;
import cn.omisheep.commons.util.CollectionUtils;
import cn.omisheep.commons.util.TimeUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static cn.omisheep.authz.core.auth.deviced.DeviceConfig.isSupportMultiDevice;
import static cn.omisheep.authz.core.auth.deviced.DeviceConfig.isSupportMultiUserForSameDeviceType;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Slf4j
public class UserDevicesDictByCache implements UserDevicesDict {

    private final AuthzProperties properties;
    private       Cache           _cache;
    private final Supplier<Cache> cache = () -> {
        if (_cache == null) _cache = AUtils.getBean(Cache.class);
        return _cache;
    };

    public UserDevicesDictByCache(AuthzProperties properties) {
        this.properties = properties;
    }

    @Override
    public int userStatus(Object userId, String deviceType, String deviceId, String accessTokenId) {
        CompletableFuture<Set<String>> acSupply        = Async.supply(() -> cache.get().keysAndLoad(acKey(userId, Constants.WILDCARD)));
        Set<String>                    refreshInfoKeys = cache.get().keysAndLoad(rfKey(userId, Constants.WILDCARD));

        boolean hasTargetDeviceInfo = false;
        if (!refreshInfoKeys.isEmpty()) {
            hasTargetDeviceInfo = refreshInfoKeys.stream()
                    .anyMatch(rfKey -> {
                        Device deviceInfo = (Device) cache.get().get(rfKey);
                        return equalsDeviceByTypeAndId(deviceInfo, deviceType, deviceId);
                    });
        }

        if (!hasTargetDeviceInfo) return REQUIRE_LOGIN;

        Set<String> accessInfoKeys = acSupply.join();
        if (accessInfoKeys.isEmpty()) {
            if (refreshInfoKeys.isEmpty()) return REQUIRE_LOGIN;
            return ACCESS_TOKEN_OVERDUE;
        }

        // ??????????????????????????????ID?????????acID
        String acKey = accessInfoKeys.stream()
                .filter(key -> {
                    AccessInfo accessInfo = (AccessInfo) cache.get().get(key);
                    if (accessInfo == null) return true;
                    return equalsDeviceByTypeAndId((Device) cache.get().get(rfKey(userId, accessInfo.getRefreshTokenId())), deviceType, deviceId);
                }).findFirst().orElse(null);

        if (acKey == null) { // ????????????????????????
            if (!isSupportMultiDevice) { // ??????????????????????????????????????????????????????????????????
                return LOGIN_EXCEPTION;
            } else {
                return ACCESS_TOKEN_OVERDUE;
            }
        }

        // 3??????????????????????????????tokenId????????????????????????????????????
        if (!StringUtils.equals(acKey, acKey(userId, accessTokenId))) {
            return LOGIN_EXCEPTION;
        }
        return SUCCESS;
    }

    @Override
    public boolean addUser(Object userId, TokenPair tokenPair, String deviceType, String deviceId, HttpMeta httpMeta) {
        Set<String>   accessInfoKeys  = new HashSet<>();
        Set<String>   refreshInfoKeys = new HashSet<>();
        DefaultDevice device          = new DefaultDevice();
        device.setType(deviceType).setId(deviceId);

        Async.combine(
                () -> accessInfoKeys.addAll(cache.get().keysAndLoad(acKey(userId, Constants.WILDCARD))),
                () -> refreshInfoKeys.addAll(cache.get().keysAndLoad(rfKey(userId, Constants.WILDCARD)))
        ).join();

        Set<String> delKeys = new HashSet<>();
        if (!isSupportMultiDevice) {
            delKeys.addAll(accessInfoKeys);
            delKeys.addAll(refreshInfoKeys);
        } else {
            if (!isSupportMultiUserForSameDeviceType) {
                accessInfoKeys.removeIf(key -> {
                    AccessInfo accessInfo = (AccessInfo) cache.get().get(key);
                    if (accessInfo == null) return true;
                    String rtid = accessInfo.getRefreshTokenId();
                    if (rtid == null) return false;
                    String rfKey      = rfKey(userId, rtid);
                    Device deviceInfo = (Device) cache.get().get(rfKey);
                    if (deviceInfo != null && !equalsDeviceByTypeOrId(deviceInfo, device)) return false;
                    delKeys.add(key);
                    delKeys.add(rfKey);
                    refreshInfoKeys.remove(rfKey);
                    return true;
                });

                refreshInfoKeys.removeIf(key -> {
                    Device deviceInfo = (Device) cache.get().get(key);
                    if (deviceInfo != null && !equalsDeviceByTypeOrId(deviceInfo, device)) return false;
                    delKeys.add(key);
                    delKeys.add(requestKey(userId, key));
                    return true;
                });
            } else {
                accessInfoKeys.removeIf(key -> {
                    AccessInfo accessInfo = (AccessInfo) cache.get().get(key);
                    if (accessInfo == null) return true;
                    String rtid = accessInfo.getRefreshTokenId();
                    if (rtid == null) return false;
                    String rfKey      = rfKey(userId, rtid);
                    Device deviceInfo = (Device) cache.get().get(rfKey);
                    if (deviceInfo != null && !equalsDeviceById(deviceInfo, device)) return false;
                    delKeys.add(key);
                    delKeys.add(rfKey);
                    refreshInfoKeys.remove(rfKey);
                    return true;
                });

                refreshInfoKeys.removeIf(key -> {
                    Device deviceInfo = (Device) cache.get().get(key);
                    if (deviceInfo != null && !equalsDeviceById(deviceInfo, device)) return false;
                    delKeys.add(key);
                    delKeys.add(requestKey(userId, key));
                    return true;
                });
            }
        }

        if (!delKeys.isEmpty()) Async.run(() -> cache.get().del(delKeys));

        AccessInfo  accessInfo  = new AccessInfo().setRefreshTokenId(tokenPair.getRefreshToken().getTokenId());
        RefreshInfo refreshInfo = new RefreshInfo().setDevice(device);
        refreshInfo.setIp(httpMeta.getIp()).setLastRequestTime(httpMeta.getNow());

        long rfLiveTime = TimeUtils.parseTimeValueTotal(properties.getToken().getAccessTime(), properties.getToken().getRefreshTime(), "10s");

        Async.run(() -> {
            cache.get().del(acKey(userId, Constants.WILDCARD));
            cache.get().del(rfKey(userId, Constants.WILDCARD));
        });


        return Async.joinAndCheck(
                Async.combine(
                        () -> cache.get().set(acKey(userId, tokenPair), accessInfo, properties.getToken().getAccessTime()),
                        () -> cache.get().set(rfKey(userId, tokenPair), refreshInfo, rfLiveTime, TimeUnit.MILLISECONDS)
                )
        );
    }

    @Override
    public boolean refreshUser(TokenPair tokenPair) {
        if (tokenPair == null) return false;
        Token  accessToken = tokenPair.getAccessToken();
        Object userId      = accessToken.getUserId();
        String rfKey       = rfKey(userId, tokenPair);
        if (cache.get().notKey(rfKey)) return false;

        String k = null;
        for (String key : cache.get().keysAndLoad(acKey(userId, Constants.WILDCARD))) {
            Device deviceInfo = getDeviceOe(userId, key);
            if (deviceInfo == null) continue;
            if (StringUtils.equals(accessToken.getDeviceType(), deviceInfo.getType())
                    && StringUtils.equals(accessToken.getDeviceId(), deviceInfo.getId())) {
                k = key;
                break;
            }
        }

        if (k != null) cache.get().del(k);

        AccessInfo accessInfo = new AccessInfo().setRefreshTokenId(tokenPair.getRefreshToken().getTokenId());
        Async.run(() -> {
            cache.get().del(acKey(userId, Constants.WILDCARD));
            cache.get().del(rfKey(userId, Constants.WILDCARD));
        });
        cache.get().set(acKey(userId, tokenPair), accessInfo, properties.getToken().getAccessTime());
        return true;
    }

    @Override
    public void removeDeviceByUserIdAndAccessTokenId(Object userId, String accessTokenId) {
        cache.get().del(acKey(userId, accessTokenId), acKey(userId, Constants.WILDCARD));
    }

    @Override
    public void removeAllDeviceByUserId(Object userId) {
        HashSet<String> keys = new HashSet<>();
        keys.addAll(cache.get().keys(acKey(userId, Constants.WILDCARD)));
        keys.addAll(cache.get().keys(rfKey(userId, Constants.WILDCARD)));
        keys.add(acKey(userId, Constants.WILDCARD));
        keys.add(rfKey(userId, Constants.WILDCARD));
        cache.get().del(keys);
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
        Set<String>     acKeys = cache.get().keysAndLoad(acKey(userId, Constants.WILDCARD));
        Set<String>     rfKeys = cache.get().keysAndLoad(rfKey(userId, Constants.WILDCARD));
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
                Device device = (Device) cache.get().get(rfKey);
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

        cache.get().del(keys);
    }

    private void removeDevice(Object userId, String deviceType, String deviceId) {
        Set<String>     acKeys = cache.get().keysAndLoad(acKey(userId, Constants.WILDCARD));
        Set<String>     rfKeys = cache.get().keysAndLoad(rfKey(userId, Constants.WILDCARD));
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
                Device device = (Device) cache.get().get(rfKey);
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

        cache.get().del(keys);
    }

    private Device getDeviceOe(Object userId, String acKey) {
        AccessInfo accessInfo = (AccessInfo) cache.get().get(acKey);
        if (accessInfo == null) return null;
        String rtid = accessInfo.getRefreshTokenId();
        if (rtid != null) {
            String rfKey = rfKey(userId, rtid);
            return (Device) cache.get().get(rfKey);
        }
        return null;
    }

    @Override
    public Device getDevice(Object userId, String deviceType, String deviceId) {
        Set<String> acKeys = cache.get().keysAndLoad(acKey(userId, Constants.WILDCARD));

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
        Set<String> keys = cache.get().keys(acKey(Constants.WILDCARD, Constants.WILDCARD));
        return keys.stream().map(key -> key.split(Constants.SEPARATOR)[2]).distinct().collect(Collectors.toList());
    }

    @Override
    public List<Device> listDevicesByUserId(Object userId) {
        Set<String> keys = cache.get().keysAndLoad(acKey(userId, Constants.WILDCARD));
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
        Set<String> rfKeys = cache.get().keysAndLoad(rfKey(Constants.WILDCARD, Constants.WILDCARD));
        return rfKeys.stream().filter(rfKey -> {
            Device device = (Device) cache.get().get(rfKey);
            if (device != null) return (now - device.getLastRequestTime().getTime()) < ms;
            return false;
        }).map(key -> key.split(Constants.SEPARATOR)[2]).distinct().collect(Collectors.toList());
    }

    @Override
    public List<Device> listActiveUserDevices(Object userId, long ms) {
        long        now    = TimeUtils.nowTime();
        Set<String> rfKeys = cache.get().keysAndLoad(rfKey(userId, Constants.WILDCARD));
        return rfKeys.stream().map(rfKey -> (Device) cache.get().get(rfKey))
                .filter(device -> device != null && ((now - device.getLastRequestTime().getTime()) < ms))
                .collect(Collectors.toList());
    }

    @Override
    public void request() {
        try {
            HttpMeta currentHttpMeta = AUtils.getCurrentHttpMeta();
            Token    token           = currentHttpMeta.getToken();
            String   acKey           = acKey(token.getUserId(), token.getTokenId());
            Object   o               = cache.get().get(acKey);
            if (o == null) return;
            String rtid = ((AccessInfo) o).getRefreshTokenId();
            if (rtid != null) {
                Async.run(() -> {
                    String rfKey = rfKey(token.getUserId(), rtid);
                    Device d     = (Device) cache.get().get(rfKey);
                    if (d != null) {
                        d.setLastRequestTime(currentHttpMeta.getNow());
                        d.setIp(currentHttpMeta.getIp());
                        cache.get().set(rfKey, d);
                    }
                });
            }
        } catch (Exception ignored) {
        }
    }

    private String requestKey(Object userId, String rfKey) {
        return Constants.DEVICE_REQUEST_INFO_KEY_PREFIX.get() + userId + Constants.SEPARATOR + rfKey.split(Constants.SEPARATOR)[3];
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
        return StringUtils.equals(device.getType(), otherDevice.getType())
                || (device.getId() != null && StringUtils.equals(device.getId(), otherDevice.getId())); // null??????????????????
    }

    private boolean equalsDeviceByTypeAndId(Device device, String deviceType, String deviceId) {
        if (device == null) return false;
        return StringUtils.equals(device.getType(), deviceType)
                && StringUtils.equals(device.getId(), deviceId);
    }

    private boolean equalsDeviceById(Device device, Device otherDevice) {
        if (device == null) return false;
        return equalsDeviceById(device, otherDevice.getId());
    }

    private boolean equalsDeviceById(Device device, String deviceId) {
        if (device == null) return false;
        return device.getId() != null && StringUtils.equals(device.getId(), deviceId);
    }

    private boolean equalsDeviceByType(Device device, String deviceType) {
        if (device == null) return false;
        return StringUtils.equals(device.getType(), deviceType);
    }

}
