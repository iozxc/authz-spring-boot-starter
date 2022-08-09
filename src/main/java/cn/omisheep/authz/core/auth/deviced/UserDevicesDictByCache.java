package cn.omisheep.authz.core.auth.deviced;

import cn.omisheep.authz.AuHelper;
import cn.omisheep.authz.core.AuthzContext;
import cn.omisheep.authz.core.AuthzProperties;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.cache.Cache;
import cn.omisheep.authz.core.config.Constants;
import cn.omisheep.authz.core.tk.AccessToken;
import cn.omisheep.authz.core.tk.GrantType;
import cn.omisheep.authz.core.tk.RefreshToken;
import cn.omisheep.authz.core.tk.TokenPair;
import cn.omisheep.commons.util.Async;
import cn.omisheep.commons.util.TimeUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static cn.omisheep.authz.core.auth.deviced.UserDevicesDict.UserStatus.*;
import static cn.omisheep.authz.core.auth.deviced.UserDevicesDict.*;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Slf4j
public class UserDevicesDictByCache implements UserDevicesDict {

    private final AuthzProperties                      properties;
    private final Cache                                cache;
    private final Map<Object, CompletableFuture<Void>> cleanCache = new ConcurrentHashMap<>();

    public UserDevicesDictByCache(AuthzProperties properties,
                                  Cache cache) {
        this.properties = properties;
        this.cache      = cache;
    }

    @Override
    public UserStatus userStatus(AccessToken accessToken) {
        String accessTokenId = accessToken.getTokenId();
        String clientId      = accessToken.getClientId();

        Device device;
        if (clientId == null) {
            device = cache.get(key(accessToken), Device.class);
        } else {
            device = cache.get(UserDevicesDict.oauthKey(accessToken), Device.class);
        }

        // 设备未登录。需要重新登录
        if (device == null) return REQUIRE_LOGIN;

        // clientId不匹配。需要重新dengue
        if (clientId != null) {
            if (!StringUtils.equals(device.getClientId(), clientId)) return REQUIRE_LOGIN;
        } else {
            // accessTokenId不匹配，账号在其他地方登录
            if (!StringUtils.equals(device.getAccessTokenId(), accessTokenId)) return LOGIN_EXCEPTION;
        }

        // 成功
        return SUCCESS;
    }

    // @since 1.2.0 优化了登录以及验证逻辑
    @Override
    public void addUser(TokenPair tokenPair,
                        HttpMeta httpMeta) {
        if (tokenPair == null || tokenPair.getAccessToken() == null || tokenPair.getRefreshToken() == null) {return;}

        AccessToken accessToken = tokenPair.getAccessToken();
        Long        expiredIn;
        Date        expiresAt;
        if (GrantType.CLIENT_CREDENTIALS.equals(accessToken.getGrantType())) {
            expiresAt = new Date(accessToken.getExpiresAt());
            expiredIn = accessToken.getExpiresIn();
        } else {
            RefreshToken refreshToken = tokenPair.getRefreshToken();
            expiresAt = new Date(refreshToken.getExpiresAt());
            expiredIn = refreshToken.getExpiresIn();
        }

        Device device = new DefaultDevice()
                .setAccessTokenId(accessToken.getTokenId());

        String clientId = accessToken.getClientId();
        if (clientId != null) {
            String    scope     = accessToken.getScope();
            GrantType grantType = accessToken.getGrantType();
            device.setScope(scope).setGrantType(grantType).setClientId(clientId)
                    .setAuthorizedDate(httpMeta.getNow())
                    .setExpiresDate(expiresAt);
            String key = UserDevicesDict.oauthKey(accessToken);
            cache.set(key, device, expiredIn);
        } else {
            String deviceType = accessToken.getDeviceType();
            String deviceId   = accessToken.getDeviceId();
            String key        = key(accessToken);
            String rKey       = UserDevicesDict.requestKey(accessToken);
            device.setDeviceType(deviceType).setDeviceId(deviceId);

            if (properties.getToken().isLogoutBeforeLogin()) {
                removeCurrentDevice();
            }

            cache.set(key, device, expiredIn);

            Object                  userId = accessToken.getUserId();
            Runnable                run    = () -> clean(userId, deviceType, deviceId, key, rKey);
            CompletableFuture<Void> future = cleanCache.get(userId);

            if (future == null || Async.isSuccessFuture(future)) {
                cleanCache.put(userId, Async.run(run));
            } else {
                future.thenRun(run);
            }
        }

    }

    @Override
    public boolean refreshUser(TokenPair tokenPair) {
        if (tokenPair == null) return false;
        String key    = key(tokenPair.getRefreshToken());
        Device device = cache.get(key, Device.class);
        if (device == null) return false;

        AccessToken accessToken = tokenPair.getAccessToken();
        Long        expiredAt   = tokenPair.getRefreshToken().getExpiresAt();

        device.setAccessTokenId(accessToken.getTokenId());

        Async.run(() -> {
            cache.set(key(accessToken), device, expiredAt - TimeUtils.nowTime());
            cache.del(key);
        });
        return true;
    }

    @Override
    public void removeAccessTokenByTid(Object userId,
                                       String tid) {
        String key    = key(userId, tid);
        Device device = cache.get(key, Device.class);
        if (device == null) return;
        device.setAccessTokenId(null);
        cache.set(key, device);
    }

    @Override
    public void removeDeviceById(Object userId,
                                 String id) {
        cache.del(key(userId, id));
    }

    @Override
    public void removeAllDevice(Object userId) {
        Async.run(() -> cache.del(cache.keys(key(userId, Constants.WILDCARD))));
    }

    @Override
    public void removeCurrentDevice() {
        try {
            cache.del(key(AuHelper.getToken()));
        } catch (Exception ignored) {
        }
    }

    @Override
    public boolean isLogin(Object userId,
                           String id) {
        return !cache.notKey(key(userId, id));
    }

    @Override
    public void removeDevice(Object userId,
                             String deviceType,
                             String deviceId) {
        if (deviceType == null || deviceType.equals("")) return;
        Map<String, Device> deviceMap = cache.get(cache.keys(key(userId, Constants.WILDCARD)), Device.class);
        Set<String> dels = deviceMap.entrySet().stream()
                .filter(e -> StringUtils.equals(e.getValue().getDeviceType(), deviceType))
                .filter(e -> deviceId == null || StringUtils.equals(e.getValue().getDeviceType(), deviceId))
                .map(Map.Entry::getKey)
                .collect(Collectors.toSet());
        Async.run(() -> cache.del(dels));
    }

    @Override
    public DeviceDetails getDevice(Object userId,
                                   String deviceType,
                                   String deviceId) {
        Set<String> keys = cache.keys(key(userId, Constants.WILDCARD));
        if (keys.isEmpty()) return null;
        Map<String, Device> deviceMap = cache.get(keys, Device.class);
        Optional<Map.Entry<String, Device>> _item = deviceMap.entrySet().stream()
                .filter(d -> equalsDeviceByTypeAndId(d.getValue(), deviceType, deviceId))
                .findAny();
        if (!_item.isPresent()) {
            return null;
        } else {
            Supplier<RequestDetails> requestDetailsSupplier = () -> {
                String[] split = _item.get().getKey().split(Constants.SEPARATOR);
                return cache.get(requestKey(userId, split[split.length - 1]),
                                 RequestDetails.class);
            };
            return new DeviceDetails().setDevice(_item.get().getValue()).setSupplier(requestDetailsSupplier);
        }
    }

    @Override
    public List<Object> listUserId() {
        Set<String> keys = cache.keys(key(Constants.WILDCARD, Constants.WILDCARD));
        if (keys.isEmpty()) return new ArrayList<>(0);
        return keys.stream().map(key -> AuthzContext.createUserId(key.split(Constants.SEPARATOR)[4]))
                .distinct().collect(Collectors.toList());
    }

    @Override
    public List<DeviceDetails> listDevicesByUserId(Object userId) {
        Set<String> keys = cache.keys(key(userId, Constants.WILDCARD));
        if (keys.isEmpty()) return new ArrayList<>(0);
        Map<String, Device> deviceMap = cache.get(keys, Device.class);

        ArrayList<DeviceDetails> deviceDetails = new ArrayList<>();
        deviceMap.forEach((k, v) -> {
            Supplier<RequestDetails> requestDetailsSupplier = () -> {
                String[] split = k.split(Constants.SEPARATOR);
                return cache.get(requestKey(userId, split[split.length - 1]),
                                 RequestDetails.class);
            };
            deviceDetails.add(new DeviceDetails().setDevice(v).setSupplier(requestDetailsSupplier));
        });
        deviceDetails.sort((v1, v2) -> v2.getLastRequestTime().compareTo(v1.getLastRequestTime()));
        return deviceDetails;
    }

    @Override
    public List<DeviceDetails> listActiveUserDevices(Object userId,
                                                     long ms) {
        if ((userId + "").contains("*") || (userId + "").contains("?")) {
            return new ArrayList<>();
        }
        return _listActiveUserDevices(requestKey(userId, Constants.WILDCARD), ms);
    }

    @Override
    public List<DeviceDetails> listActiveUserDevices(long ms) {
        return _listActiveUserDevices(requestKey(Constants.WILDCARD, Constants.WILDCARD), ms);
    }

    private List<DeviceDetails> _listActiveUserDevices(String requestKey,
                                                       long ms) {
        long        now   = TimeUtils.nowTime();
        Set<String> rKeys = cache.keys(requestKey);
        if (rKeys.isEmpty()) return new ArrayList<>(0);

        Map<String, RequestDetails> requestDetailsMap = cache.get(rKeys, RequestDetails.class);

        return requestDetailsMap.entrySet().stream()
                .filter(e -> (now - e.getValue().getLastRequestTime().getTime()) < ms)
                .map(e -> {
                    String[] split = e.getKey().split(Constants.SEPARATOR);
                    return new DeviceDetails().setId(split[5])
                            .setUserId(split[4]).setRequest(e.getValue());
                })
                .sorted((v1, v2) -> v2.getLastRequestTime().compareTo(v1.getLastRequestTime()))
                .collect(Collectors.toList());
    }

    @Override
    public void request(HttpMeta httpMeta) {
        try {
            AccessToken token = httpMeta.getToken();
            if (token.getClientId() == null) {
                DefaultRequestDetails requestDetails = (DefaultRequestDetails) new DefaultRequestDetails()
                        .setLastRequestTime(httpMeta.getNow())
                        .setIp(httpMeta.getIp())
                        .setDeviceType(token.getDeviceType())
                        .setDeviceId(token.getDeviceId());
                Async.run(() -> cache.setSneaky(requestKey(token), requestDetails, 2, TimeUnit.DAYS));
            }
        } catch (Exception ignored) {
        }
    }

    @Override
    public void deviceClean(Object userId) {

        AtomicReference<Runnable> reference = new AtomicReference<>();

        if (AuHelper.isLogin()) {
            AccessToken token  = AuHelper.getToken();
            Device      device = cache.get(key(token), Device.class);
            if (device != null) {
                reference.set(() -> clean(userId,
                                          device.getDeviceType(), device.getDeviceId(),
                                          key(token), requestKey(token)));

            }
        } else {
            reference.set(() -> clean(userId, null, null, null, null));
        }

        CompletableFuture<Void> future = cleanCache.get(userId);

        if (future == null || Async.isSuccessFuture(future)) {
            cleanCache.put(userId, Async.run(reference.get()));
        } else {
            future.thenRun(reference.get());
        }

    }

    private void clean(Object userId,
                       String deviceType,
                       String deviceId,
                       String key,
                       String rKey) {
        AuthzProperties.UserConfig userConfig = usersConfig.getOrDefault(userId, properties.getUser());

        Set<String> delKeys = new HashSet<>();

        Set<String> keys  = new HashSet<>();
        Set<String> rKeys = new HashSet<>();
        Async.joinAndCheck(
                Async.combine(() -> keys.addAll(cache.keys(key(userId, Constants.WILDCARD))),
                              () -> rKeys.addAll(cache.keys(requestKey(userId, Constants.WILDCARD)))
                ));

        if (key != null && !keys.isEmpty()) {
            keys.remove(key);
        }
        if (rKey != null && !rKeys.isEmpty()) {
            rKeys.remove(rKey);
        }

        if (keys.isEmpty()) return;

        Map<String, Device>         deviceMap  = new HashMap<>();
        Map<String, RequestDetails> requestMap = new HashMap<>();

        Async.joinAndCheck(
                Async.combine(() -> deviceMap.putAll(cache.get(keys, Device.class)),
                              () -> requestMap.putAll(cache.get(rKeys, RequestDetails.class))
                ));

        if (deviceMap.isEmpty()) return;

        // 删除同type同id
        if (deviceType != null && deviceId != null) {
            d(Integer.MIN_VALUE, deviceMap, requestMap, delKeys,
              e -> StringUtils.equals(deviceType, e.getValue().getDeviceType())
                      && StringUtils.equals(deviceId, e.getValue().getDeviceId()));
        }

        List<DeviceCountInfo> typesTotal = userConfig.getTypesTotal();

        // 登录设备总数
        if (userConfig.getMaximumTotalDevice() != -1
                && userConfig.getMaximumTotalDevice() > 0
                && deviceMap.size() > userConfig.getMaximumTotalDevice()) {
            d(userConfig.getMaximumTotalDevice() - 1, deviceMap, requestMap, delKeys, e -> true);
        }

        // 同类型设备最大登录数量
        if (userConfig.getMaximumTotalSameTypeDevice() != -1 && deviceType != null && typesTotal.stream()
                .noneMatch(v -> v.getTypes().contains(deviceType))) {
            d(userConfig.getMaximumTotalSameTypeDevice() - 1, deviceMap, requestMap, delKeys,
              e -> StringUtils.equals(e.getValue().getDeviceType(), deviceType));
        }

        // 每[一种、多种]设备类型设置[共同]的最大登录数（最小为1）
        if (typesTotal != null && !typesTotal.isEmpty()) {
            for (DeviceCountInfo deviceCountInfo : typesTotal) {
                if (deviceCountInfo.getTypes().isEmpty()) continue;
                d(deviceCountInfo.getTotal() - 1, deviceMap, requestMap, delKeys,
                  e -> deviceCountInfo.getTypes().contains(e.getValue().getDeviceType()));
            }
        }

        if (!delKeys.isEmpty()) {
            cache.del(delKeys);
            cache.del(key(userId, Constants.WILDCARD));
        }
    }

    private void d(int max,
                   Map<String, Device> deviceMap,
                   Map<String, RequestDetails> requestDetailsMap,
                   Set<String> delKeys,
                   Predicate<? super Map.Entry<String, Device>> predicate) {
        if (max <= 0) {
            if (deviceMap.isEmpty()) return;
            delKeys.addAll(deviceMap.keySet());
        }
        List<Map.Entry<String, Device>> devices = deviceMap.entrySet().stream().filter(predicate).sorted(
                        (v1, v2) -> {
                            RequestDetails requestDetails1 = requestDetailsMap.get(v1.getKey());
                            RequestDetails requestDetails2 = requestDetailsMap.get(v2.getKey());
                            long           l1              = 0;
                            long           l2              = 0;
                            if (requestDetails1 != null) l1 = requestDetails1.getLastRequestTimeLong();
                            if (requestDetails2 != null) l2 = requestDetails2.getLastRequestTimeLong();
                            return Math.toIntExact(l1 - l2);
                        }
                )
                .collect(Collectors.toList());
        int deleteCount = devices.size() - max;
        if (deleteCount <= 0) return;
        for (Map.Entry<String, Device> v : devices.subList(0, Math.min(deleteCount, devices.size()))) {
            delKeys.add(v.getKey());
        }
    }

}
