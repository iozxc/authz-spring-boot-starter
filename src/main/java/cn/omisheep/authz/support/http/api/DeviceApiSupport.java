package cn.omisheep.authz.support.http.api;

import cn.omisheep.authz.AuHelper;
import cn.omisheep.authz.core.AuthzContext;
import cn.omisheep.authz.core.AuthzResult;
import cn.omisheep.authz.core.auth.deviced.DeviceDetails;
import cn.omisheep.authz.core.auth.ipf.Blacklist;
import cn.omisheep.authz.core.msg.AuthzModifier;
import cn.omisheep.authz.support.http.ApiSupport;
import cn.omisheep.authz.support.http.annotation.*;
import cn.omisheep.authz.support.util.IPAddress;
import cn.omisheep.commons.util.TimeUtils;
import cn.omisheep.web.entity.ResponseResult;
import lombok.Data;

import java.util.*;
import java.util.stream.Collectors;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Mapping(value = "/device", requireLogin = false)
public class DeviceApiSupport implements ApiSupport {

    @Get(value = "/all", desc = "获得所有设备")
    public ResponseResult<Map<Object, List<DeviceDetails>>> version() {
        return AuthzResult.SUCCESS.data(AuHelper.getAllUserDevices());
    }


    @Get(value = "/get-all-userid", desc = "获得当前有效用户id列表")
    public ResponseResult<List<Object>> getAllUserId() {
        try {
            return AuthzResult.SUCCESS.data(AuHelper.getAllUserId());
        } catch (Exception e) {
            return AuthzResult.FAIL.data();
        }
    }

    @Get(value = "/active-users-count", desc = "当前在线用户数量")
    public ResponseResult<Integer> activeUsersCount(@Param("time") String time) {
        return AuthzResult.SUCCESS.data(AuHelper.getNumberOfActiveUser(time));
    }

    @Get(value = "/active-users", desc = "当前所有在线用户的详细设备信息")
    public ResponseResult<List<DeviceDetails>> activeUsers(@Param("time") String time) {
        return AuthzResult.SUCCESS.data(AuHelper.getActiveDevices(time));
    }

    @Get(value = "/check-is-login", desc = "判断该用户是否在线")
    public ResponseResult<Boolean> checkLogin(@Param("userId") String userId,
                                              @Param("id") String id) {
        try {
            return AuthzResult.SUCCESS.data(AuHelper.isLoginById(AuthzContext.createUserId(userId), id));
        } catch (Exception e) {
            return AuthzResult.FAIL.data();
        }
    }

    @Get(value = "/logout", desc = "让该用户下线")
    public ResponseResult<Object> logout(@Param("userId") String userId,
                         @Param("id") String id) {
        try {
            AuHelper.logoutById(AuthzContext.createUserId(userId), id);
            return AuthzResult.SUCCESS.data();
        } catch (Exception e) {
            return AuthzResult.FAIL.data();
        }
    }

    @Post(value = "/get-deny-info", desc = "获得封禁信息")
    public ResponseResult<DenyInfo> getDenyInfo(@JSON AuthzModifier.BlacklistInfo info) {
        try {
            return AuthzResult.SUCCESS.data(new DenyInfo(AuthzContext.createUserId(info.getUserId()), info));
        } catch (Exception e) {
            return AuthzResult.FAIL.data();
        }
    }

    @Get(value = "/get-all-deny-info", desc = "获得封禁信息")
    public ResponseResult<Map<String, Object>> getAllDenyInfo() {
        try {
            return AuthzResult.SUCCESS.data(Blacklist.readAll());
        } catch (Exception e) {
            return AuthzResult.FAIL.data();
        }
    }

    @Post(value = "/deny", desc = "封禁")
    public ResponseResult<DenyInfo> denyInfo(@JSON AuthzModifier.BlacklistInfo info) {
        try {
            Object _userId = AuthzContext.createUserId(info.getUserId());

            Date endTime = TimeUtils.formatParse(info.getDate());

            switch (info.getType()) {
                case USER: {
                    AuHelper.denyUser(_userId, endTime);
                    break;
                }
                case DEVICE: {
                    AuHelper.denyDevice(_userId, info.getDeviceType(), info.getDeviceId(), endTime);
                    break;
                }
                case IP: {
                    AuHelper.denyIP(info.getIp(), endTime);
                    break;
                }
                case IP_RANGE: {
                    AuHelper.denyIPRange(info.getIp(), endTime);
                    break;
                }
                default: {
                    return AuthzResult.FAIL.data();
                }
            }

            return AuthzResult.SUCCESS.data(new DenyInfo(_userId, info));
        } catch (Exception e) {
            return AuthzResult.FAIL.data();
        }

    }

    @Post(value = "/deny-remove", desc = "移除封禁")
    public ResponseResult<DenyInfo> removeDenyInfo(@JSON AuthzModifier.BlacklistInfo info) {
        try {
            Object _userId = AuthzContext.createUserId(info.getUserId());

            switch (info.getType()) {
                case USER: {
                    AuHelper.removeDenyUser(_userId);
                    break;
                }
                case DEVICE: {
                    AuHelper.removeDenyDevice(_userId, info.getDeviceType(), info.getDeviceId());
                    break;
                }
                case IP: {
                    AuHelper.removeDenyIP(info.getIp());
                    break;
                }
                case IP_RANGE: {
                    AuHelper.removeDenyIPRange(info.getIp());
                    break;
                }
                default: {
                    return AuthzResult.FAIL.data();
                }
            }

            return AuthzResult.SUCCESS.data(new DenyInfo(_userId, info));
        } catch (Exception e) {
            return AuthzResult.FAIL.data();
        }

    }


    @Data
    public static class DenyInfo {
        private Blacklist.User             userId;
        private Blacklist.User             device;
        private Blacklist.IP               ip;
        private Set<Blacklist.IPRangeDeny> iprange;

        public DenyInfo(Object _userId,
                        AuthzModifier.BlacklistInfo info) {
            userId = AuHelper.getDenyUserInfo(_userId);
            device = AuHelper.getDenyDeviceInfo(info.getUserId(), info.getDeviceType(), info.getDeviceId());
            ip     = AuHelper.getDenyIPInfo(info.getIp());
            if (info.getIp() != null) {
                IPAddress ipAddress = new IPAddress(info.getIp());
                iprange = AuHelper.getAllDenyIPRangeInfo()
                        .stream()
                        .filter(v -> v.getIpRange().isIPAddressInRange(ipAddress))
                        .collect(
                                Collectors.toSet());
            } else {
                iprange = new HashSet<>(0);
            }
        }
    }

}
