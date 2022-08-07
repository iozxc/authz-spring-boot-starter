package cn.omisheep.authz.support.http.api;

import cn.omisheep.authz.AuHelper;
import cn.omisheep.authz.core.AuthzContext;
import cn.omisheep.authz.core.auth.ipf.Blacklist;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.msg.AuthzModifier;
import cn.omisheep.authz.support.http.ApiSupport;
import cn.omisheep.authz.support.http.annotation.*;
import cn.omisheep.authz.support.util.IPAddress;
import cn.omisheep.commons.util.TimeUtils;
import cn.omisheep.web.entity.Result;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
@Mapping(value = "/device", requireLogin = false)
public class DeviceApiSupport implements ApiSupport {

    @Get(value = "/all", desc = "获得所有设备")
    public Result version() {
        return Result.SUCCESS.data(AuHelper.getAllUsersDevices());
    }

    @Get(value = "/active-users-count", desc = "当前在线用户数量")
    public Result activeUsersCount(@Param String time) {
        return Result.SUCCESS.data(AuHelper.getNumberOfActiveUser(time));
    }

    @Get(value = "/active-users", desc = "当前在线用户的详细设备信息")
    public Result activeUsers(@Param String time) {
        return Result.SUCCESS.data(AuHelper.getActiveDevices(time));
    }

    @Get(value = "/check-is-login", desc = "当前在线用户的详细设备信息")
    public Result checkLogin(@Param String userId,
                             @Param String id) {
        try {
            return Result.SUCCESS.data(AuHelper.isLoginById(AuthzContext.createUserId(userId), id));
        } catch (Exception e) {
            return Result.FAIL.data();
        }
    }

    @Get(value = "/logout", desc = "当前在线用户的详细设备信息")
    public Result logout(@Param String userId,
                         @Param String id) {
        try {
            AuHelper.logoutById(AuthzContext.createUserId(userId), id);
            return Result.SUCCESS.data();
        } catch (Exception e) {
            return Result.FAIL.data();
        }
    }

    @Post(value = "/get-deny-info", desc = "获得封禁信息")
    public Result getDenyInfo(@JSON AuthzModifier.BlacklistInfo info) {
        try {
            return Result.SUCCESS.data(new DenyInfo(AuthzContext.createUserId(info.getUserId() + ""), info));
        } catch (Exception e) {
            return Result.FAIL.data();
        }
    }

    @Get(value = "/get-all-deny-info", desc = "获得封禁信息")
    public Result getAllDenyInfo() {
        try {
            return Result.SUCCESS.data(Blacklist.readAll());
        } catch (Exception e) {
            return Result.FAIL.data();
        }
    }

    @Post(value = "/deny", desc = "封禁")
    public Result denyInfo(@JSON AuthzModifier.BlacklistInfo info,
                           HttpMeta httpMeta) {
        try {
            Object _userId = AuthzContext.createUserId(info.getUserId() + "");

            long ms = info.getDate().getTime() - TimeUtils.nowTime();

            switch (info.getType()) {
                case USER: {
                    if (ms < 0) {AuHelper.removeDenyUser(_userId);} else AuHelper.denyUser(_userId, ms);
                    break;
                }
                case DEVICE: {
                    if (ms < 0) {
                        AuHelper.removeDenyDevice(_userId, info.getDeviceType(), info.getDeviceId());
                    } else {
                        AuHelper.denyDevice(_userId, info.getDeviceType(), info.getDeviceId(), ms);
                    }
                    break;
                }
                case IP: {
                    if (ms < 0) {
                        AuHelper.removeDenyIP(info.getIp());
                    } else {
                        AuHelper.denyIP(info.getIp(), ms);
                    }
                    break;
                }
                case IP_RANGE: {
                    if (ms < 0) {
                        AuHelper.removeDenyIPRange(info.getIp());
                    } else {
                        AuHelper.denyIPRange(info.getIp(), ms);
                    }
                    break;
                }
                default: {
                    return Result.FAIL.data();
                }
            }

            return Result.SUCCESS.data(new DenyInfo(_userId, info));
        } catch (Exception e) {
            return Result.FAIL.data();
        }

    }

    @Data
    public static class DenyInfo {
        private List<Blacklist.User>        userId;
        private Blacklist.User              device;
        private List<Blacklist.IP>          ip;
        private List<Blacklist.IPRangeDeny> iprange;

        public DenyInfo(Object _userId,
                        AuthzModifier.BlacklistInfo info) {
            userId = AuHelper.getDenyUserInfo(_userId);
            device = AuHelper.getDenyDeviceInfo(info.getUserId(), info.getDeviceType(), info.getDeviceId());
            ip     = AuHelper.getDenyIPInfo().stream().filter(v -> v.getIp().equals(info.getIp())).collect(
                    Collectors.toList());
            if (info.getIp() != null) {
                IPAddress ipAddress = new IPAddress(info.getIp());
                iprange = AuHelper.getDenyIPRangeInfo()
                        .stream()
                        .filter(v -> v.getIpRange().isIPAddressInRange(ipAddress))
                        .collect(
                                Collectors.toList());
            } else {
                iprange = new ArrayList<>(0);
            }
        }
    }

}
