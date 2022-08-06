package cn.omisheep.authz.support.http.api;

import cn.omisheep.authz.AuHelper;
import cn.omisheep.authz.support.http.ApiSupport;
import cn.omisheep.authz.support.http.annotation.Get;
import cn.omisheep.authz.support.http.annotation.Mapping;
import cn.omisheep.authz.support.http.annotation.Param;
import cn.omisheep.web.entity.Result;

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
        return Result.SUCCESS.data(AuHelper.getNumberOfActiveUsers(time));
    }

    @Get(value = "/active-users", desc = "当前在线用户的详细设备信息")
    public Result activeUsers(@Param String time) {
        return Result.SUCCESS.data(AuHelper.getActiveDevices(time));
    }

}
