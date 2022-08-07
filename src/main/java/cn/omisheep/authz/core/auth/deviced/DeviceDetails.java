package cn.omisheep.authz.core.auth.deviced;

import cn.omisheep.authz.core.AuthzContext;
import cn.omisheep.authz.core.auth.ipf.Blacklist;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AccessLevel;
import lombok.Data;
import lombok.Getter;
import lombok.experimental.Accessors;

import java.util.Date;
import java.util.function.Supplier;

/**
 * 仅用于包装数据返回给用户
 *
 * @author zhouxinchen
 * @since 1.2.0
 */
@Data
@Accessors(chain = true)
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class DeviceDetails {

    /**
     * 登录标识
     */
    private String Id;

    /**
     * 用户id
     */
    private Object userId;

    /**
     * 最后一次请求时间
     */
    private Date lastRequestTime;

    /**
     * 最后一次请求ip
     */
    private String lastRequestIp;

    /**
     * 设备类型
     */
    private String deviceType;

    /**
     * 设备id
     */
    private String deviceId;

    /**
     * 过期时间
     */
    private Date expires;

    public DeviceDetails setUserId(Object userId) {
        this.userId = AuthzContext.createUserId(userId);
        return this;
    }

    @Getter(AccessLevel.PRIVATE)
    private Supplier<RequestDetails> supplier;

    public DeviceDetails setDevice(Device device) {
        this.deviceType = device.getDeviceType();
        this.deviceId   = device.getDeviceId();
        return this;
    }

    public DeviceDetails setRequest(RequestDetails request) {
        _setRequest(request);
        this.deviceType = request.getDeviceType();
        this.deviceId   = request.getDeviceId();
        return this;
    }

    private void _setRequest(RequestDetails request) {
        this.lastRequestTime = request.getLastRequestTime();
        this.lastRequestIp   = request.getIp();
    }

    public Date getLastRequestTime() {
        if (lastRequestTime == null) {
            _setRequest(supplier.get());
        }
        return lastRequestTime;
    }

    public String getLastRequestIp() {
        if (lastRequestIp == null) {
            _setRequest(supplier.get());
        }
        return lastRequestIp;
    }

    public boolean isDenyIp() {
        return !Blacklist.IP.check(getLastRequestIp());
    }

    public boolean isDenyIpRange() {
        return !Blacklist.IPRangeDeny.check(getLastRequestIp());
    }

    public boolean isDenyUser() {
        return !Blacklist.User.check(userId, deviceType, deviceId);
    }

}
