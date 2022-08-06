package cn.omisheep.authz.core.auth.deviced;

import cn.omisheep.authz.core.tk.GrantType;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.experimental.Accessors;

import java.util.Date;

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

    private String issueTokenId;
    private Date   lastRequestTime;
    private String lastRequestIp;
    private String deviceType;
    private String deviceId;
    private Object userId;

    private String    clientId;
    private String    scope;
    private GrantType grantType;

    private Date expires;

    public DeviceDetails setDevice(Device device) {
        this.deviceType = device.getDeviceType();
        this.deviceId   = device.getDeviceId();
        this.clientId   = device.getClientId();
        this.scope      = device.getScope();
        this.grantType  = device.getGrantType();
        this.expires    = device.getExpiresDate();
        return this;
    }

    public DeviceDetails setRequest(RequestDetails request) {
        this.lastRequestTime = request.getLastRequestTime();
        this.lastRequestIp   = request.getIp();
        this.deviceType      = request.getDeviceType();
        this.deviceId        = request.getDeviceId();
        return this;
    }

}
