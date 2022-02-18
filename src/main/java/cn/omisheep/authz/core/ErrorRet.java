package cn.omisheep.authz.core;

import lombok.Data;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
@Data
public class ErrorRet {
    private int code;
    private String message;

    public ErrorRet(RequestExceptionStatus status) {
        this.code = status.getCode();
        this.message = status.getMsg();
    }
}