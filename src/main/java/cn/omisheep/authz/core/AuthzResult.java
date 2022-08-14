package cn.omisheep.authz.core;

import cn.omisheep.web.entity.IResponseResult;

/**
 * @author zhouxinchen
 * @since 1.2.4
 */
public enum AuthzResult implements IResponseResult {

    SUCCESS(100, "SUCCESS"),
    FAIL(-100, "FAIL");

    private final int    code;
    private final String msg;

    @Override
    public int getCode() {
        return code;
    }

    @Override
    public String getMessage() {
        return msg;
    }

    AuthzResult(int code,
                String msg) {
        this.code = code;
        this.msg  = msg;
    }

}
