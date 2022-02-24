package cn.omisheep.authz.core;

import cn.omisheep.commons.web.entity.Result;
import cn.omisheep.commons.web.entity.ResultCode;

import static cn.omisheep.commons.web.entity.ResultCode.info;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public class QuaResult extends Result {
    public static final ResultCode FAIL = info(100, "FAIL");
}
