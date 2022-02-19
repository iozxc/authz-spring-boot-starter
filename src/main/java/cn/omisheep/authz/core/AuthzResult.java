package cn.omisheep.authz.core;


import cn.omisheep.commons.web.entity.Result;
import cn.omisheep.commons.web.entity.ResultCode;

import static cn.omisheep.commons.web.entity.ResultCode.info;

public class AuthzResult extends Result {
    ResultCode AUTH_ERROR = info(-100, "失败");
}