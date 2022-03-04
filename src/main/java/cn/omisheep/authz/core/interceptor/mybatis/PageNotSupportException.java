package cn.omisheep.authz.core.interceptor.mybatis;

import cn.omisheep.authz.core.AuthzException;

import static cn.omisheep.authz.core.ExceptionStatus.PAGE_NOT_SUPPORT;

public class PageNotSupportException extends AuthzException {
    private static final long serialVersionUID = -1363227878202784788L;

    public PageNotSupportException() {
        super(PAGE_NOT_SUPPORT);
    }
}