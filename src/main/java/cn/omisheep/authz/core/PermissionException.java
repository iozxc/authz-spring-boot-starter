package cn.omisheep.authz.core;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.10
 */
@SuppressWarnings("serial")
public class PermissionException extends AuthzException {

    public PermissionException() {
        super(ExceptionStatus.PERM_EXCEPTION);
    }

}
