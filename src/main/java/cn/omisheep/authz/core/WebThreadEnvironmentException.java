package cn.omisheep.authz.core;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.1.3
 */
@SuppressWarnings("serial")
public class WebThreadEnvironmentException extends AuthzException {
    public WebThreadEnvironmentException() {
        super(ExceptionStatus.WEB_ENVIRONMENT);
    }
}
