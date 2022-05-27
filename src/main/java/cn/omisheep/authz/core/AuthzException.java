package cn.omisheep.authz.core;

import lombok.Getter;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@SuppressWarnings("serial")
public class AuthzException extends RuntimeException {
    @Getter
    private final        ExceptionStatus exceptionStatus;

    public AuthzException(ExceptionStatus exceptionStatus) {
        super(exceptionStatus.getMessage());
        this.exceptionStatus = exceptionStatus;
    }

    public AuthzException(Throwable cause, ExceptionStatus exceptionStatus) {
        super(exceptionStatus.getMessage(), cause);
        this.exceptionStatus = exceptionStatus;
    }

    public AuthzException(Throwable cause) {
        super(cause.getMessage(), cause);
        this.exceptionStatus = ExceptionStatus.UNKNOWN;
    }
}
