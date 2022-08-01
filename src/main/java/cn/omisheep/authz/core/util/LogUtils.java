package cn.omisheep.authz.core.util;

import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.auth.rpd.PermRolesMeta;
import cn.omisheep.authz.core.config.Constants;
import cn.omisheep.authz.core.tk.AccessToken;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import org.springframework.boot.logging.LogLevel;

import java.util.ArrayList;
import java.util.List;

/**
 * 日志工具类
 *
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Slf4j(topic = "authz.global.log")
public abstract class LogUtils {

    @Setter
    private static       LogLevel                   logLevel;
    private static final Marker                     MARKER = MarkerFactory.getMarker("cn.omisheep.authz");
    private static final ThreadLocal<List<LogMeta>> logs   = ThreadLocal.withInitial(ArrayList::new);

    public static void info(String msg,
                            Object... args) {
        if (logLevel.ordinal() <= LogLevel.INFO.ordinal() && log.isInfoEnabled(MARKER)) log.info(MARKER, msg, args);
    }

    public static void error(String msg,
                             Object... args) {
        if (logLevel.ordinal() <= LogLevel.ERROR.ordinal() && log.isErrorEnabled(MARKER)) log.error(MARKER, msg, args);
    }

    public static void error(Throwable throwable) {
        if (logLevel.ordinal() <= LogLevel.ERROR.ordinal() && log.isErrorEnabled(MARKER)) {
            log.error(MARKER,
                      throwable.getMessage(),
                      throwable);
        }
    }

    public static void error(String msg,
                             Throwable throwable) {
        if (logLevel.ordinal() <= LogLevel.ERROR.ordinal() && log.isErrorEnabled(MARKER)) {
            log.error(MARKER, msg,
                      throwable);
        }
    }

    public static void warn(String msg,
                            Object... args) {
        if (logLevel.ordinal() <= LogLevel.WARN.ordinal() && log.isWarnEnabled(MARKER)) log.warn(MARKER, msg, args);
    }

    public static void debug(String msg,
                             Object... args) {
        if (logLevel.ordinal() <= LogLevel.DEBUG.ordinal() && log.isDebugEnabled(MARKER)) log.debug(MARKER, msg, args);
    }

    public static void push(String formatMsg,
                            Object... args) {
        push(LogLevel.INFO, formatMsg, args);
    }

    public static void push(LogLevel logLevel,
                            String formatMsg,
                            Object... args) {
        if (LogUtils.logLevel.ordinal() > logLevel.ordinal()) return;
        logs.get().add(new LogMeta(logLevel, formatMsg, args));
    }

    public static void export() {
        if (logLevel.equals(LogLevel.OFF)) return;
        List<LogMeta> logMetas = logs.get();
        if (logMetas == null) return;
        StringBuilder info  = new StringBuilder();
        StringBuilder warn  = new StringBuilder();
        StringBuilder debug = new StringBuilder();
        StringBuilder error = new StringBuilder();
        logMetas.forEach(logMeta -> {
            switch (logMeta.logLevel) {
                case INFO:
                    info.append(Constants.CRLF).append(logMeta);
                    break;
                case WARN:
                    warn.append(Constants.CRLF).append(logMeta);
                    break;
                case DEBUG:
                    debug.append(Constants.CRLF).append(logMeta);
                    break;
                case ERROR:
                    error.append(Constants.CRLF).append(logMeta);
                    break;
            }
        });
        if (info.length() > 0) {
            info(info.toString());
        }
        if (warn.length() > 0) {
            warn(warn.toString());
        }
        if (debug.length() > 0) {
            debug(debug.toString());
        }
        if (error.length() > 0) {
            error(error.toString());
        }
        logMetas.clear();
    }

    @Getter
    public static class LogMeta {
        private final LogLevel logLevel;
        private final String   format;
        private final Object[] objects;

        public LogMeta(LogLevel logLevel,
                       String format,
                       Object... objects) {
            if (logLevel == null) {
                logLevel = LogLevel.INFO;
            }
            this.logLevel = logLevel;
            this.format   = format;
            this.objects  = objects;
        }

        @Override
        public String toString() {
            return format(format, objects);
        }

        private static String format(String formatMsg,
                                     Object... args) {
            for (Object arg : args) {
                formatMsg = formatMsg.replaceFirst("\\{}", String.valueOf(arg));
            }
            return formatMsg;
        }
    }

    public static void logs(String status,
                            HttpMeta httpMeta,
                            PermRolesMeta meta) {
        AccessToken accessToken = httpMeta.getToken();
        if (accessToken == null) {
            httpMeta.log("「{}」\t{}", status, meta);
        } else {
            httpMeta.log("「{}」\t\t{}\t, userId: [{}]\t, deviceType = [{}]\t, deviceId = [{}]",
                         status, meta, accessToken.getUserId(), accessToken.getDeviceType(), accessToken.getDeviceId());
        }
    }

    public static void logs(String status,
                            HttpMeta httpMeta) {
        AccessToken accessToken = httpMeta.getToken();
        if (accessToken == null) {
            httpMeta.log("「{}」", status);
        } else {
            httpMeta.log("「{}」\t, userId: [{}]\t, deviceType = [{}]\t, deviceId = [{}]",
                         status, accessToken.getUserId(), accessToken.getDeviceType(), accessToken.getDeviceId());
        }
    }

}

