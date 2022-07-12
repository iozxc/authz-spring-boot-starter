package cn.omisheep.authz.core.util;

import cn.omisheep.authz.core.config.Constants;
import cn.omisheep.web.utils.HttpUtils;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import org.springframework.boot.logging.LogLevel;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;

/**
 * 日志工具类
 *
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
@Slf4j(topic = "authz.global.log")
public abstract class LogUtils {

    @Setter
    private static       LogLevel logLevel;
    private static final String   AU_LOGS = "au_logs";
    private static final Marker   MARKER  = MarkerFactory.getMarker("cn.omisheep.au");

    public static void info(String msg, Object... args) {
        if (logLevel.ordinal() <= LogLevel.INFO.ordinal()) log.info(MARKER, msg, args);
    }

    public static void error(String msg, Object... args) {
        if (logLevel.ordinal() <= LogLevel.ERROR.ordinal()) log.error(MARKER, msg, args);
    }

    public static void error(String msg, Throwable throwable) {
        if (logLevel.ordinal() <= LogLevel.ERROR.ordinal()) log.error(msg, throwable);
    }

    public static void warn(String msg, Object... args) {
        if (logLevel.ordinal() <= LogLevel.WARN.ordinal()) log.warn(MARKER, msg, args);
    }

    public static void debug(String msg, Object... args) {
        if (logLevel.ordinal() <= LogLevel.DEBUG.ordinal()) log.info(MARKER, Constants.DEBUG_PREFIX + msg, args);
    }


    public static void pushToRequest(String formatMsg, Object... args) {
        pushToRequest(LogLevel.INFO, formatMsg, args);
    }

    @SuppressWarnings("unchecked")
    public static void pushToRequest(LogLevel logLevel, String formatMsg, Object... args) {
        HttpServletRequest request = HttpUtils.getCurrentRequest();
        ArrayList<LogMeta> au_logs = (ArrayList<LogMeta>) request.getAttribute(AU_LOGS);
        if (au_logs == null) {
            au_logs = new ArrayList<>();
            request.setAttribute(AU_LOGS, au_logs);
        }
        au_logs.add(new LogMeta(logLevel, format(formatMsg, args)));
    }

    public static void exportFromRequest() {
        exportFromRequest(HttpUtils.getCurrentRequest());
    }

    @SuppressWarnings("unchecked")
    public static void exportFromRequest(HttpServletRequest request) {
        ArrayList<LogMeta> logs = (ArrayList<LogMeta>) request.getAttribute(AU_LOGS);
        if (logLevel.equals(LogLevel.OFF) || logs == null) return;
        StringBuilder info  = new StringBuilder();
        StringBuilder warn  = new StringBuilder();
        StringBuilder debug = new StringBuilder();
        StringBuilder error = new StringBuilder();
        logs.forEach(logMeta -> {
            switch (logMeta.logLevel) {
                case INFO:
                    info.append(Constants.CRLF).append(logMeta.getMsg());
                    break;
                case WARN:
                    warn.append(Constants.CRLF).append(logMeta.getMsg());
                    break;
                case DEBUG:
                    debug.append(Constants.CRLF).append(logMeta.getMsg());
                    break;
                case ERROR:
                    error.append(Constants.CRLF).append(logMeta.getMsg());
                    break;
            }
        });
        if (info.length() > 0) {
            info(info.append(Constants.CRLF).toString());
        }
        if (warn.length() > 0) {
            warn(warn.append(Constants.CRLF).toString());
        }
        if (debug.length() > 0) {
            debug(debug.append(Constants.CRLF).toString());
        }
        if (error.length() > 0) {
            error(error.append(Constants.CRLF).toString());
        }
        logs.clear();
    }

    @Getter
    public static class LogMeta {
        private final LogLevel logLevel;
        private final String   msg;

        public LogMeta(LogLevel logLevel, String msg) {
            if (logLevel == null) {
                logLevel = LogLevel.INFO;
            }
            this.logLevel = logLevel;
            this.msg      = msg;
        }
    }

    private static String format(String formatMsg, Object... args) {
        for (Object arg : args) {
            formatMsg = formatMsg.replaceFirst("\\{}", String.valueOf(arg));
        }
        return formatMsg;
    }

}

