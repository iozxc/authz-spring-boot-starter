package cn.omisheep.authz.core.util;

import cn.omisheep.authz.core.Constants;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;
import org.springframework.boot.logging.LogLevel;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalTime;
import java.util.ArrayList;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
@Slf4j(topic = "Authz log")
public class LogUtils {

    @Setter
    private static LogLevel logLevel;
    private static final Marker MARKER = MarkerFactory.getMarker("cn.omisheep.au");

    public static void logInfo(String msg, Object... args) {
        if (logLevel.ordinal() <= LogLevel.INFO.ordinal()) log.info(MARKER, msg, args);
    }

    public static void logError(String msg, Object... args) {
        if (logLevel.ordinal() <= LogLevel.ERROR.ordinal()) log.error(MARKER, msg, args);
    }

    public static void logWarn(String msg, Object... args) {
        if (logLevel.ordinal() <= LogLevel.WARN.ordinal()) log.warn(MARKER, msg, args);
    }

    public static void logDebug(String msg, Object... args) {
        if (logLevel.ordinal() <= LogLevel.DEBUG.ordinal()) log.info(MARKER, Constants.DEBUG_PREFIX + msg, args);
    }

    @SuppressWarnings("unchecked")
    public static void pushLogToRequest(String formatMsg, Object... args) {
        HttpServletRequest request = ((ServletRequestAttributes) (RequestContextHolder.currentRequestAttributes())).getRequest();
        ArrayList<LogMeta> au_logs = (ArrayList<LogMeta>) request.getAttribute("au_logs");
        if (au_logs == null) {
            au_logs = new ArrayList<>();
            request.setAttribute("au_logs", au_logs);
        }
        LogMeta logMeta = new LogMeta(null, format(formatMsg, args));
        au_logs.add(logMeta);
    }

    @SuppressWarnings("unchecked")
    public static void exportLogsFromRequest() {
        HttpServletRequest request = ((ServletRequestAttributes) (RequestContextHolder.currentRequestAttributes())).getRequest();
        ArrayList<LogMeta> logs = (ArrayList<LogMeta>) request.getAttribute("au_logs");
        if (!logLevel.equals(LogLevel.OFF) || logs == null) return;
        StringBuilder info = new StringBuilder();
        StringBuilder warn = new StringBuilder();
        StringBuilder debug = new StringBuilder();
        StringBuilder error = new StringBuilder();
        logs.forEach(logMeta -> {
            switch (logMeta.logType) {
                case INFO:
                    info.append("\n").append(logMeta.getMsg());
                    break;
                case WARN:
                    warn.append("\n").append(logMeta.getMsg());
                    break;
                case DEBUG:
                    debug.append("\n").append(logMeta.getMsg());
                    break;
                case ERROR:
                    error.append("\n").append(logMeta.getMsg());
                    break;
            }
        });
        if (info.length() > 0) {
            log.info(info.toString() + "\n");
        }
        if (warn.length() > 0) {
            log.warn(warn.toString() + "\n");
        }
        if (debug.length() > 0) {
            log.debug(debug.toString() + "\n");
        }
        if (error.length() > 0) {
            log.error(error.toString() + "\n");
        }

        logs.clear();
    }

    public enum LogType {
        INFO,
        WARN,
        ERROR,
        DEBUG
    }

    @Getter
    public static class LogMeta {
        private LogType logType;
        private final String msg;

        public LogMeta(LogType logType, String msg) {
            if (logType == null) {
                logType = LogType.INFO;
            }
            this.logType = logType;
            this.msg = msg;
        }

        public LogMeta(String msg) {
            this.logType = LogType.INFO;
            this.msg = msg;
        }

        public void info() {
            this.logType = LogType.INFO;
        }

        public void warn() {
            this.logType = LogType.WARN;
        }

        public void debug() {
            this.logType = LogType.DEBUG;
        }

        public void error() {
            this.logType = LogType.ERROR;
        }
    }

    private static String format(String formatMsg, Object... args) {
        for (Object arg : args) {
            formatMsg = formatMsg.replaceFirst("\\{\\}", String.valueOf(arg));
        }
        return formatMsg;
    }

    /**
     * System.out
     *
     * @param log       log
     * @param formatMsg formatMsg
     */
    public static void debug(String formatMsg, Object... log) {
        StackTraceElement[] stacks = new Throwable().getStackTrace();
        System.out.println(stacks[1].getClassName() + " line no: " + stacks[1].getLineNumber() + "   time: " + LocalTime.now());
        for (Object o : log) {
            System.out.println(format(formatMsg, log));
        }
    }

}

