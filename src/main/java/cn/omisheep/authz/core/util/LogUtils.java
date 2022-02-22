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
@Slf4j(topic = "Authz.log")
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


    public static void pushLogToRequest(String formatMsg, Object... args) {
        pushLogToRequest(LogLevel.INFO, formatMsg, args);
    }

    @SuppressWarnings("unchecked")
    public static void pushLogToRequest(LogLevel logLevel, String formatMsg, Object... args) {
        HttpServletRequest request = ((ServletRequestAttributes) (RequestContextHolder.currentRequestAttributes())).getRequest();
        ArrayList<LogMeta> au_logs = (ArrayList<LogMeta>) request.getAttribute("au_logs");
        if (au_logs == null) {
            au_logs = new ArrayList<>();
            request.setAttribute("au_logs", au_logs);
        }
        au_logs.add(new LogMeta(logLevel, format(formatMsg, args)));
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
            switch (logMeta.logLevel) {
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
            log.info(info.append("\n").toString());
        }
        if (warn.length() > 0) {
            log.warn(warn.append("\n").toString());
        }
        if (debug.length() > 0) {
            log.debug(debug.append("\n").toString());
        }
        if (error.length() > 0) {
            log.error(error.append("\n").toString());
        }

        logs.clear();
    }

    @Getter
    public static class LogMeta {
        private final LogLevel logLevel;
        private final String msg;

        public LogMeta(LogLevel logLevel, String msg) {
            if (logLevel == null) {
                logLevel = LogLevel.INFO;
            }
            this.logLevel = logLevel;
            this.msg = msg;
        }

        public LogMeta(String msg) {
            this.logLevel = LogLevel.INFO;
            this.msg = msg;
        }
    }

    private static String format(String formatMsg, Object... args) {
        for (Object arg : args) {
            formatMsg = formatMsg.replaceFirst("\\{}", String.valueOf(arg));
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

