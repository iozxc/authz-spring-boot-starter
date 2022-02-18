package cn.omisheep.authz.core.util;

import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
public class TimeUtils {

    public static long parseTimeValueTotal(String... timeVals) {
        long c = 0;
        for (String timeVal : timeVals) {
            c += parseTimeValue(timeVal);
        }
        return c;
    }

    public static long parseTimeValue(String timeVal) {
        return parseTimeValue(timeVal, " ");
    }

    public static long parseTimeValueToSecond(String timeVal) {
        return TimeUnit.MILLISECONDS.toSeconds(parseTimeValue(timeVal, " "));
    }

    public static long parseTimeValue(String timeVal, String delimiter) {
        if (timeVal == null || timeVal.equals("") || timeVal.equals("0")) return 0L;
        String[] s = timeVal.trim().split(delimiter);
        long time = 0;
        for (String val : s) {
            time += parseTime(val);
        }
        return time;
    }

    public static String parseTime(long ms) {
        return parseTime(ms, " ");
    }

    public static String parseTime(long ms, String delimiter) {
        String _ms = ms % 1000 + "ms";
        if (ms < 1000) return _ms;

        long s = ms / 1_000;
        String _s = s % 60 + "s" + delimiter + _ms;
        if (s < 60) return _s;

        long m = s / 60;
        String _m = m % 60 + "m" + delimiter + _s;
        if (m < 60) return _m;

        long h = m / 60;
        String _h = h % 60 + "h" + delimiter + _m;
        if (h < 24) return _h;

        long d = h / 24;
        return d + "d" + delimiter + _h;
    }

    private static long parseTime(String timeVal) {
        String normalized = timeVal.toLowerCase(Locale.ROOT).trim();

        if (normalized.endsWith("d")) {
            return TimeUnit.DAYS.toMillis(parse(normalized, "d"));
        } else if (normalized.endsWith("h")) {
            return TimeUnit.HOURS.toMillis(parse(normalized, "h"));
        } else if (normalized.endsWith("m")) {
            return TimeUnit.MINUTES.toMillis(parse(normalized, "m"));
        } else if (normalized.endsWith("ms")) {
            return TimeUnit.MILLISECONDS.toMillis(parse(normalized, "ms"));
        } else if (normalized.endsWith("s")) {
            return TimeUnit.SECONDS.toMillis(parse(normalized, "s"));
        }
        return 0L;
    }

    private static long parse(String normalized, String suffix) {
        String s = normalized.substring(0, normalized.length() - suffix.length()).trim();
        try {
            long value = Long.parseLong(s);
            if (value >= 0L) {
                return value;
            }
        } catch (Exception e) {
            return 0;
        }
        return 0;
    }

    public static long nowTime() {
        return now().getTime();
    }

    public static Date now() {
        return Date.from(LocalDateTime.now().atZone(ZoneId.systemDefault()).toInstant());
    }

    public static LocalDateTime nowDateTime() {
        return LocalDateTime.now();
    }

    public static String nowString() {
        return format(now());
    }

    public static String nowString(String pattern) {
        return format(pattern, now());
    }

    public static Date datePlus(Date date, String plusTimeVal) {
        return datePlus(date, parseTimeValue(plusTimeVal));
    }

    public static Date datePlus(Date date, long plusTime) {
        return Date.from(date.toInstant().plus(plusTime, ChronoUnit.MILLIS).atZone(ZoneId.systemDefault()).toInstant());
    }

    public static Date plus(String plusTimeVal) {
        return plus(parseTimeValue(plusTimeVal));
    }

    public static Date plus(long plusTimeVak) {
        return Date.from(nowPlus(plusTimeVak).atZone(ZoneId.systemDefault()).toInstant());
    }

    public static Date dateMinus(Date date, String minusTimeVal) {
        return dateMinus(date, parseTimeValue(minusTimeVal));
    }

    public static Date dateMinus(Date date, long minusTime) {
        return Date.from(date.toInstant().minus(minusTime, ChronoUnit.MILLIS).atZone(ZoneId.systemDefault()).toInstant());
    }

    public static Date minus(long minusTimeVal) {
        return Date.from(nowMinus(minusTimeVal).atZone(ZoneId.systemDefault()).toInstant());
    }

    public static Date minus(String minusTimeVal) {
        return minus(parseTimeValue(minusTimeVal));
    }

    public static String format(Date date) {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
        return simpleDateFormat.format(date);
    }

    public static String format(String pattern, Date date) {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat(pattern);
        return simpleDateFormat.format(date);
    }

    public static int maxDaysInMonth(int year, int month) {
        Calendar cal = Calendar.getInstance();
        cal.set(Calendar.YEAR, year);
        cal.set(Calendar.MONTH, month - 1);
        return cal.getActualMaximum(Calendar.DATE);
    }

    public static int[] currentYearAndMonth() {
        LocalDateTime now = LocalDateTime.now();
        return new int[]{now.getYear(), now.getMonthValue()};
    }

    public static int[] yesterdayYearAndMonth() {
        LocalDateTime localDateTime = nowMinus("1d");
        return new int[]{localDateTime.getYear(), localDateTime.getMonthValue()};
    }

    public static int currentYear() {
        return LocalDateTime.now().getYear();
    }

    public static int currentMonth() {
        return LocalDateTime.now().getMonthValue();
    }

    public static int currentDay() {
        return LocalDateTime.now().getDayOfMonth();
    }

    public static int currentHour() {
        return LocalDateTime.now().getHour();
    }

    public static int currentMinute() {
        return LocalDateTime.now().getMinute();
    }

    public static LocalDateTime nowPlus(long plusTime) {
        return LocalDateTime.now().plus(plusTime, ChronoUnit.MILLIS);
    }

    public static LocalDateTime nowPlus(String plusTimeVal) {
        return LocalDateTime.now().plus(parseTimeValue(plusTimeVal), ChronoUnit.MILLIS);
    }

    public static LocalDateTime nowMinus(long minusTime) {
        return LocalDateTime.now().minus(minusTime, ChronoUnit.MILLIS);
    }

    public static LocalDateTime nowMinus(String minusTimeVal) {
        return LocalDateTime.now().minus(parseTimeValue(minusTimeVal), ChronoUnit.MILLIS);
    }

    public static Date nextIntactDateForMinute() {
        Calendar ca = Calendar.getInstance();
        ca.set(Calendar.SECOND, 0);
        ca.set(Calendar.MILLISECOND, 0);
        ca.add(Calendar.MINUTE, 1);
        return ca.getTime();
    }

    public static Date nextIntactDateForDay() {
        Calendar ca = Calendar.getInstance();
        ca.set(Calendar.HOUR, 0);
        ca.set(Calendar.MINUTE, 0);
        ca.set(Calendar.SECOND, 0);
        ca.set(Calendar.MILLISECOND, 0);
        ca.add(Calendar.DAY_OF_MONTH, 1);
        return ca.getTime();
    }

}
