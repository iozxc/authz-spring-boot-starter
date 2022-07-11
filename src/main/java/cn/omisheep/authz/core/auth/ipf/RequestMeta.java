package cn.omisheep.authz.core.auth.ipf;

import cn.omisheep.authz.core.callback.RateLimitCallback;
import cn.omisheep.commons.util.TimeUtils;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;
import org.apache.commons.lang.builder.HashCodeBuilder;

import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class RequestMeta {
    @Getter
    private final  String            ip;
    @Getter
    private final  Object            userId;
    @Getter
    private        boolean           ban;
    private        int               punishmentLevel;
    private        long              reliveTime;
    private        long              lastRequestTime;
    private        long              sinceLastTime;
    private final  LinkedList<Long>  requestTimeList = new LinkedList<>();
    private static RateLimitCallback callback;

    protected static void setCallback(RateLimitCallback callback) {
        RequestMeta.callback = callback;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public Date getReliveTime() {
        return ban ? new Date(reliveTime) : null;
    }

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public List<Date> getRequestTimeList() {
        return requestTimeList.stream().map(Date::new).collect(Collectors.toList());
    }

    public void setLastRequestTime(long lastRequestTime) {
        this.sinceLastTime   = lastRequestTime - this.lastRequestTime;
        this.lastRequestTime = lastRequestTime;
    }

    public Date getLastRequestTime() {
        return new Date(lastRequestTime);
    }

    public RequestMeta(long now, String ip, Object userId) {
        this.ip     = ip;
        this.userId = userId;
        request(now, 1, 0, 0);
    }

    public boolean enableRelive(long now) {
        return reliveTime <= now;
    }

    public void relive(String method, String api, LimitMeta limitMeta) {
        ban = false;
        callback.relive(method, api, ip, userId, limitMeta);
    }

    public RequestMeta forbidden(String method, String api, LimitMeta limitMeta) {
        long       nowTime        = TimeUtils.nowTime();
        List<Long> punishmentTime = limitMeta.getPunishmentTime();
        if (punishmentTime == null) return this;
        // 惩罚升级
        punishmentLevel++;
        if (punishmentLevel <= punishmentTime.size()) {
            reliveTime = punishmentTime.get(punishmentLevel - 1) + nowTime;
        } else {
            reliveTime = punishmentTime.get(punishmentTime.size() - 1) + nowTime;
        }
        requestTimeList.clear();
        ban = true;
        if (callback != null) callback.forbid(method, api, ip, userId, limitMeta, new Date(reliveTime));
        return this;
    }

    public boolean pushRequest(long now, int maxRequests, long window, long minInterval) {
        if (requestTimeList.isEmpty() || requestTimeList.getLast() < now) {
            return request(now, maxRequests, window, minInterval);
        }

        for (int i = 0; i < requestTimeList.size(); i++) {
            if (requestTimeList.get(i) >= now) {
                requestTimeList.add(i, now);
                break;
            }
        }

        int size = requestTimeList.size();
        if (minInterval > 0 && size >= 2) {
            if (requestTimeList.get(size - 1) - requestTimeList.get(size - 2) > minInterval) {
                return false;
            }
        }

        if (size > maxRequests) {
            Long first = requestTimeList.getFirst();
            return requestTimeList.getLast() - first >= window;
        }
        return true;
    }


    public boolean pushRequest(long now, LimitMeta limitMeta) {
        return pushRequest(now, limitMeta.getMaxRequests(), limitMeta.getWindow(), limitMeta.getMinInterval());
    }

    /**
     * @param now         nowMills
     * @param maxRequests 请求限制最大次数
     * @param window      时间窗口
     * @param minInterval 最小请求间隔时间
     * @return 访问是否成功
     */
    public boolean request(long now, int maxRequests, long window, long minInterval) {
        // 过了一个周期后，惩罚等级归零
        if (now - reliveTime > window) punishmentLevel = 0;

        Long lastSecond = null;
        if (!requestTimeList.isEmpty()) {
            lastSecond    = requestTimeList.getLast();
            sinceLastTime = now - lastSecond;
        }
        lastRequestTime = now;

        requestTimeList.removeIf(time -> (now - time) > window);
        requestTimeList.offer(now);
        Long lastFirst = requestTimeList.getLast();

        if (minInterval > 0 && lastSecond != null) {
            if (lastFirst - lastSecond < minInterval) {
                return false; // 请求间隔太短，封禁
            }
        }

        while (requestTimeList.size() - 1 > maxRequests) requestTimeList.pollFirst();

        if (requestTimeList.size() > maxRequests) {
            Long first = requestTimeList.getFirst();
            return lastFirst - first >= window;
        }

        return true;
    }

    public String sinceLastTime() {
        return TimeUtils.parseTime(sinceLastTime);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RequestMeta ipMeta = (RequestMeta) o;
        return Objects.equals(ip, ipMeta.ip) && Objects.equals(userId, ipMeta.userId) && ipMeta.reliveTime < reliveTime;
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37).append(ip).toHashCode();
    }
}