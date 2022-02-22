package cn.omisheep.authz.core.auth.ipf;

import cn.omisheep.commons.util.TimeUtils;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang.builder.HashCodeBuilder;

import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
public class IpMeta {
    @Getter
    private final String ip;
    @Getter
    private boolean ban;

    private long reliveTime = 0;

    private final LinkedList<Long> requestTimeList = new LinkedList<>();

    @Setter
    private long lastRequestTime;

    @JsonFormat(pattern = "yyyy-MM-dd hh:mm:ss:SSS")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public Date getReliveTime() {
        return reliveTime == 0 ? null : new Date(reliveTime);
    }

    @JsonFormat(pattern = "yyyy-MM-dd hh:mm:ss:SSS")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public List<Date> getRequestTimeList() {
        return requestTimeList.stream().map(Date::new).collect(Collectors.toList());
    }

    @JsonFormat(pattern = "yyyy-MM-dd hh:mm:ss:SSS")
    public Date getLastRequestTime() {
        return new Date(lastRequestTime);
    }

    public IpMeta(String ip) {
        this.ip = ip;
        request(1, 0, 0);
    }

    public boolean enableRelive(long now) {
        return reliveTime <= now;
    }

    public void relive() {
        if (this.ban) {
            this.ban = false;
            this.reliveTime = 0;
        }
    }

    public IpMeta forbidden(long punishmentTime) {
        this.reliveTime = punishmentTime + new Date().getTime();
        requestTimeList.clear();
        this.ban = true;
        return this;
    }

    /**
     * @param maxRequests 请求限制最大次数
     * @param window      时间窗口
     * @param minInterval 最小请求间隔时间
     * @return 访问是否成功
     */
    public boolean request(int maxRequests, long window, long minInterval) {
        long now = TimeUtils.nowTime();

        Long lastSecond = null;
        if (!requestTimeList.isEmpty()) {
            lastSecond = requestTimeList.getLast(); 
            lastRequestTime = lastSecond;
        } else {
            if (lastRequestTime == 0) lastRequestTime = now;
        }

        requestTimeList.removeIf(time -> (now - time) > window);

        requestTimeList.offer(now);
        Long lastFirst = requestTimeList.getLast();

        if (minInterval > 0 && lastSecond != null) {
            if (lastFirst - lastSecond < minInterval) {
                return false; // 请求间隔太短，封禁
            }
        }

        while (requestTimeList.size() - 1 > maxRequests) {
            requestTimeList.pollFirst();
        }

        if (requestTimeList.size() > maxRequests) {
            Long first = requestTimeList.getFirst();
            return lastFirst - first >= window;
        }

        return true;
    }

    public String sinceLastTime() {
        return TimeUtils.parseTime(new Date().getTime() - lastRequestTime);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;

        if (o == null || getClass() != o.getClass()) return false;

        IpMeta ipMeta = (IpMeta) o;

        return ip.equals(ipMeta.ip)
                && ipMeta.reliveTime < reliveTime;
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37)
                .append(ip)
                .toHashCode();
    }
}