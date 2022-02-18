package cn.omisheep.authz.core.auth.ipf;

import cn.omisheep.authz.core.util.TimeUtils;
import lombok.Getter;
import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;

import java.util.Date;
import java.util.LinkedList;

/**
 * @author zhou xin chen
 */
public class IpMeta {
    @Getter
    private final String ip;
    @Getter
    private boolean ban;
    @Getter
    private long reliveTime;
    private final LinkedList<Long> linkedList = new LinkedList<>();
    private long lastRequestTime;

    public IpMeta(String ip) {
        this.ip = ip;
        request(1, 0, 0);
    }

    public void relive() {
        this.ban = false;
    }

    public void forbidden(long reliveTime) {
        this.reliveTime = reliveTime + new Date().getTime();
        linkedList.clear();
        this.ban = true;
    }

    /**
     * @param limitMaxCount 请求限制最大次数
     * @param limitTime     限制时间
     * @param interval      请求间隔时间
     * @return 访问是否成功
     */
    public boolean request(int limitMaxCount, long limitTime, long interval) {
        long now = TimeUtils.nowTime();

        Long lastSecond = null;
        if (!linkedList.isEmpty()) {
            lastSecond = linkedList.getLast(); // 倒数第二个
            lastRequestTime = lastSecond;
        } else {
            lastRequestTime = now;
        }

        linkedList.offer(now);
        Long lastFirst = linkedList.getLast();

        if (interval > 0 && lastSecond != null) {
            if (lastFirst - lastSecond < interval) {
                return false; // 请求间隔太短，封禁
            }
        }

        while (linkedList.size() - 1 > limitMaxCount) {
            linkedList.pollFirst();
        }

        if (linkedList.size() > limitMaxCount) {
            Long first = linkedList.getFirst(); // 第一个
            return lastFirst - first >= limitTime;
        }

        return true;
    }

    public String lastTime() {
        return TimeUtils.parseTime(new Date().getTime() - lastRequestTime);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;

        if (o == null || getClass() != o.getClass()) return false;

        IpMeta ipMeta = (IpMeta) o;

        return new EqualsBuilder()
                .append(ip, ipMeta.ip)
                .isEquals()
                && ipMeta.reliveTime < reliveTime;
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37)
                .append(ip)
                .toHashCode();
    }
}