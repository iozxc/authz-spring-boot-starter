package cn.omisheep.authz.core.aggregate;

import cn.omisheep.authz.core.util.CapacityRestrictedQueue;
import cn.omisheep.authz.core.util.TimeUtils;
import lombok.Data;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.util.Arrays;

/**
 * qq: 1269670415
 *
 * @author zhou xin chen
 */
@Data
public class LatestHours implements Summable, Serializable {

    private static final long serialVersionUID = -3679258668123086765L;

    private long[] list;
    private long total;

    private final CapacityRestrictedQueue<Hour> hours;

    public LatestHours() {
        this(24);
    }

    public LatestHours(int maxCapacity) {
        hours = new CapacityRestrictedQueue<>(maxCapacity);
    }

    public void update(int minute, int num) {
        if (hours.size() == 0) {
            hours.offerFirst(new Hour());
            hours.getFirst().setMinute(minute, num);
        } else {
            Hour first = hours.getFirst();
            first.setMinute(minute, num);
            if (first.getHour() != TimeUtils.currentHour()) {
                hours.offerFirst(new Hour());
            }
        }

        this.list = hours.stream().mapToLong(Summable::getTotal).toArray();
        this.total = Arrays.stream(list).sum();
    }

    public void update(int num) {
        update((TimeUtils.currentMinute() - 1 + 60) % 60, num);
    }

    @Data
    public static class Hour implements Summable, Serializable {

        private static final long serialVersionUID = -64338996914080622L;
        private long[] minutes = new long[60];
        private long total = 0;

        private final String date = TimeUtils.nowString("y-M-d_h");
        private final int hour = TimeUtils.currentHour();

        public Hour() {
            // to json string or serialize
        }

        public void setMinute(int minute, long num) {
            Assert.isTrue(num >= 0, "ensure num > 0");
            Assert.isTrue(minute >= 0 && minute <= 59, "ensure minute from 0 to 59");
            total += num - minutes[minute];
            minutes[minute] = num;
        }
    }


}
