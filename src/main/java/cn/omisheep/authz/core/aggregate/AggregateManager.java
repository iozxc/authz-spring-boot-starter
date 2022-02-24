package cn.omisheep.authz.core.aggregate;

import cn.omisheep.authz.annotation.Aggregate;
import cn.omisheep.authz.annotation.StatisticalType;
import cn.omisheep.authz.core.auth.ipf.HttpMeta;
import cn.omisheep.authz.core.tk.Token;
import cn.omisheep.authz.core.util.AUtils;
import com.clearspring.analytics.stream.cardinality.HyperLogLog;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.core.annotation.AnnotationUtils;

import java.util.Arrays;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @version 1.0.0
 * @since 1.0.0
 */
@Aspect
@Slf4j
public class AggregateManager {

    @Getter
    private final Details details = new Details();

    @Getter
    private static final HashMap<StatisticalType, ConcurrentHashMap<String, Object>> cmp = new HashMap<>();

    static {
        Arrays.stream(StatisticalType.values()).forEach(type -> cmp.put(type, new ConcurrentHashMap<>()));
    }

    @Pointcut("@annotation(cn.omisheep.authz.annotation.Aggregate)")
    public void hasAggregate() {
    }


    @Before("hasAggregate()")
    public void Before(JoinPoint joinPoint) {
        MethodSignature methodSignature = (MethodSignature) joinPoint.getSignature();
        Aggregate a1 = AnnotationUtils.getAnnotation(methodSignature.getMethod(), Aggregate.class);
        Aggregate a2 = AnnotationUtils.getAnnotation(joinPoint.getSignature().getDeclaringType(), Aggregate.class);
        StatisticalType[] types = Stream.concat(Arrays.stream(a1 != null ? a1.statisticalType() : new StatisticalType[0]), Arrays.stream(a2 != null ? a2.statisticalType() : new StatisticalType[0])).distinct().toArray(StatisticalType[]::new);

        HttpMeta currentHttpMeta = AUtils.getCurrentHttpMeta();
        if (currentHttpMeta == null) {
            return;
        }
        String scope = a1 != null ? a1.scope() : "";
        if (a2 != null && !a2.scope().equals("")) {
            scope = a2.scope();
        }

        for (StatisticalType type : types) {
            switch (type) {
                case PV:
                    pv(currentHttpMeta, scope);
                    break;
                case UV:
                    uv(currentHttpMeta, scope);
                    break;
                case IP:
                    ip(currentHttpMeta, scope);
                    break;
            }
        }

    }

    /*
     * 统计uv
     */
    public void uv(HttpMeta httpMeta, String scope) {
        Token token = httpMeta.getToken();
        if (token != null) {
            HyperLogLog hyperLogLog = (HyperLogLog) cmp.get(StatisticalType.UV).computeIfAbsent(scope, k -> new HyperLogLog(0.0001));
            hyperLogLog.offer(token.getUserId());
        }
    }

    /*
     * 统计ip
     */
    public void ip(HttpMeta httpMeta, String scope) {
        String ip = httpMeta.getIp();
        HyperLogLog hyperLogLog = (HyperLogLog) cmp.get(StatisticalType.IP).computeIfAbsent(scope, k -> new HyperLogLog(0.0001));
        hyperLogLog.offer(ip);
    }

    public void pv(HttpMeta httpMeta, String scope) {
        long d = (long) cmp.get(StatisticalType.PV).computeIfAbsent(scope, k -> 0L);
        d += 1;
        System.out.println(d);
    }


}
