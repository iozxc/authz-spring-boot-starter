package cn.omisheep.authz.core.auth.rpd;

import cn.omisheep.authz.core.util.LogUtils;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.google.common.base.Objects;
import lombok.Getter;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Getter
public class ArgsMeta {
    final Class<?>            type;
    final Method              method;
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    final List<Class<?>>      parameterList;
    final Class<?>            returnType;
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    final Map<String, String> returnTypeTemplate;

    private ArgsMeta(Class<?> type,
                     Method method) {
        this.type               = type;
        this.method             = method;
        this.returnType         = method.getReturnType();
        this.parameterList      = Arrays.stream(method.getParameterTypes()).collect(Collectors.toList());
        this.returnTypeTemplate = ArgsHandler.parseTypeForTemplate(this.returnType.getTypeName());
    }

    public String getMethod() {
        return method.getName();
    }

    public static ArgsMeta of(Class<?> type,
                              Method method) {
        return new ArgsMeta(type, method);
    }

    public static ArgsMeta of(Class<?> type,
                              String methodName,
                              Class<?>... args) {
        try {
            return new ArgsMeta(type, type.getMethod(methodName, args));
        } catch (NoSuchMethodException e) {
            LogUtils.error("NoSuchMethodException", e);
            return null;
        }
    }

    public static ArgsMeta of(Object type,
                              String methodName,
                              Class<?>... args) {
        return of(type.getClass(), methodName, args);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ArgsMeta)) return false;
        ArgsMeta meta = (ArgsMeta) o;
        return Objects.equal(method, meta.method) && Objects.equal(type, meta.type);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(method, type);
    }
}