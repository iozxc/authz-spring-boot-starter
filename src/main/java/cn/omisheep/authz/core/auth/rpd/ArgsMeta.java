package cn.omisheep.authz.core.auth.rpd;

import cn.omisheep.authz.core.schema.Model;
import cn.omisheep.authz.core.schema.ModelParser;
import cn.omisheep.authz.core.util.LogUtils;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.google.common.base.Objects;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Getter
@Accessors(chain = true)
public class ArgsMeta {
    @JsonIgnore
    final Class<?>       type;
    @JsonIgnore
    final Method         method;
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    final List<Class<?>> parameters;
    @JsonIgnore
    final Class<?>       returnType;
    final Model          model;
    final String         ref;
    @Setter
    String description = "";

    private ArgsMeta(Class<?> type,
                     Method method) {
        this.type       = type;
        this.method     = method;
        this.returnType = method.getReturnType();
        this.parameters = Arrays.stream(method.getParameterTypes()).collect(Collectors.toList());
        this.model      = ModelParser.parse(method.getReturnType());
        String[] s = method.toString().split(" ");
        this.ref = s[s.length - 1];
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