package cn.omisheep.authz.core.schema;

import com.fasterxml.classmate.ResolvedType;
import com.fasterxml.classmate.types.ResolvedArrayType;

public class ResolvedTypes {

    private ResolvedTypes() {
        throw new UnsupportedOperationException();
    }

    public static String simpleTypeName(ResolvedType type) {
        String name = Types.typeNameFor(type.getErasedType());
        if (name == null) {
            return type instanceof ResolvedArrayType ? "Array" : type.getErasedType().getSimpleName();
        } else {
            return name;
        }
    }

}
