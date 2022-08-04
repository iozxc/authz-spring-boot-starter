package cn.omisheep.authz.core.schema;

import com.fasterxml.classmate.ResolvedType;
import com.fasterxml.classmate.types.ResolvedArrayType;
import com.fasterxml.classmate.types.ResolvedPrimitiveType;

import java.lang.reflect.Type;

public class ResolvedTypes {

    private ResolvedTypes() {
        throw new UnsupportedOperationException();
    }

    public static String simpleQualifiedTypeName(ResolvedType type) {
        if (type instanceof ResolvedPrimitiveType) {
            Type primitiveType = type.getErasedType();
            return Types.typeNameFor(primitiveType);
        } else {
            return type instanceof ResolvedArrayType ? Types.typeNameFor(
                    type.getArrayElementType().getErasedType()) : type.getErasedType().getName();
        }
    }

    public static String simpleTypeName(ResolvedType type) {
        String name = Types.typeNameFor(type.getErasedType());
        if (name == null) {
            return type instanceof ResolvedArrayType ? Types.typeNameFor(
                    type.getArrayElementType().getErasedType()) : type.getErasedType().getName();
        } else {
            return name;
        }
    }

}
