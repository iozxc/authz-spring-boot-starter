package cn.omisheep.authz.core.schema;

import com.fasterxml.classmate.*;
import com.fasterxml.classmate.members.ResolvedField;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class ModelParser {
    private static final TypeResolver   typeResolver   = new TypeResolver();
    private static final MemberResolver memberResolver = new MemberResolver(typeResolver);

    private static final AnnotationConfiguration.StdConfiguration stdAnnotationConfiguration = new AnnotationConfiguration.StdConfiguration(
            AnnotationInclusion.DONT_INCLUDE);

    private static final AnnotationOverrides.StdImpl stdAnnotationOverrides = new AnnotationOverrides.StdImpl(
            new HashMap<>());


    public static String simpleQualifiedTypeName(Class<?> type) {
        return ResolvedTypes.simpleQualifiedTypeName(typeResolver.resolve(type));
    }

    public static String simpleTypeName(Class<?> type) {
        return ResolvedTypes.simpleTypeName(typeResolver.resolve(type));
    }

    public static ResolvedTypeWithMembers memberResolve(ResolvedType resolvedType) {
        return memberResolver.resolve(resolvedType, stdAnnotationConfiguration,
                                      stdAnnotationOverrides);
    }


    public static ModelMember parseMember(ResolvedType mainType) {
        String      typeNameFor = ResolvedTypes.simpleQualifiedTypeName(mainType);
        ModelMember modelMember = new ModelMember(typeNameFor);

        if (Types.isBaseType(mainType)) {
            return modelMember;
        } else if (mainType.isArray()) {

        } else if (mainType.isInstanceOf(Collection.class)) {
            modelMember.setMembers(new ArrayList<>());
            for (ResolvedField memberField : memberResolve(mainType.getTypeParameters().get(0)).getMemberFields()) {
                ResolvedType fieldType = memberField.getType();
                if (Types.isBaseType(fieldType)) {
                    modelMember.getMembers().add(new ModelMember(Types.typeNameFor(fieldType), memberField.getName()));
                } else {
                    modelMember.getMembers().add(parseMember(fieldType));
                }
            }
        }

        return modelMember;
    }


    public static Model parseModel(ResolvedType mainType) {
        String typeNameFor = ResolvedTypes.simpleQualifiedTypeName(mainType);
        Model  model       = new Model(typeNameFor);
        if (Types.isBaseType(mainType)) {
            return model;
        } else {
            model.setMembers(new ArrayList<>());
            if (mainType.isArray()) {
                model.setArray(true);
            } else if (mainType.isInstanceOf(Collection.class)) {
                model.setCollection(true);
                for (ResolvedField memberField : memberResolve(mainType.getTypeParameters().get(0)).getMemberFields()) {
                    ResolvedType fieldType = memberField.getType();
                    if (Types.isBaseType(fieldType)) {
                        model.getMembers().add(new ModelMember(Types.typeNameFor(fieldType), memberField.getName()));
                    } else {
                        model.getMembers().add(parseMember(fieldType));
                    }
                }
            } else {
                for (ResolvedField memberField : memberResolve(mainType).getMemberFields()) {
                    ResolvedType fieldType = memberField.getType();
                    if (Types.isBaseType(fieldType)) {
                        model.getMembers().add(new ModelMember(Types.typeNameFor(fieldType), memberField.getName()));
                    } else {
                        model.getMembers().add(parseMember(fieldType));
                    }
                }
            }
        }


        return model;
    }

    public static Model parse(ResolvedType mainType) {
        return parseModel(mainType);
    }

}
