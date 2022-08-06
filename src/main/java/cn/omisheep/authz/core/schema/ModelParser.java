package cn.omisheep.authz.core.schema;

import cn.omisheep.authz.core.auth.PermLibrary;
import com.fasterxml.classmate.*;
import com.fasterxml.classmate.members.ResolvedField;
import com.fasterxml.classmate.util.ClassStack;

import java.lang.reflect.Field;
import java.util.*;
import java.util.function.Predicate;

/**
 * @author zhouxinchen
 * @since 1.2.0
 */
public class ModelParser {

    private ModelParser() {
        throw new UnsupportedOperationException();
    }

    private static final TypeResolver   typeResolver   = new TypeResolver();
    private static final MemberResolver memberResolver = new MemberResolver(typeResolver);

    private static final AnnotationConfiguration.StdConfiguration stdAnnotationConfiguration = new AnnotationConfiguration.StdConfiguration(
            AnnotationInclusion.DONT_INCLUDE);

    private static final AnnotationOverrides.StdImpl stdAnnotationOverrides = new AnnotationOverrides.StdImpl(
            new HashMap<>());

    public static Model parse(Object obj) {
        Objects.requireNonNull(obj, "模型解析的对象不能为空");
        return parseModel(typeResolver.resolve(obj.getClass()), null);
    }

    public static Model parse(Class<?> clz) {
        Objects.requireNonNull(clz, "模型解析的类型不能为空");
        return parseModel(typeResolver.resolve(clz), null);
    }

    public static Model parse(ResolvedType mainType) {
        return parseModel(mainType, null);
    }

    public static Model parse(Object obj,
                              Predicate<Field> filter) {
        Objects.requireNonNull(obj, "模型解析的对象不能为空");
        return parseModel(typeResolver.resolve(obj.getClass()), filter);
    }

    public static Model parse(Class<?> clz,
                              Predicate<Field> filter) {
        Objects.requireNonNull(clz, "模型解析的类型不能为空");
        return parseModel(typeResolver.resolve(clz), filter);
    }

    public static Model parse(ResolvedType mainType,
                              Predicate<Field> filter) {
        return parseModel(mainType, filter);
    }

    public static String simpleTypeName(Class<?> type) {
        return ResolvedTypes.simpleTypeName(typeResolver.resolve(type));
    }

    public static Class<?> getUserIdType(Object o) {
        try {
            ResolvedType       resolve               = typeResolver.resolve(o.getClass());
            List<ResolvedType> implementedInterfaces = resolve.getParentClass().getImplementedInterfaces();
            Optional<ResolvedType> first = implementedInterfaces.stream()
                    .filter(v -> v.isInstanceOf(PermLibrary.class))
                    .findFirst();
            if (!first.isPresent()) {
                return Object.class;
            } else {
                return first.get().getTypeParameters().get(0).getErasedType();
            }
        } catch (Exception e) {
            return Object.class;
        }
    }

    private static ResolvedTypeWithMembers memberResolve(ResolvedType resolvedType) {
        return memberResolver.resolve(resolvedType, stdAnnotationConfiguration,
                                      stdAnnotationOverrides);
    }

    private static ModelMember parseMember(ResolvedType mainType,
                                           ClassStack classStack,
                                           Predicate<Field> filter) {
        ModelMember modelMember = new ModelMember(ResolvedTypes.simpleTypeName(mainType));

        if (Types.isEnum(mainType)) {
            if (classStack.find(mainType.getErasedType()) != null) {
                return modelMember;
            }
            String name = ResolvedTypes.simpleTypeName(mainType);
            Arrays.stream(mainType.getErasedType().getDeclaredFields()).filter(Field::isEnumConstant).forEach(e -> {
                modelMember.members.add(
                        new ModelMember(name, e.getName()));
            });
            return modelMember;
        }
        classStack = classStack.child(mainType.getErasedType());

        if (Types.isBaseType(mainType)) {
            return modelMember;
        } else if (mainType.isArray()) {
            ResolvedType arrayElementType = mainType.getArrayElementType();
            modelMember.setItem(new ModelObject());
            modelMember.getItem().setTypeName(ResolvedTypes.simpleTypeName(arrayElementType));
            if (!Types.isBaseType(arrayElementType)) {
                for (ResolvedField memberField : memberResolve(arrayElementType).getMemberFields()) {
                    ResolvedType fieldType  = memberField.getType();
                    Class<?>     erasedType = fieldType.getErasedType();
                    if (filter != null && filter.test(memberField.getRawMember())) {
                        continue;
                    }
                    if (classStack.find(erasedType) != null || Types.isBaseType(fieldType)) {
                        modelMember.members.add(
                                new ModelMember(ResolvedTypes.simpleTypeName(fieldType), memberField.getName()));
                    } else {
                        modelMember.members.add(
                                parseMember(fieldType, classStack, filter).setMemberName(
                                        memberField.getName()));
                    }
                }
            }
        } else if (mainType.isInstanceOf(Collection.class)) {
            if (mainType.getTypeParameters().size() == 0) {
                return modelMember;
            }
            ResolvedType resolvedType = mainType.getTypeParameters().get(0);
            if (classStack.find(resolvedType.getErasedType()) != null) {
                return modelMember;
            }
            ClassStack child = classStack.child(resolvedType.getErasedType());
            modelMember.setItem(new ModelObject());
            if (Types.isBaseType(mainType) || Types.isVoid(mainType) || mainType.getErasedType()
                    .getTypeName()
                    .startsWith("java.")) {
                modelMember.getItem().typeName = ResolvedTypes.simpleTypeName(resolvedType);
                return modelMember;
            }
            for (ResolvedField memberField : memberResolve(resolvedType).getMemberFields()) {
                ResolvedType fieldType  = memberField.getType();
                Class<?>     erasedType = fieldType.getErasedType();
                if (filter != null && filter.test(memberField.getRawMember())) {
                    continue;
                }
                if (child.find(erasedType) != null || Types.isBaseType(fieldType)) {
                    modelMember.getItem().getMembers()
                            .add(new ModelMember(ResolvedTypes.simpleTypeName(fieldType), memberField.getName()));
                } else {
                    modelMember.getItem().getMembers()
                            .add(parseMember(fieldType, child, filter).setTypeName(
                                    memberField.getName()));
                }
            }
        } else {
            for (ResolvedField memberField : memberResolve(mainType).getMemberFields()) {
                ResolvedType fieldType  = memberField.getType();
                Class<?>     erasedType = fieldType.getErasedType();
                if (filter != null && filter.test(memberField.getRawMember())) {
                    continue;
                }
                if (classStack.find(erasedType) != null || Types.isBaseType(fieldType)) {
                    modelMember.members.add(
                            new ModelMember(ResolvedTypes.simpleTypeName(fieldType), memberField.getName()));
                } else {
                    modelMember.members.add(
                            parseMember(fieldType, classStack, filter).setMemberName(
                                    memberField.getName()));
                }
            }
        }
        return modelMember;

    }

    private static ModelArray parseModelArray(ResolvedType mainType,
                                              Predicate<Field> filter) {
        ModelArray   modelArray                 = new ModelArray();
        ResolvedType arrayElementType           = mainType.getArrayElementType();
        Class<?>     arrayElementTypeErasedType = arrayElementType.getErasedType();

        ClassStack classStack = new ClassStack(arrayElementTypeErasedType);
        modelArray.getItem().setTypeName(ResolvedTypes.simpleTypeName(arrayElementType));
        if (Types.isBaseType(arrayElementType)) {
            return modelArray;
        } else {
            for (ResolvedField memberField : memberResolve(arrayElementType).getMemberFields()) {
                ResolvedType fieldType  = memberField.getType();
                Class<?>     erasedType = fieldType.getErasedType();
                if (filter != null && filter.test(memberField.getRawMember())) {
                    continue;
                }
                if (classStack.find(erasedType) != null || Types.isBaseType(fieldType)) {
                    modelArray.getItem().members.add(
                            new ModelMember(ResolvedTypes.simpleTypeName(fieldType), memberField.getName()));
                } else {
                    modelArray.getItem().members.add(
                            parseMember(fieldType, classStack, filter).setMemberName(
                                    memberField.getName()));
                }
            }
        }
        return modelArray;
    }

    private static ModelCollection parseModelCollection(ResolvedType mainType,
                                                        Predicate<Field> filter) {
        ModelCollection modelCollection = new ModelCollection(ResolvedTypes.simpleTypeName(mainType));
        if (mainType.getTypeParameters().size() == 0) return modelCollection;
        ResolvedType resolvedType        = mainType.getTypeParameters().get(0);
        Class<?>     parameterErasedType = resolvedType.getErasedType();
        ClassStack   classStack          = new ClassStack(parameterErasedType);
        modelCollection.getItem().setTypeName(ResolvedTypes.simpleTypeName(resolvedType));
        if (Types.isBaseType(resolvedType)) {
            return modelCollection;
        }
        for (ResolvedField memberField : memberResolve(resolvedType).getMemberFields()) {
            ResolvedType fieldType  = memberField.getType();
            Class<?>     erasedType = fieldType.getErasedType();
            if (filter != null && filter.test(memberField.getRawMember())) {
                continue;
            }
            if (classStack.find(erasedType) != null || Types.isBaseType(fieldType)) {
                modelCollection.getItem().members.add(
                        new ModelMember(ResolvedTypes.simpleTypeName(fieldType), memberField.getName()));
            } else {
                modelCollection.getItem().members.add(
                        parseMember(fieldType, classStack, filter).setMemberName(
                                memberField.getName()));
            }
        }
        return modelCollection;
    }

    private static ModelObject parseModelObject(ResolvedType mainType,
                                                Predicate<Field> filter) {
        Class<?>    mainTypeErasedType = mainType.getErasedType();
        ClassStack  classStack         = new ClassStack(mainTypeErasedType);
        ModelObject modelObject        = new ModelObject(ResolvedTypes.simpleTypeName(mainType));
        for (ResolvedField memberField : memberResolve(mainType).getMemberFields()) {
            ResolvedType fieldType = memberField.getType();
            if (filter != null && filter.test(memberField.getRawMember())) {
                continue;
            }
            Class<?> erasedType = fieldType.getErasedType();
            if (classStack.find(erasedType) != null || Types.isBaseType(fieldType)) {
                modelObject.members.add(
                        new ModelMember(ResolvedTypes.simpleTypeName(fieldType), memberField.getName()));
            } else {
                modelObject.members.add(
                        parseMember(fieldType, classStack, filter).setMemberName(
                                memberField.getName()));
            }
        }
        return modelObject;
    }

    private static Model parseModel(ResolvedType mainType,
                                    Predicate<Field> filter) {

        if (Types.isBaseType(mainType) || Types.isVoid(mainType) || mainType.getErasedType()
                .getTypeName()
                .startsWith("java.")) {
            return new Model(ResolvedTypes.simpleTypeName(mainType));
        } else {
            if (mainType.isArray()) {
                return parseModelArray(mainType, filter);
            } else if (mainType.isInstanceOf(Collection.class)) {
                return parseModelCollection(mainType, filter);
            } else {
                return parseModelObject(mainType, filter);
            }
        }
    }

}
