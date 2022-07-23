package cn.omisheep.authz.core.config;

import cn.omisheep.authz.core.slot.Slot;
import cn.omisheep.authz.core.slot.SlotScan;
import cn.omisheep.authz.core.util.ScanUtils;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.lang.NonNull;

import java.util.Map;

/**
 * @author zhouxinchen[1269670415@qq.com]
 * @since 1.0.0
 */
public class SlotImportSelector implements ImportSelector {

    @NonNull
    @Override
    public String[] selectImports(AnnotationMetadata importingClassMetadata) {
        Map<String, Object> annotationAttributes = importingClassMetadata.getAnnotationAttributes(SlotScan.class.getName());
        String[]            basePackages         = new String[0];
        if (annotationAttributes != null) basePackages = (String[]) annotationAttributes.get("basePackages");
        return ScanUtils.scan(Slot.class, basePackages);
    }

}