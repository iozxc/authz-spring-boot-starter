# 更新日记【Authz】

## Version 1.0.11 - 2022.7.8

### Added

- 自定义解码器 （需注册在Spring容器中且实现`cn.omisheep.authz.core.codec.Decryptor`类）

## Version 1.0.10 - 2022.7.8

### Added

- 现在`@Roles` `@Perms` `@Certificated`能够作用与非Mapping上进行权限拦截了。
- 如：对`MyService`中的`test方法`进行登录检查

```java
import cn.omisheep.authz.annotation.Certificated;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@RequestMapping("/method-test")
public class MethodTestController {

    @Autowired
    private MyService myService;

    @GetMapping("/u")
    public Result u1() {
        return Result.SUCCESS.data(myService.test());
    }
}

@Service
public class MyService {
    @Certificated
    public List<Object> test() {
        return new ArrayList<Object>();
    }
}
```

## Version 1.0.9 - 2022.7.7

### Added

- 对于`@Decrypt` 新增了对象加密解密功能，支持对对象内某一个字段进行单独加密以及对整体加密，以及参数加密

```java
@GetMapping("/get")
public Result get(@Decrypt("name") String name){
        return Result.SUCCESS.data("name",name);
        }

@PostMapping("/post")
public Result post(@Decrypt({"name", "content", "obj.name"}) @RequestBody HashMap<String, Object> map){
        return Result.SUCCESS.data("map",map);
        }
```

- 若`@Decrypt`无参，则key无限制,但值必须为整个加密的json，如

```json
{
  "key名无限制": "value为整个json加密后的值，包含 `{` `}`"
}
```

## Version 1.0.8 - 2022.7.5

### Fixed

- 修复了一些bug

## Version 1.0.7 - 2022.7.5

### Fixed

- 修复了一些bug

## Version 1.0.6 - 2022.7.1

### Fixed

- 修复了一些依赖bug
- 修复了ObservableMap的兼容问题

## Version 1.0.5 - 2022.5.29

### Fixed

- 修复了一些bug
- 对于数据权限的yml配置进行了修改

```yaml
authz:
  orm: mybatis
```

## Version 1.0.4 - 2022.5.28

### Fixed

- 修复了一些bug

## Version 1.0.3 - 2022.5.28

### Added

- 增加了md5校验

### Fixed

- 修复了在数据权限匹配时，如果为多角色，则condition为AND的错误。（应该为OR）

## Version 1.0.2 - 2022.5.27

### Added

- 添加了新的注解 `@Certificated`
    - 用于一些只需要验证是否登录并不需要验证身份和权限的接口上。若作用于controller上则此内部的api都需要登录

### Fixed

- 删除L2Cache对Keys的缓存
- 修复了对1.0.1版本中type类名字修改之后之前版本json转换错误的问题

## Version 1.0.1 - 2022.5.24

### Modify

- 修改了Token内部类Type的枚举类型名字

### Fixed

- 修复了在Controller上添加@Roles、@Permissions标签时，如果方法上没有注解的话报空指针异常的问题

## Version 1.0.0 - 2022.5.16

### desc

> 在前一个beta版本上优化了api。删除了一些用不到的功能。添加了一些新的功能

### Added

- AuHelper文档的完善
- 添加了数据的列权限，现在有两种数据权限
- 完善了参数权限（其中i的优先级高于ii）
    1. 限制某些参数，只有拥有指定的`角色(权限)`或`角色(权限)组`才能使用
    2. 限制指定的某个`角色(权限)`或`角色(权限)组`使用的参数内容(范围)
- 给出了统一的修改接口
    1. `api`和`api参数`的动态权限接口
    2. 数据 `行` `列` 的动态权限接口
    3. 请求速率限制rateLimit的动态权限接口
- 微服务下的同服务不同实例之间
    1. 同步了request，共享request池，以达到同步forbid和同步解封
    2. 同步了配置，只要在任意一台服务内配置，其他服务就会同步
- 添加了动态配置的页面，现在可以在页面配置了（简略版）
- 添加自定义RSA公私钥功能

### Removed

- 移除未完善的统计功能

### Fixed

- 修复了SpringBoot2.6版本不兼容问题
- 部分API的调整 避免了空指针的问题

## Version 1.0.0.BETA1 - 2022.5.5

### desc

> beta版本
