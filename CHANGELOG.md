# 更新日记【Authz】

## Version 1.1.3 - 2022.7.12

### Added

- 现在可以对默认返回体对状态码做出一点点调整

### Fixed

- 修复了一些bug

## Version 1.1.2 - 2022.7.12

### Added

- 添加了banner和版本号的打印
- 修改了一些目录结构

## Version 1.1.1 - 2022.7.11

### Added

1. 为了弥补封禁类型，新增 **封禁时和解封时** 的【回调函数】，可以在程序初始化时调用，或者直接继承`cn.omisheep.authz.core.callback.RateLimitCallback`接口并将其注入Spring。

```java
import cn.omisheep.authz.AuHelper;

class Main {
    void test() {
        AuHelper.Callback.setRateLimitCallback((v1, v2, v3, v4, v5, v6) -> {
            ...
        });
    }
}
```

2. 新增根据userId进行RateLimit限制。
3. 对参数权限进行限制时，在参数配置时可以使用`@ArgResource`标注过的资源了，用法与数据权限中的condition用法一致。

```java
public class ArgResourceTest {
    @ArgResource("name")
    public static String name() {
        return "ooo";
    }

    @ArgResource
    public static int id() {
        return 123;
    }
}

@RestController
class Main {
    // 参数name为ooo时，必须需要role包含zxc  
    // id为177时必须需要admin权限
    // zxc 能够访问id属于123-156 不能访问177
    // admin 能够访问id属于146-200
    // 如果某个用户有两个角色，那么取并集。如 zxc,admin 能访问123-200
    @Roles({"admin", "zxc"})
    @GetMapping("/get/{name}/{id}")
    public Result getPath2(@Roles(value = "zxc", paramResources = "#{name}") @PathVariable String name,
                           @BatchAuthority(roles = {
                                   @Roles(value = "zxc", paramRange = {"#{id}-156", "177"}),
                                   @Roles(value = "admin", paramRange = "146-200", paramResources = "177")
                           }) @PathVariable int id) {
    ...
    }
}
```

### Fixed

- 修复了一些bug和文字描述
- 优化了部分代码

### Removed

- 移除`cn.omisheep.authz.annotation.Auth`,`cn.omisheep.authz.annotation.BannedType`
- 移除封禁类型，现在只能封禁API

## Version 1.1.0 - 2022.7.11

### Added

- 新增app范围限制，避免不同应用在同一redis中启动的情况下出现数据污染

```yaml
authz:
  app: omisheep1
  ...
```

```yaml
authz:
  app: omisheep2
  ...
```

- 新增主动封禁功能，如下。
    - 现在能够主动对【某用户 - by `userId` `deviceType` `deviceId` `ip` `iprange`】进行封禁xx时间
    - 解除封禁（触发RateLimit的无法解除）
    - 修改封禁时间
    - 查看封禁信息

```java
import cn.omisheep.authz.AuHelper;

class Main {
    public void test() {
        AuHelper.denyUser(1, "2s"); // 对用户1进行封禁2秒
        AuHelper.denyUser(2, "mac", "10s"); // 对用户2的mac设备进行封禁10秒
        AuHelper.removeDenyUser(1); // 移除用户1的封禁
        AuHelper.denyIPRange("10.2.0.0/24", "10d"); // 对10.2.0.0/24网段下的IP进行封禁10天
        AuHelper.denyIP("10.2.0.2", "10d"); // 对ip 10.2.0.2进行封禁10天
    }
}
```

### Fixed

- 修改了`cn.omisheep.authz.core.slot.Slot`接口
  在其内的chain方法不在返回值，若此slot需要返回错误并且中断之后的slot，则调用`cn.omisheep.authz.core.slot.Error`函数接口中error方法即可

## Version 1.0.13 - 2022.7.9

### Fixed

- 路径匹配异常
- AuHelper中部分方法返回结果与预期不一致（标记为@Nonnull结果返回为空）

## Version 1.0.12 - 2022.7.8

### Fixed

- AuKey rename -> AuthzRSAManager
- 优化了解码部分的代码

## Version 1.0.11 - 2022.7.8

### Added

- 自定义解码器 （需注册在Spring容器中且实现`cn.omisheep.authz.core.codec.Decryptor`类）

## Version 1.0.10 - 2022.7.8

### Added

- 现在`@Roles` `@Perms` `@Certificated`能够作用于非Mapping上进行权限拦截了。
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
import org.springframework.web.bind.annotation.RestController;

@RestController
class MainController {
    @GetMapping("/get")
    public Result get(@Decrypt("name") String name) {
        return Result.SUCCESS.data("name", name);
    }

    @PostMapping("/post")
    public Result post(@Decrypt({"name", "content", "obj.name"}) @RequestBody HashMap<String, Object> map) {
        return Result.SUCCESS.data("map", map);
    }
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
