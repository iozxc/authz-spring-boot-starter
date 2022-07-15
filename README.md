### Authz - (authz-spring-boot-starter)

## 动态权限框架 - 简单介绍

> [Authz](https://github.com/iozxc/authz-spring-boot-starter) 
- gitee地址 https://gitee.com/iozxc/authz-spring-boot-starter
- github地址 https://github.com/iozxc/authz-spring-boot-starter
- 更新日志 <a href='CHANGELOG.md'>CHANGELOG.md</a>

![Authz](http://cdn.omisheep.cn/upload/img/article/320649505852620800.png)

## 导入&配置

### Maven

```xml

<dependency>
    <groupId>cn.omisheep</groupId>
    <artifactId>authz-spring-boot-starter</artifactId>
    <version>1.1.8</version>
</dependency>
```

### yml配置

```yaml
authz:
  token:
    key: 123456 # token加密密钥
  cache:
    enable-redis: true 
    # 是否开启redis二级缓存，默认为一级缓存，单机版可以不开启。
    # 若为cloud项目建议开启。否则用户信息无法同步
  log: error   # authz的log等级
  orm: mybatis # orm框架
  dashboard:
    enabled: true # 是否开启dashboard，默认页面为 http[s]://{baseUrl}/authz-dashboard/
  app: omisheep # app名。默认为defaultApp，若不同项目用一个redis建议单独命名各个项目的app名
```

## 登录 & 退出 & 封禁、ip限制、网段限制 & RateLimit & 在线人数信息、人数查询

### 登录
```java
AuHelper.login(1,"Chrome");
```

### 退出
```java
AuHelper.logout();
AuHelper.logoutAll();
AuHelper.logout(1,"Chrome");
```

### 在线人数
```java
AuHelper.checkUserIsActive(1); // 检查用户1是否最近活跃 返回：true｜false
AuHepler.queryActiveUsers(); // 获得所有活跃的用户信息 返回：用户id集合
```

### 封禁、ip限制、网段限制
```java
AuHelper.denyUser(1, "2s"); // 对用户1进行封禁2秒
AuHelper.denyUser(2, "mac", "10s"); // 对用户2的mac设备进行封禁10秒
AuHelper.removeDenyUser(1); // 移除用户1的封禁
AuHelper.denyIPRange("10.2.0.0/24", "10d"); // 对10.2.0.0/24网段下的IP进行封禁10天
AuHelper.denyIP("10.2.0.2", "10d"); // 对ip 10.2.0.2进行封禁10天
```

### 更多操作
```java
AuHelper.login(1);    // 登录用户1，返回：TokenPair
AuHelper.refreshToken("用户的RefreshTokenValue"); // 利用RefreshToken刷新获得新的AccessToken
AuHelper.getToken();    // 获取当前用户的Token，返回：Token
AuHelper.isLogin();    // 此次访问是否已经登录, 返回：true｜false
AuHelper.logout();    // 注销当前访问用户的当前设备
AuHelper.logoutAll();    // 注销当前访问用户的所有设备
AuHelper.logoutAll(2);    // 注销用户2的所有设备
AuHelper.logout(2, "macOS");    // 注销用户2的macOS系统的设备
AuHelper.hasRole("admin");    // 查询当前访问用户是否含有指定角色标识， 返回：true｜false
AuHelper.hasPermission("admin");    // 查询当前访问用户是否含有指定权限标识，返回：true｜false
AuHelper.getRSAPublicKey(); // 得到当前RSA的公钥， 返回String
AuHelper.checkUserIsActive(1); // 检查用户1是否活跃， 返回true或false
AuHelper.checkUserIsActive(1, "20s"); // 检查用户1是否在20s内访问过，返回：true｜false
AuHelper.queryActiveUsers(); // 查询活跃用户，返回：List
AuHelper.queryNumberOfActiveUsers(); // 查询活跃用户人数，返回：int
AuHelper.queryAllDeviceByUserId(1); // 获得用户id为1的所有设备信息，返回：List<Device>
AuHelper.reloadCache(); // 重新加载二级缓存
```

### RateLimit
#### RateLimit注解配置
限制接口10秒内最多访问3次，当超过时进行封禁，若重复封禁，时间递增3s-5s-10s
```java
@RateLimit(maxRequests = 3, window = "10s",
        punishmentTime = {"3s", "5s", "10s"})
@GetMapping("/limit")
public Result limit() {
        ...
}
```
#### RateLimit封禁时回调函数
1、直接继承`cn.omisheep.authz.core.callback.RateLimitCallback`接口并将其注入Spring。
2、方法配置回调函数，如下
```java
AuHelper.Callback.setRateLimitCallback((method, api, ip, userId, limitMeta, reliveDate) -> {
            ...
});
```

## 接口需要登录 & 接口需要权限

### 接口需要登录
```java
@GetMapping("/info")
@Certificated
public Result getInfo(){
        ...
}
```

### 接口需要权限
```java
@GetMapping("/role-admin-and-zxc")
@Roles("admin,zxc")  // 并
public Result roleAdmin(){
        ...
}
```
```java
@GetMapping("/permission-user-or-update")
@Perms({"user:add","user:update"}) // 或
public Result permissionUser(){
        ...
}
```

## 数据加密

### @Decrypt使用

- 对于`@Decrypt` 新增了对象加密解密功能，支持对对象内某一个字段进行单独加密以及对整体加密，以及参数加密

```java
@GetMapping("/get")
public Result get(@Decrypt String name){
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

## 参数需要权限

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

    // 对于参数operate
// 如果需要 "查询" 和 "重启"，则需要 "工程师权限", "运维权限", "技术人员权限" 这三个权限
// 如果需要 "开机", "关机", "添加" 则需要 "运维权限" 权限
// 如果需要 "登录" 则需要 "技术人员权限" 权限
    @Roles({"admin", "zxc"})
    @GetMapping("/operate")
    public Result test(
            @BatchAuthority(perms = {
                    @Perms(value = {"工程师权限", "运维权限", "技术人员权限"}, paramResources = {"查询", "重启"}),
                    @Perms(value = {"运维权限"}, paramResources = {"开机", "关机", "添加"}),
                    @Perms(value = {"技术人员权限"}, paramResources = "登录")})
            @RequestParam(required = true) String operate) {
        ....
    }
```

## 数据行权限（数据权限）和 数据列权限（字段权限）

> 目前只支持Mybatis

```java

// 如果是admin角色，那么只能看到id在 #{test}内的数据
// 如果是zxc角色，那么只能看到 id >=10的数据
// 如果两个都有， 那么就是 or
// #{test}为【资源】
@BatchAuthority({
        @Roles(value = "admin", condition = "id in (#{test})"),
        @Roles(value = "zxc", condition = "id >= 10")
})
@Data
@TableName("hnie_user")
@Accessors(chain = true)
public class HnieUser {

    @TableId(type = IdType.AUTO)
    private Integer id;

    private String name;
    private String avatar;

    private String username;

    // 只有admin角色才能看见password字段
    @Roles("admin")
    private String password;

    // 只有zxc角色才能看见info字段
    @Roles("zxc")
    private String info;

}

```

## 权限接口

> 可在这里调用你的数据库

```java

@Component
public class UserPermLibrary implements PermLibrary<Integer> {

    @Autowired
    private UserService userService;

    @NonNull
    @Override
    public Set<String> getRolesByUserId(@NonNull Integer userId) {
        return userService.getRolesByUserId(userId);
    }

    @NonNull
    @Override
    public Set<String> getPermissionsByRole(@NonNull String role) {
        return userService.getPermissionsByRole(role);
    }
}
```

## 【资源】

> 在使用数据权限时会用到condition，里面会有变量，该变量可以动态控制。

> 对于下列资源，分别可以如下使用 <br>
> `conditon = "name = #{go}"`  <br>
> `conditon = "str = #{goStatic}"` <br>
> `conditon = "id in #{listUsers.id}"` <br>

```java

import java.util.Arrays;

public class Testw {

    @ArgResource("go")
    public String go() {
        return "go";
    }

    @ArgResource("goStatic")
    public static String goStatic() {
        return "goStatic";
    }

    @ArgResource("listUsers")
    public static List<User> usersId() {
        ArrayList<User> list = new ArrayList<User>();
        list.add(new User(1));
        list.add(new User(2));
        return list;

    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    class User {
        public String id;
    }
}
```

### 自定义解码器

- 自定义解码器

```java

@Component
public class CustomDecryptor implements Decryptor {
    @Override
    public String decrypt(String encryptText) {
        return encryptText + new Date();
    }
}
```

- 使用

```java
@GetMapping("/get")
public Result get(@Decrypt("name") String name){
        return Result.SUCCESS.data("name",name);
}

@GetMapping("/get-custom")
public Result getCustom(@Decrypt(value = "name", decryptor = CustomDecryptor.class) String name){
        return Result.SUCCESS.data("name",name);
}
```

## 自定义Slot

```java

@Order(6) // 执行顺序 越大执行越靠后
@Component
public class ApiLogSlot implements Slot {
    @Override
    public boolean chain(HttpMeta httpMeta, HandlerMethod handler) throws AuthzException, Exception {
        // ...
        return true;
    }
}
```

