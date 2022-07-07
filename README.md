### Authz

## 动态权限框架 - 简单介绍

> [Authz](https://gitee.com/iozxc/authz) 主页地址 https://gitee.com/iozxc/authz
![Authz](http://cdn.omisheep.cn/upload/img/article/320649505852620800.png)

## 1. 导入&配置

### 1.1 Maven

```xml

<dependency>
    <groupId>cn.omisheep</groupId>
    <artifactId>authz-spring-boot-starter</artifactId>
    <version>LATEST</version>
</dependency>
```

### 1.2 yml配置

```yaml
authz:
  token:
    key: 123456
  cache:
    enable-redis: true
  log: error
  orm: mybatis
  dashboard:
    enabled: true
```

## 2. 登录

```java
AuHelper.login(1,"Chrome");
```

## 3. 退出

```java
AuHelper.logout();
AuHelper.logoutAll();
AuHelper.logout(1,"Chrome");
```

## 4. 接口需要登录

```java
@GetMapping("/info")
@Certificated
public Result getInfo(){
        ...
}
```

## 5. 接口需要权限

```java
@GetMapping("/role-admin")
@Roles("admin")
public Result roleAdmin(){
        ...
}
```

## 6. 参数需要权限

```java
// 对于参数x
// zxc 只能够访问123-156,177
// admin 只能访问146-200
// 如果某个用户有两个角色，那么取并集。如 zxc,admin 能访问123-200
@Roles({"admin", "zxc"})
@GetMapping("/operate/{x}")
public Result test(@BatchAuthority({
        @Roles(value = "zxc", paramRange = {"123-156", "177"}),
        @Roles(value = "admin", paramRange = "146-200")
}) @PathVariable int x){
        ...
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
@RequestParam(required = true) String operate){
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

## 7.【资源】

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

## 8. 权限接口

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

## 9. 自定义Slot

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

### 10. 数据加密

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
