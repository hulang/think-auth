<?php

declare(strict_types=1);

if (!function_exists('AuthCheck')) {
    /**
     * 权限检测快捷方法
     * @param mixed|string|array $name 需要验证的规则列表,支持逗号分隔的权限规则或索引数组
     * @param mixed|int $uid 认证用户的id
     * @param mixed|int $type 认证类型
     * @param mixed|string $mode 执行check的模式
     * @param mixed|string $relation 如果为'or'表示满足任一条规则即通过验证;如果为'and'则表示需满足所有规则才能通过验证
     * @return mixed|bool 通过验证返回true;失败返回false
     */
    function AuthCheck($name = '', $uid = 0, $type = 1, $mode = 'url', $relation = 'or')
    {
        return \think\Auth::check($name, $uid, $type, $mode, $relation);
    }
}

if (!function_exists('getAuthRules')) {
    /**
     * 返回用户的所有规则表
     * @param mixed|int $uid 认证用户的id
     * @param mixed|int $type 认证类型
     * @return mixed
     */
    function getAuthRules($uid = 0, $type = 1)
    {
        return \think\Auth::rules($uid, $type);
    }
}

if (!function_exists('getAuthRoleIds')) {
    /**
     * 获取用户所有角色 id
     * 该函数通过调用 think\Auth 类的 roles 方法来获取指定用户的所有角色 id
     * 主要用于权限控制,确定用户拥有的角色,以便在应用中进行相应的权限判断和控制
     * 
     * @param mixed|int $uid 用户id,用于指定需要获取角色的用户,如果为0,则表示获取当前会话用户的角色
     * @param mixed|string $field 指定返回角色的字段名,默认为'role_id',即角色 id
     * @return mixed 返回用户的所有角色id,类型取决于内部实现,可能是数组或其他形式
     */
    function getAuthRoleIds($uid = 0, $field = 'role_id')
    {
        return \think\Auth::roles($uid, $field);
    }
}

if (!function_exists('getAuthRoles')) {
    /**
     * 获取用户所有角色数据
     * 该函数封装了think\Auth类的roles方法,提供一个简洁的接口来查询用户角色
     * @param mixed|int $uid 用户ID,默认为0,如果为0,则表示获取当前会话用户的角色
     * @param mixed|string $field 可选参数,用于指定返回角色的特定字段,如果为空,则返回所有字段
     * @return mixed 返回用户角色数据,数据类型取决于$field参数的设置
     */
    function getAuthRoles($uid = 0, $field = '')
    {
        return \think\Auth::roles($uid, $field);
    }
}
