<?php

declare(strict_types=1);

namespace think\auth\service;

use think\facade\Db;
use think\facade\Session;
use think\facade\Config;
use think\auth\model\RoleUser;

class Auth
{
    /**
     * 当前用户模型
     * @var mixed|string
     */
    protected $user;

    /**
     * 默认配置
     * @var mixed|array
     */
    protected $config = [
        // 权限开关
        'auth_on' => 1,
        // 认证方式,1为实时认证;2为登录认证
        'auth_type' => 1,
        // 用户信息表
        'auth_user' => 'admin',
    ];

    /**
     * 类架构函数
     * Auth constructor
     */
    public function __construct()
    {
        // 可设置配置项auth,此配置项为数组
        $config = Config::get('auth', []);
        if (is_array($config)) {
            $this->config = array_merge($this->config, $config);
        }
        // 初始化用户模型
        $this->user = Db::name($this->config['auth_user']);
    }

    /**
     * 检查权限
     * @param mixed|string|array $name 需要验证的规则列表,支持逗号分隔的权限规则或索引数组
     * @param mixed|int $uid 认证用户的id
     * @param mixed|int $type 认证类型
     * @param mixed|string $mode 执行check的模式
     * @param mixed|string $relation 如果为'or'表示满足任一条规则即通过验证;如果为'and'则表示需满足所有规则才能通过验证
     * @return mixed|bool 通过验证返回true;失败返回false
     * @throws \think\db\exception\DataNotFoundException
     * @throws \think\db\exception\DbException
     * @throws \think\db\exception\ModelNotFoundException
     * @throws \think\exception\DbException
     */
    public function check($name = '', $uid = 0, $type = 1, $mode = 'url', $relation = 'or')
    {
        if (!$this->config['auth_on']) {
            return true;
        }
        // 获取用户需要验证的所有有效规则列表
        $authList = $this->getAuthList($uid, $type);
        if (is_string($name)) {
            $name = explode(',', strtolower($name));
        }
        // 保存验证通过的规则名
        $list = [];
        if ('url' == $mode) {
            $REQUEST = unserialize(strtolower(serialize(request()->param())));
        }

        foreach ($authList as $auth) {
            $query = preg_replace('/^.+\?/U', '', $auth);
            if ('url' == $mode && $query != $auth) {
                // 解析规则中的|param
                parse_str($query, $param);
                $intersect = array_intersect_assoc($REQUEST, $param);
                $auth = preg_replace('/\?.*$/U', '', $auth);
                if (in_array($auth, $name) && $intersect == $param) {
                    // 如果节点相符且url参数满足
                    $list[] = $auth;
                }
            } else {
                if (in_array($auth, $name)) {
                    $list[] = $auth;
                }
            }
        }
        if ('or' == $relation && !empty($list)) {
            return true;
        }
        $diff = array_diff($name, $list);
        if ('and' == $relation && empty($diff)) {
            return true;
        }
        return false;
    }

    /**
     * 返回用户的所有规则表
     * @param mixed|int $uid 认证用户的id
     * @param mixed|int $type 认证类型
     * @return mixed|array
     * @throws \think\db\exception\DataNotFoundException
     * @throws \think\db\exception\DbException
     * @throws \think\db\exception\ModelNotFoundException
     * @throws \think\exception\DbException
     */
    public function rules($uid = 0, $type = 1)
    {
        // 获取用户需要验证的所有有效规则列表
        return $this->getAuthList($uid, $type);
    }

    /**
     * 获取用户所有角色信息
     * @param mixed|int $uid
     * @param mixed|string $field
     * @return mixed|array|false|\PDOStatement|string|\think\Collection
     * @throws \think\db\exception\DataNotFoundException
     * @throws \think\db\exception\DbException
     * @throws \think\db\exception\ModelNotFoundException
     * @throws \think\exception\DbException
     */
    public function roles($uid = 0, $field = '')
    {
        $map = [];
        $map[] = ['user_id', '=', $uid];
        $role = RoleUser::where($map);
        if (!empty($field)) {
            return $role->column($field);
        }
        return $role->select();
    }

    /**
     * 获得权限列表
     * @param int $uid 用户id
     * @param int|mixed $type
     * @return mixed|array
     * @throws \think\db\exception\DataNotFoundException
     * @throws \think\db\exception\DbException
     * @throws \think\db\exception\ModelNotFoundException
     * @throws \think\exception\DbException
     */
    protected function getAuthList($uid = 0, $type = 0)
    {
        // 保存用户验证通过的权限列表
        static $_authList = [];
        $t = $type;

        if (isset($_authList[$uid . $t])) {
            return $_authList[$uid . $t];
        }

        if ($this->config['auth_type'] && Session::has('_auth_list_' . $uid . $t) == 2) {
            return Session::get('_auth_list_' . $uid . $t);
        }

        $roles = $this->roles($uid);
        if (empty($roles)) {
            $_authList[$uid . $t] = [];
            return [];
        }

        $pk = $this->user->getPk();
        $user = $this->user->where([$pk => $uid])->column('*', $pk);
        if (is_array($user) && isset($user[$uid])) {
            $user = $user[$uid];
        } else {
            $user = [];
        }
        // 循环规则,判断结果
        $authList = [];
        foreach ($roles as $k => $v) {
            foreach ($v->rules as $value) {
                $rule = $value->toArray();
                // 当规则为空或状态不为1时跳过
                if (empty($rule) || $rule['status'] != '1') {
                    continue;
                }
                if (!empty($rule['condition'])) {
                    // 根据condition进行验证
                    $command = preg_replace('/\{(\w*?)\}/', '$user[\'\\1\']', $rule['condition']);
                    // dump($command);
                    // debug
                    $condition = '';
                    @(eval('$condition=(' . $command . ');'));
                    if ($condition) {
                        $authList[] = strtolower($rule['url']);
                    }
                } else {
                    //只要存在就记录
                    $authList[] = strtolower($rule['url']);
                }
            }
        }
        $_authList[$uid . $t] = $authList;

        if ($this->config['auth_type'] == 2) {
            // 规则列表结果保存到|session
            Session::set('_auth_list_' . $uid . $t, $authList);
        }

        $list = [];
        $n = 0;
        $authList = array_unique($authList);
        foreach ($authList as $k => $v) {
            if (!empty($v)) {
                $list[$n] = $v;
                $n++;
            }
        }
        sort($list);

        return $list;
    }
}
