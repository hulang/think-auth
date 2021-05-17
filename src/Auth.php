<?php

declare(strict_types=1);

namespace think;

use think\Facade;

/**
 * auth 权限检测入口
 * 
 * @see \think\auth\service\Auth
 * @mixin \think\auth\service\Auth
 */
class Auth extends Facade
{
    /**
     * 获取当前Facade对应类名（或者已经绑定的容器对象标识）
     * @access protected
     * @return string
     */
    protected static function getFacadeClass()
    {
        return 'think\auth\service\Auth';
    }
}
