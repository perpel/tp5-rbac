<?php
namespace admin\common\libs\rbac;

interface CheckAccessInterface
{
    public function checkAccess($userId, $permissionName, $params = []);
}
