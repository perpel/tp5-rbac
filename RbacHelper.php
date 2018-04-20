<?php
namespace admin\common\libs\rbac;

class RbacHelper
{
    public static function rolesList($_roles = [], $roles = [], $name = '')
    {
        $data = [];
        $map = array_flip(array_keys($_roles));
        foreach ($roles as $key => $role) {
            if ($name == $role->name) {
                continue;
            }
            $data[$key]['checked'] = '';
            if (isset($map[$role->name])) {
                $data[$key]['checked'] = 'checked';
            }
            $data[$key]['name'] = $role->name;
            $data[$key]['desc'] = $role->description;
        }
        return $data;
    }


    public static function permissionsList($_permissions = [], $permissions = [])
    {
        $data = [];
        $map = array_flip(array_keys($_permissions));
        $permissions = self::permissionsToGroup($permissions);
        foreach ($permissions as $groupKey => $group) {
            foreach ($group as $key => $permission) {
                $data[$groupKey][$key]['checked'] = '';
                if (isset($map[$permission->name])) {
                    $data[$groupKey][$key]['checked'] = 'checked';
                }
                $data[$groupKey][$key]['name'] = $permission->name;
                $data[$groupKey][$key]['desc'] = $permission->description;
            }
        }
        return $data;
    }

    public static function permissionsToGroup($permissions)
    {
        $iterator = new ItemsToGroup($permissions, function ($key) {
            return preg_match('/(\w+)\/(\w+)/', $key, $matches) ? $matches[0] : '';
        });

        $data = [];
        foreach ($iterator as $key => $val) {
            $data[$iterator->group][$key] = $val;
        }
        return $data;
    }

}