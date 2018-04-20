<?php
namespace admin\common\libs\rbac;

use think\Cache;
use think\Db;
use think\Exception;

class DbManager extends BaseManager
{
    /**
     * @var Connection|array|string the DB connection object or the application component ID of the DB connection.
     * After the DbManager object is created, if you want to change this property, you should only assign it
     * with a DB connection object.
     * Starting from version 2.0.2, this can also be a configuration array for creating the object.
     */
    public $db = 'db';
    /**
     * @var string the name of the table storing authorization items. Defaults to "auth_item".
     */
    public $itemTable = 'tbl_auth_item';
    /**
     * @var string the name of the table storing authorization item hierarchy. Defaults to "auth_item_child".
     */
    public $itemChildTable = 'tbl_auth_item_child';
    /**
     * @var string the name of the table storing authorization item assignments. Defaults to "auth_assignment".
     */
    public $assignmentTable = 'tbl_auth_assignment';
    /**
     * @var string the name of the table storing rules. Defaults to "auth_rule".
     */
    public $ruleTable = 'tbl_auth_rules';
    /**
     * @var CacheInterface|array|string the cache used to improve RBAC performance. This can be one of the following:
     *
     * - an application component ID (e.g. `cache`)
     * - a configuration array
     * - a [[\yii\caching\Cache]] object
     *
     * When this is not set, it means caching is not enabled.
     *
     * Note that by enabling RBAC cache, all auth items, rules and auth item parent-child relationships will
     * be cached and loaded into memory. This will improve the performance of RBAC permission check. However,
     * it does require extra memory and as a result may not be appropriate if your RBAC system contains too many
     * auth items. You should seek other RBAC implementations (e.g. RBAC based on Redis storage) in this case.
     *
     * Also note that if you modify RBAC items, rules or parent-child relationships from outside of this component,
     * you have to manually call [[invalidateCache()]] to ensure data consistency.
     *
     * @since 2.0.3
     */
    public $cache;
    /**
     * @var string the key used to store RBAC data in cache
     * @see cache
     * @since 2.0.3
     */
    public $cacheKey = 'rbac';

    /**
     * @var Item[] all auth items (name => Item)
     */
    protected $items;
    /**
     * @var Rule[] all auth rules (name => Rule)
     */
    protected $rules;
    /**
     * @var array auth item parent-child relationships (childName => list of parents)
     */
    protected $parents;


    /**
     * Initializes the application component.
     * This method overrides the parent implementation by establishing the database connection.
     */
    public function init()
    {
    }

    private $_checkAccessAssignments = [];

    /**
     * @inheritdoc
     */
    public function checkAccess($userId, $permissionName, $params = [])
    {
        if (isset($this->_checkAccessAssignments[(string) $userId])) {
            $assignments = $this->_checkAccessAssignments[(string) $userId];
        } else {
            $assignments = $this->getAssignments($userId);
            $this->_checkAccessAssignments[(string) $userId] = $assignments;
        }

        if ($this->hasNoAssignments($assignments)) {
            return false;
        }

        $this->loadFromCache();
        if ($this->items !== null) {
            return $this->checkAccessFromCache($userId, $permissionName, $params, $assignments);
        }

        return $this->checkAccessRecursive($userId, $permissionName, $params, $assignments);
    }

    /**
     * Performs access check for the specified user based on the data loaded from cache.
     * This method is internally called by [[checkAccess()]] when [[cache]] is enabled.
     * @param string|int $user the user ID. This should can be either an integer or a string representing
     * the unique identifier of a user. See [[\yii\web\User::id]].
     * @param string $itemName the name of the operation that need access check
     * @param array $params name-value pairs that would be passed to rules associated
     * with the tasks and roles assigned to the user. A param with name 'user' is added to this array,
     * which holds the value of `$userId`.
     * @param Assignment[] $assignments the assignments to the specified user
     * @return bool whether the operations can be performed by the user.
     * @since 2.0.3
     */
    protected function checkAccessFromCache($user, $itemName, $params, $assignments)
    {
        if (!isset($this->items[$itemName])) {
            return false;
        }

        $item = $this->items[$itemName];

        if (!$this->executeRule($user, $item, $params)) {
            return false;
        }

        if (isset($assignments[$itemName]) || in_array($itemName, $this->defaultRoles)) {
            return true;
        }

        if (!empty($this->parents[$itemName])) {
            foreach ($this->parents[$itemName] as $parent) {
                if ($this->checkAccessFromCache($user, $parent, $params, $assignments)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Performs access check for the specified user.
     * This method is internally called by [[checkAccess()]].
     * @param string|int $user the user ID. This should can be either an integer or a string representing
     * the unique identifier of a user. See [[\yii\web\User::id]].
     * @param string $itemName the name of the operation that need access check
     * @param array $params name-value pairs that would be passed to rules associated
     * with the tasks and roles assigned to the user. A param with name 'user' is added to this array,
     * which holds the value of `$userId`.
     * @param Assignment[] $assignments the assignments to the specified user
     * @return bool whether the operations can be performed by the user.
     */
    protected function checkAccessRecursive($user, $itemName, $params, $assignments)
    {
        if (($item = $this->getItem($itemName)) === null) {
            return false;
        }

        if (!$this->executeRule($user, $item, $params)) {
            return false;
        }

        if (isset($assignments[$itemName]) || in_array($itemName, $this->defaultRoles)) {
            return true;
        }

        $parents = Db::table($this->itemChildTable)->where(['child' => $itemName])->column('parent');

        foreach ($parents as $parent) {
            if ($this->checkAccessRecursive($user, $parent, $params, $assignments)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @inheritdoc
     */
    protected function getItem($name)
    {
        if (empty($name)) {
            return null;
        }

        if (!empty($this->items[$name])) {
            return $this->items[$name];
        }

        $row = Db::table($this->itemTable)->where(['name' => $name])->find();
        if ($row === false) {
            return null;
        }

        return $this->populateItem($row);
    }

    /**
     * Returns a value indicating whether the database supports cascading update and delete.
     * The default implementation will return false for SQLite database and true for all other databases.
     * @return bool whether the database supports cascading update and delete.
     */
    protected function supportsCascadeUpdate()
    {
        return true;
    }

    /**
     * @inheritdoc
     */
    protected function addItem($item)
    {
        $time = time();
        if ($item->createdAt === null) {
            $item->createdAt = $time;
        }
        if ($item->updatedAt === null) {
            $item->updatedAt = $time;
        }

        Db::table($this->itemTable)->insert([
            'name' => $item->name,
            'type' => $item->type,
            'description' => $item->description,
            'rule_name' => $item->ruleName,
            'data' => $item->data === null ? null : serialize($item->data),
            'created_at' => $item->createdAt,
            'updated_at' => $item->updatedAt,
        ]);

        $this->invalidateCache();

        return true;
    }

    /**
     * @inheritdoc
     */
    protected function removeItem($item)
    {
        Db::table($this->itemTable)->where(['name' => $item->name])->delete();
        $this->invalidateCache();

        return true;
    }

    /**
     * @inheritdoc
     */
    protected function updateItem($name, $item)
    {
        $item->updatedAt = time();

        Db::table($this->itemTable)->where(['name' => $name])->update([
            'name' => $item->name,
            'description' => $item->description,
            'rule_name' => $item->ruleName,
            'data' => $item->data === null ? null : serialize($item->data),
            'updated_at' => $item->updatedAt,
        ]);

        $this->invalidateCache();

        return true;
    }

    /**
     * @inheritdoc
     */
    protected function addRule($rule)
    {
        $time = time();
        if ($rule->createdAt === null) {
            $rule->createdAt = $time;
        }
        if ($rule->updatedAt === null) {
            $rule->updatedAt = $time;
        }

        Db::table($this->ruleTable)->insert([
            'name' => $rule->name,
            'data' => serialize($rule),
            'created_at' => $rule->createdAt,
            'updated_at' => $rule->updatedAt,
        ]);

        $this->invalidateCache();

        return true;
    }

    /**
     * @inheritdoc
     */
    protected function updateRule($name, $rule)
    {
        $rule->updatedAt = time();

        Db::table($this->ruleTable)->where(['name' => $name])->update([
            'name' => $rule->name,
            'data' => serialize($rule),
            'updated_at' => $rule->updatedAt,
        ]);

        $this->invalidateCache();

        return true;
    }

    /**
     * @inheritdoc
     */
    protected function removeRule($rule)
    {
        Db::table($this->ruleTable)->where(['name' => $rule->name])->delete();
        $this->invalidateCache();
        return true;
    }

    /**
     * @inheritdoc
     */
    protected function getItems($type)
    {
        $data = Db::table($this->itemTable)->where(['type' => $type])->select();
        $items = [];
        foreach ($data as $row) {
            $items[$row['name']] = $this->populateItem($row);
        }
        return $items;
    }

    /**
     * Populates an auth item with the data fetched from database.
     * @param array $row the data from the auth item table
     * @return Item the populated auth item instance (either Role or Permission)
     */
    protected function populateItem($row)
    {
        $class = $row['type'] == Item::TYPE_PERMISSION ? Permission::className() : Role::className();

        if (!isset($row['data']) || ($data = @unserialize(is_resource($row['data']) ? stream_get_contents($row['data']) : $row['data'])) === false) {
            $data = null;
        }

        return new $class([
            'name' => $row['name'],
            'type' => $row['type'],
            'description' => $row['description'],
            'ruleName' => $row['rule_name'],
            'data' => $data,
            'createdAt' => $row['created_at'],
            'updatedAt' => $row['updated_at'],
        ]);
    }

    /**
     * @inheritdoc
     * The roles returned by this method include the roles assigned via [[$defaultRoles]].
     */
    public function getRolesByUser($userId)
    {
        if ($this->isEmptyUserId($userId)) {
            return [];
        }

        $data = Db::table($this->assignmentTable)->alias('a')
            ->join($this->itemTable . ' b', 'a.item_name=b.name')
            ->where(['a.user_id'=>(string) $userId, 'b.type'=>Item::TYPE_ROLE])->select();

        $roles = $this->getDefaultRoleInstances();
        foreach ($data as $row) {
            $roles[$row['name']] = $this->populateItem($row);
        }

        return $roles;
    }

    /**
     * @inheritdoc
     */
    public function getChildRoles($roleName)
    {
        $role = $this->getRole($roleName);

        if ($role === null) {
            throw new Exception("Role \"$roleName\" not found.");
        }

        $result = [];
        $this->getChildrenRecursive($roleName, $this->getChildrenList(), $result);

        $roles = [$roleName => $role];

        $roles += array_filter($this->getRoles(), function (Role $roleItem) use ($result) {
            return array_key_exists($roleItem->name, $result);
        });

        return $roles;
    }

    /**
     * @inheritdoc
     */
    public function getPermissionsByRole($roleName)
    {
        $childrenList = $this->getChildrenList();
        $result = [];
        $this->getChildrenRecursive($roleName, $childrenList, $result);
        if (empty($result)) {
            return [];
        }

        $data = Db::table($this->itemTable)->where(['type' => Item::TYPE_PERMISSION, 'name' => ['IN', array_keys($result)]])->select();

        $permissions = [];
        foreach ($data as $row) {
            $permissions[$row['name']] = $this->populateItem($row);
        }

        return $permissions;
    }

    /**
     * @inheritdoc
     */
    public function getPermissionsByUser($userId)
    {
        if ($this->isEmptyUserId($userId)) {
            return [];
        }

        $directPermission = $this->getDirectPermissionsByUser($userId);
        $inheritedPermission = $this->getInheritedPermissionsByUser($userId);

        return array_merge($directPermission, $inheritedPermission);
    }

    /**
     * Returns all permissions that are directly assigned to user.
     * @param string|int $userId the user ID (see [[\yii\web\User::id]])
     * @return Permission[] all direct permissions that the user has. The array is indexed by the permission names.
     * @since 2.0.7
     */
    protected function getDirectPermissionsByUser($userId)
    {
        $data = Db::table($this->assignmentTable)->alias('a')
            ->join($this->itemTable . ' b', 'a.item_name=b.name')
            ->where(['a.user_id'=>(string) $userId, 'b.type'=>Item::TYPE_PERMISSION])->select();

        $permissions = [];
        foreach ($data as $row) {
            $permissions[$row['name']] = $this->populateItem($row);
        }

        return $permissions;
    }

    /**
     * Returns all permissions that the user inherits from the roles assigned to him.
     * @param string|int $userId the user ID (see [[\yii\web\User::id]])
     * @return Permission[] all inherited permissions that the user has. The array is indexed by the permission names.
     * @since 2.0.7
     */
    protected function getInheritedPermissionsByUser($userId)
    {
        $data = Db::table($this->assignmentTable)->where(['user_id' => (string) $userId])->column('item_name');
        $childrenList = $this->getChildrenList();
        $result = [];
        foreach ($data as $roleName) {
            $this->getChildrenRecursive($roleName, $childrenList, $result);
        }

        if (empty($result)) {
            return [];
        }

        $data = Db::table($this->itemTable)->where([
            'type' => Item::TYPE_PERMISSION,
            'name' => ['IN', array_keys($result)],
        ])->select();

        $permissions = [];
        foreach ($data as $row) {
            $permissions[$row['name']] = $this->populateItem($row);
        }

        return $permissions;
    }

    /**
     * Returns the children for every parent.
     * @return array the children list. Each array key is a parent item name,
     * and the corresponding array value is a list of child item names.
     */
    protected function getChildrenList()
    {
        $data = Db::table($this->itemChildTable)->select();
        $parents = [];
        foreach ($data as $row) {
            $parents[$row['parent']][] = $row['child'];
        }

        return $parents;
    }

    /**
     * Recursively finds all children and grand children of the specified item.
     * @param string $name the name of the item whose children are to be looked for.
     * @param array $childrenList the child list built via [[getChildrenList()]]
     * @param array $result the children and grand children (in array keys)
     */
    protected function getChildrenRecursive($name, $childrenList, &$result)
    {
        if (isset($childrenList[$name])) {
            foreach ($childrenList[$name] as $child) {
                $result[$child] = true;
                $this->getChildrenRecursive($child, $childrenList, $result);
            }
        }
    }

    /**
     * @inheritdoc
     */
    public function getRule($name)
    {
        if ($this->rules !== null) {
            return isset($this->rules[$name]) ? $this->rules[$name] : null;
        }

        $row = Db::table($this->ruleTable)->where(['name' => $name])->find();
        if ($row === false) {
            return null;
        }
        $data = $row['data'];
        if (is_resource($data)) {
            $data = stream_get_contents($data);
        }

        return unserialize($data);
    }

    /**
     * @inheritdoc
     */
    public function getRules()
    {
        if ($this->rules !== null) {
            return $this->rules;
        }

        $result = Db::table($this->ruleTable)->select();

        $rules = [];
        foreach ($result as $row) {
            $data = $row['data'];
            if (is_resource($data)) {
                $data = stream_get_contents($data);
            }
            $rules[$row['name']] = unserialize($data);
        }

        return $rules;
    }

    /**
     * @inheritdoc
     */
    public function getAssignment($roleName, $userId)
    {
        if ($this->isEmptyUserId($userId)) {
            return null;
        }

        $row = Db::table($this->assignmentTable)->where(['user_id' => (string) $userId, 'item_name' => $roleName])->find();
        if ($row === false) {
            return null;
        }

        return new Assignment([
            'userId' => $row['user_id'],
            'roleName' => $row['item_name'],
            'createdAt' => $row['created_at'],
        ]);
    }

    /**
     * @inheritdoc
     */
    public function getAssignments($userId)
    {
        if ($this->isEmptyUserId($userId)) {
            return [];
        }

        $data = Db::table($this->assignmentTable)->where(['user_id' => (string) $userId])->select();
        $assignments = [];
        foreach ($data as $row) {
            $assignments[$row['item_name']] = new Assignment([
                'userId' => $row['user_id'],
                'roleName' => $row['item_name'],
                'createdAt' => $row['created_at'],
            ]);
        }

        return $assignments;
    }

    /**
     * @inheritdoc
     * @since 2.0.8
     */
    public function canAddChild($parent, $child)
    {
        return !$this->detectLoop($parent, $child);
    }

    /**
     * @inheritdoc
     */
    public function addChild($parent, $child)
    {
        if ($parent->name === $child->name) {
            throw new Exception("Cannot add '{$parent->name}' as a child of itself.");
        }

        if ($parent instanceof Permission && $child instanceof Role) {
            throw new Exception('Cannot add a role as a child of a permission.');
        }

        if ($this->detectLoop($parent, $child)) {
            throw new Exception("Cannot add '{$child->name}' as a child of '{$parent->name}'. A loop has been detected.");
        }

        Db::table($this->itemChildTable)->insert(['parent' => $parent->name, 'child' => $child->name]);
        $this->invalidateCache();

        return true;
    }

    /**
     * @inheritdoc
     */
    public function removeChild($parent, $child)
    {
        $result = Db::table($this->itemChildTable)->where(['parent' => $parent->name, 'child' => $child->name])->delete() > 0;
        $this->invalidateCache();
        return $result;
    }

    /**
     * @inheritdoc
     */
    public function removeChildren($parent)
    {
        $result = Db::table($this->itemChildTable)->where(['parent' => $parent->name])->delete() > 0;
        $this->invalidateCache();
        return $result;
    }

    /**
     * @inheritdoc
     */
    public function hasChild($parent, $child)
    {
        return Db::table($this->itemChildTable)->where(['parent' => $parent->name, 'child' => $child->name])->find() !== false;
    }

    /**
     * @inheritdoc
     */
    public function getChildren($name)
    {
        $children = Db::table($this->itemTable)
                        ->field(['name', 'type', 'description', 'rule_name', 'data', 'created_at', 'updated_at'])
                        ->where('name','IN', function($query) use($name) {
                            $query->table($this->itemChildTable)->field('child')->where(['parent' => $name]);
                        })->select();

        foreach ($children as $row) {
            $children[$row['name']] = $this->populateItem($row);
        }

        return $children;
    }

    /**
     * Checks whether there is a loop in the authorization item hierarchy.
     * @param Item $parent the parent item
     * @param Item $child the child item to be added to the hierarchy
     * @return bool whether a loop exists
     */
    protected function detectLoop($parent, $child)
    {
        if ($child->name === $parent->name) {
            return true;
        }
        foreach ($this->getChildren($child->name) as $grandchild) {
            if ($this->detectLoop($parent, $grandchild)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @inheritdoc
     */
    public function assign($role, $userId)
    {
        $assignment = new Assignment([
            'userId' => $userId,
            'roleName' => $role->name,
            'createdAt' => time(),
        ]);

        Db::table($this->assignmentTable)->insert([
            'user_id' => $assignment->userId,
            'item_name' => $assignment->roleName,
            'created_at' => $assignment->createdAt,
        ]);

        unset($this->_checkAccessAssignments[(string) $userId]);
        return $assignment;
    }

    /**
     * @inheritdoc
     */
    public function revoke($role, $userId)
    {
        if ($this->isEmptyUserId($userId)) {
            return false;
        }

        unset($this->_checkAccessAssignments[(string) $userId]);
        return Db::table($this->assignmentTable)->where(['user_id' => (string) $userId, 'item_name' => $role->name])->delete() > 0;
    }

    /**
     * @inheritdoc
     */
    public function revokeAll($userId)
    {
        if ($this->isEmptyUserId($userId)) {
            return false;
        }

        unset($this->_checkAccessAssignments[(string) $userId]);
        return Db::table($this->assignmentTable)->where(['user_id' => (string) $userId])->delete() > 0;
    }

    /**
     * @inheritdoc
     */
    public function removeAll()
    {
        $this->removeAllAssignments();
        Db::table($this->itemChildTable)->delete(true);
        Db::table($this->itemTable)->delete(true);
        Db::table($this->ruleTable)->delete(true);
        $this->invalidateCache();
    }

    /**
     * @inheritdoc
     */
    public function removeAllPermissions()
    {
        $this->removeAllItems(Item::TYPE_PERMISSION);
    }

    /**
     * @inheritdoc
     */
    public function removeAllRoles()
    {
        $this->removeAllItems(Item::TYPE_ROLE);
    }

    /**
     * Removes all auth items of the specified type.
     * @param int $type the auth item type (either Item::TYPE_PERMISSION or Item::TYPE_ROLE)
     */
    protected function removeAllItems($type)
    {
        Db::table($this->itemTable)->where(['type' => $type])->delete();
        $this->invalidateCache();
    }

    /**
     * @inheritdoc
     */
    public function removeAllRules()
    {
        Db::table($this->ruleTable)->delete(true);
        $this->invalidateCache();
    }

    /**
     * @inheritdoc
     */
    public function removeAllAssignments()
    {
        $this->_checkAccessAssignments = [];
        Db::table($this->assignmentTable)->delete(true);
    }

    public function invalidateCache()
    {
        Cache::rm($this->cacheKey);
        $this->items = null;
        $this->rules = null;
        $this->parents = null;
        $this->_checkAccessAssignments = [];
    }

    public function loadFromCache()
    {
        $data = Cache::get($this->cacheKey);
        if ($this->items !== null || !$data) {
            return;
        }

        if (is_array($data) && isset($data[0], $data[1], $data[2])) {
            list($this->items, $this->rules, $this->parents) = $data;
            return;
        }

        $items = Db::table($this->itemTable)->select();
        $this->items = [];
        foreach ($items as $row) {
            $this->items[$row['name']] = $this->populateItem($row);
        }

        $rules = Db::table($this->ruleTable)->select();
        $this->rules = [];
        foreach ($rules as $row) {
            $data = $row['data'];
            if (is_resource($data)) {
                $data = stream_get_contents($data);
            }
            $this->rules[$row['name']] = unserialize($data);
        }

        $parents = Db::table($this->itemChildTable)->select();
        $this->parents = [];
        foreach ($parents as $row) {
            if (isset($this->items[$row['child']])) {
                $this->parents[$row['child']][] = $row['parent'];
            }
        }

        Cache::set($this->cacheKey, [$this->items, $this->rules, $this->parents]);
    }

    /**
     * Returns all role assignment information for the specified role.
     * @param string $roleName
     * @return string[] the ids. An empty array will be
     * returned if role is not assigned to any user.
     * @since 2.0.7
     */
    public function getUserIdsByRole($roleName)
    {
        if (empty($roleName)) {
            return [];
        }

        return Db::table($this->assignmentTable)->where(['item_name' => $roleName])->column('user_id');
    }

    /**
     * Check whether $userId is empty.
     * @param mixed $userId
     * @return bool
     */
    private function isEmptyUserId($userId)
    {
        return !isset($userId) || $userId === '';
    }
}
