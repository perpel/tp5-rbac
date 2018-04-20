<?php
namespace admin\common\libs\rbac;

class Assignment extends BaseObject
{
    /**
     * @var string|int user ID
     */
    public $userId;
    /**
     * @var string the role name
     */
    public $roleName;
    /**
     * @var int UNIX timestamp representing the assignment creation time
     */
    public $createdAt;
}
