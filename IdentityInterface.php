<?php
namespace admin\common\libs\rbac;

interface IdentityInterface
{
    public static function findIdentity($id);

    //public static function findIdentityByAccessToken($token, $type = null);

    //public function getId();

    //public function getAuthKey();

    //public function validateAuthKey($authKey);
}
