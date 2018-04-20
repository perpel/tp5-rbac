<?php
namespace admin\common\libs\rbac;

interface Arrayable
{
    public function fields();

    public function extraFields();

    public function toArray(array $fields = [], array $expand = [], $recursive = true);
}
