<?php 
namespace App\Auth;

use Cake\Auth\AbstractPasswordHasher;
use Cake\Utility\Security;

class LegacyPasswordHasher extends AbstractPasswordHasher
{

    public function hash($password)
    {
        return Security::hash($password,'sha256',true);
    }

    public function check($password, $hashedPassword)
    { 
        return Security::hash($password,'sha256',true) === $hashedPassword;
    }
}
