<?php
namespace App\Auth;

use App\Auth\AuthLdapAuthenticate;
use Cake\Controller\ComponentRegistry;
use Cake\Network\Exception\InternalErrorException;
use Cake\Network\Exception\UnauthorizedException;
use Cake\Network\Request;
use Cake\Network\Response;
use Cake\ORM\TableRegistry;
use Cake\Core\Configure;

class AuthMsadMldAuthenticate extends AuthLdapAuthenticate
{
    /**
     * Constructor
     *
     * @param \Cake\Controller\ComponentRegistry $registry The Component registry used on this request.
     * @param array $config Array of config to use.
     */
    public function __construct(ComponentRegistry $registry, array $config = [])
    {
        parent::__construct($registry, $config);     
    }

}
