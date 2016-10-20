<?php
namespace App\Auth;

use Cake\Network\Request;
use Cake\Network\Response;
use Cake\Controller\ComponentRegistry;
use Cake\ORM\TableRegistry;
use App\Auth\AuthBasicAuthenticate;

/**
 * AuthLocal component
 */
class AuthLocalAuthenticate extends AuthBasicAuthenticate
{
   
    protected $_defaultConfig = [
        'fields' => [
            'username' => 'username',
            'password' => 'password'
        ],
        'userModel' => 'Usrs',
        'scope' => [],
        'finder' => 'all',
        'contain' => null,
        'passwordHasher' => 'Legacy'
    ];

    public $options =  ['description' => 'Local Account Database', 'prefix' => 'local_', 'optionalParamPrefix' => 'local_account_'];

    /**
     * Constructor
     *
     * @param \Cake\Controller\ComponentRegistry $registry The Component registry used on this request.
     * @param array $config Array of config to use.
     */
    public function __construct(ComponentRegistry $registry, array $config = [])
    {
        parent::__construct($registry, $config);
        $this->getOptionalParamPrefix();
    }

	public function authenticate(Request $request, Response $response)
    {   
        try {
            $result = ['info' => ['fail' => [], 'pass' => []]];
            if($request->data['username'] && $request->data['password']) {
                $user = $this->_findUser($request->data['username'], $request->data['password']);
                if (is_array($user) && array_key_exists('id',$user)) {
                    $this->updatePreferences($user['id']);
                    $this->putlog('pass', "User authenticated");
                    return(array('id' => $user['id'],'username' => $user['username'], 'method' => 'Local', 'userPrefs' => $this->getUserPreferences($user['id']),
                        'prefs' => $this->config, 'groups' => $user['groops'], 'mode' => $user['isroot'], 'info' => $this->logs, 'params' => $this->config));
                } else 
                    $this->putlog('fail', "User account not found in database");
            } else 
                $this->putlog('fail', "Please fill all user data");
        } catch (\ErrorException $e) {
            $this->controller->Flash->set($e->getMessage() ,['element' => 'error']);
        }
        return ['info' => $this->logs];
    }
}
