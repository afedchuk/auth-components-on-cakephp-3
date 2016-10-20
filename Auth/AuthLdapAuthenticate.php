<?php
namespace App\Auth;

use App\Auth\AuthBasicAuthenticate;
use Cake\Controller\ComponentRegistry;
use Cake\Log\LogTrait;
use Cake\Network\Exception\InternalErrorException;
use Cake\Network\Exception\UnauthorizedException;
use Cake\Network\Request;
use Cake\Network\Response;
use Cake\ORM\TableRegistry;
use Cake\Core\Configure;
use Cake\Utility\Security;

/**
 * LDAP Authentication adapter for AuthComponent.
 *
 * Provides LDAP authentication support for AuthComponent. LDAP will
 * authenticate users against the specified LDAP Server
 *
 * ### Using LDAP auth
 *
 * In your controller's components array, add auth + the required config
 * ```
 *  public $components = [
 *      'Auth' => [
 *          'authenticate' => ['Ldap']
 *      ]
 *  ];
 * ```
 */
class AuthLdapAuthenticate extends AuthBasicAuthenticate
{
    use LogTrait;
    /**
     * LDAP Object
     *
     * @var object
     */
    protected $ldapConnection;

    private $errors;

    public $options =  ['description' => 'LDAP', 'prefix' => 'auth_ldap_', 'optionalParamPrefix' => 'ldap_'];

    protected $baseDn;

    protected $request;

    protected $mode = ['R' => 'auth_ldap_user_report_dn', 
                       'N' => 'auth_ldap_user_standard_dn', 
                       'Y' => 'auth_ldap_user_admin_dn'];

    protected $config = ['auth_ldap_hostname'        => 'The hostname of your LDAP server',
                        'auth_ldap_query_account'   => 'Account DN to use for performing searches',
                        'auth_ldap_query_password'  => 'Password for the search account',
                        'auth_ldap_search_base'     => 'Base DN for user account searches',
                        'auth_ldap_search_key'      => 'Account Attribute',
                        'auth_ldap_groups_dn'       => 'Group Membership DN',
                        'auth_ldap_groups_key'      => 'Group Membership Attribute',
                        'auth_ldap_email_key'       => 'Email Address Attribute',
                        'auth_ldap_user_allow_dn'   => 'Allowed User DN (Empty for open access)',
                        'auth_ldap_user_admin_dn'   => 'Admin User DN',
                        'auth_ldap_user_standard_dn'=> 'Standard User DN',
                        'auth_ldap_user_report_dn'  => 'Report Only User DN'
                        ];

    public $logs = [["message" => "Initialization successful", "type" => "pass"],
                    ["message" => "Protocol Version 3 selected", "type" => "pass"]
                    ];
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

    /**
     * Destructor
     */
    public function __destruct()
    {
        @ldap_unbind($this->ldapConnection);
    }
    /**
     * Authenticate a user based on the request information.
     *
     * @param \Cake\Network\Request $request The request to authenticate with.
     * @param \Cake\Network\Response $response The response to add headers to.
     * @return mixed Either false on failure, or an array of user data on success.
     */
    public function authenticate(Request $request, Response $response)
    {
        if (!isset($request->data['username']) || !isset($request->data['password'])) {
            return false;
        }

        $this->connect();
        $this->request = $request;

        if(empty($this->config[$this->options['prefix']. 'hostname']))
            $this->putlog('fail', "Server hostname URL not specified");

        if(!$this->config[$this->options['prefix']. 'search_key'])
            $this->config[$this->options['prefix']. 'search_key'] = 'uid';

        if(!$this->config[$this->options['prefix']. 'email_key'])
            $this->config[$this->options['prefix']. 'email_key'] = 'mail';

        if(!$this->config[$this->options['prefix']. 'groups_key'])
            $this->config[$this->options['prefix']. 'groups_key'] = 'memberof';

        return $this->_findUser($this->config[$this->options['prefix']. 'query_account'], $this->config[$this->options['prefix']. 'query_password']);
    }

    public function connect() 
    {
        $this->config = $this->getOptionalParamPrefix();
        if (!defined('LDAP_OPT_DIAGNOSTIC_MESSAGE')) {
            define('LDAP_OPT_DIAGNOSTIC_MESSAGE', 0x0032);
        }

        try {
            if (empty($this->config[$this->options['prefix']. 'hostname']))
                throw new \ErrorException(__('Server not specified!'));
            $this->ldapConnection = ldap_connect($this->config[$this->options['prefix']. 'hostname']);
            ldap_set_option($this->ldapConnection, LDAP_OPT_NETWORK_TIMEOUT, 5);
            ldap_set_option($this->ldapConnection, LDAP_OPT_PROTOCOL_VERSION, 3);
        } catch (\ErrorException $e) {
            $this->controller->Flash->set($e->getMessage() ,['element' => 'error']);
        }
        return $this->ldapConnection;
    }

    /**
     * Find a user record using the username and password provided.
     *
     * @param string $username The username/identifier.
     * @param string|null $password The password
     * @return bool|array Either false on failure, or an array of user data.
     */
    protected function _findUser($username, $password = null)
    {

        try { 
            $ldapBind = @ldap_bind($this->ldapConnection, $username, $password);
            if ($ldapBind === true) {
                $this->putlog('pass', ["Bind successful using: " .  $this->config[$this->options['prefix']. 'query_account'],
                                       "LDAP Search Base: " . $this->config[$this->options['prefix']. 'search_base'],
                                       "LDAP Search Filter: " . $this->config[$this->options['prefix']. 'search_key'] . "=".$this->request->data['username']
                                   ]);

                $searchResults = null;
                $results = $this->getEntries($this->ldapConnection, $this->config[$this->options['prefix']. 'search_base'], 
                    '(' . $this->config[$this->options['prefix']. 'search_key'] . '=' . $this->request->data['username'] . ')', 
                    ['uid','dn', $this->config[$this->options['prefix']. 'email_key'], $this->config[$this->options['prefix']. 'groups_key']], $searchResults);

                $mode = $this->_identifyMode($searchResults, $results, $password);
                return(array_merge(['username' => $this->request->data['username'], 'method' => 'LDAP', 'info' => $this->logs], $mode));
            } else 
                throw new \ErrorException(__('Unable to connect to LDAP server at this time.',true));
        } catch (\ErrorException $e) {
            $this->putlog('fail', $e->getMessage());
        }
        restore_error_handler();
        return ['info' => $this->logs];
    }


    /**
     * Find a user restrictions.
     *
     * @param string $searchResults bind result.
     * @param array $results The password
     * @param string $password The password
     * @return array user restions info.
     */
    protected function _identifyMode($searchResults, $results, $password)
    {
        $entry = @ldap_first_entry($this->ldapConnection, $searchResults);
        $ldapUserDn = isset($results[0]['dn']) ? $results[0]['dn'] : '';

        // connect as the requesting user dn
        if(!($conectUserDn = @ldap_bind($this->ldapConnection, $ldapUserDn, $password)))
            throw new \ErrorException(__('Incorrect Login.'));
        
        $this->putlog('pass', "Authentication succeeded for user: " . $ldapUserDn);

        $groups = []; $prefs = [];
        $this->getDnListUsers($ldapUserDn, $groups);

        // determine the user mode and access
        if(($attributes = @ldap_get_attributes($this->ldapConnection, $entry))) {
            if(isset($attributes['mail'][0]))
                array_push($prefs, ['email_address' => $attributes['mail'][0]]);
        }

        $userMode = false; $user = false;
        foreach($this->mode as $key => $userDn) {
            // check if the user has exactly the same dn as it was set in auth_ldap_user_admin/standard/report_dn properties
            $users = explode(';', $this->config[$userDn]);
            if($this->config[$userDn] && in_array($ldapUserDn, $users))   {
                $userMode = $key;  $user = true;
            }

            // if no user has exactly set credentials try to find the user in DN set in properties
            if(!$user && $this->config[$userDn]) {
                $query = "(&(objectClass=*)(" . $this->config[$this->options['prefix']. 'groups_key'] . "=" . $ldapUserDn . "))";
                try { 
                    $userEntries = @ldap_get_entries($this->ldapConnection, @ldap_search($this->ldapConnection, $this->config[$userDn], $query, ['dn']));
                    if (!empty($userEntries) && !empty($userEntries['count']))
                        $user_mode = $key;
                } catch (\ErrorException $e) {
                    continue;  
                }
            }

            // check if the user is a member of a group that was set in auth_ldap_user_admin/standard/report_dn properties
            foreach ($users as $dn) {
                if (in_array(strtolower($dn), array_map('strtolower', $groups))) {
                    $userMode = $key;
                    break;
                }
            }

        }

        $usrs = TableRegistry::get('Usrs');  
        $user = $usrs->find()->where(['username' => $this->request->data['username']])->first();
        if(empty($user) && $userMode) {
            $usrs->newUser(['username' => $this->request->data['username'], 
                            'password' => Security::hash($password,'sha256',true),
                            'method' => $this->options['description'],
                            'groops' => $groups,
                            'isroot' => $userMode]);
            $user = $usrs->find()->where(['id' => $usrs->getLastInsertId()])->first();
            if($user->toArray()['username'] != $this->request->data['username'])
                throw new \ErrorException(__('Unable to complete login process.'));
        } 

        return array_merge(['prefs' => $prefs, 'groups' => $groups, 
                            'mode' => $userMode, 'userPrefs' => $this->getUserPreferences($usrs->getLastInsertId())], (!is_null($user) ? $user->toArray() : []));
    }

    public function getEntries($connection, $searchdn, $filter, $attributes = array(), &$search = null){
        if (($search = @ldap_search($connection, $searchdn, $filter, $attributes))) {
            $this->putlog('pass',"User account search succeeded");
            if(($info = @ldap_get_entries($connection, $search))) {
                $this->putlog('pass', "Retrieved a unique account record");
                return $info;
            } else {
                throw new \ErrorException(__('Unable to verify login.', true));
            }
        }  else
            throw new \ErrorException(__('Invalid Account.',true));
        return null;
    }

    /**
     * gather a list of all the DN's this user is a member of
     *
     * @param string $user user.
     * @param array $groups groups
     * @return void.
     */
    private function getDnListUsers($user, &$groups) 
    {
        if(($ldapDns = explode(',', $user)) && !empty($this->config[$this->options['prefix']. 'groups_key'])) {
            $query = "(&(objectClass=groupOfNames)(" . $this->config[$this->options['prefix']. 'groups_key'] . "=" . $user . "))";
            $entries = $this->getEntries($this->ldapConnection, $this->config[$this->options['prefix']. 'groups_dn'], $query, ["dn"]);
            if(!empty($entries)) {
                $this->putlog('pass', "Group membership search results:");
                for ($i = 0; $i < $entries['count']; $i++) {
                    $groups[] = $entries[$i]['dn'];
                    $this->putlog('ok', $entries[$i]['dn']);
                }
            } else {
                $this->putlog('info', "Group membership search returned no results");
            }
        }
    }

    public function _testConnection($options = [])
    {
        return $this->_members($options);
    }

    /**
     * m
     *
     * @param string $user user.
     * @param array $groups groups
     * @return void.
     */
    private function _members($options = []) 
    {
        $this->connect();
        $members  = []; $prefs = $this->getOptionalParamPrefix();
        $entries = $this->getEntries($this->ldapConnection, $this->config[$this->options['prefix']. 'groups_dn'], '(objectClass=*)', ["dn", $this->config[$this->options['prefix']. 'groups_key']]);
        if(!empty($entries)) {
            for($i = 0; $i < $entries['count']; $i++) {
                $members[$entries[$i]['dn']] = $entries[$i]['dn'];
                if(isset($entries[$i]['member'])) {
                    for($j = 0; $j < $entries[$i]['member']['count']; $j++) {
                        $members[$entries[$i]['member'][$j]] = $entries[$i]['member'][$j];
                    }
                }
            }
            $members = array_unique(array_keys($members));
        }
        return array_combine($members, $members);
    }
    
}
