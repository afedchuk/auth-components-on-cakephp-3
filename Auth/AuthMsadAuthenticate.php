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

class AuthMsadAuthenticate extends AuthLdapAuthenticate
{
    public $options =  ['description' => 'Active Directory', 'prefix' => 'auth_msad_', 'optionalParamPrefix' => 'active_directory_'];

    protected $config = ['auth_msad_hostname'       => 'Active Directory Server',
                        'auth_msad_rdn'             => 'Active Directory RDN',
                        'auth_msad_user_allow_dn'   => 'Allowed User DN (Empty for open access)',
                        'auth_msad_user_admin_dn'   => 'Admin User DN',
                        'auth_msad_user_standard_dn'    => 'Standard User DN',
                        'auth_msad_user_report_dn'  => 'Report Only User DN',
                        ];

     protected $mode = ['R' => 'auth_msad_user_report_dn', 
                        'N' => 'auth_msad_user_standard_dn', 
                        'Y' => 'auth_msad_user_admin_dn'];
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

        if(empty($this->config['auth_msad_hostname']))
            $this->putlog('fail', "Server hostname URL not specified");

        if (empty($this->config['active_directory_account_key']))
            $this->config['active_directory_account_key'] = "sAMAccountName";

        if (empty($this->config['active_directory_memberof_key']))
                $this->config['active_directory_memberof_key'] = "memberof";

        if (empty($this->config['active_directory_email_key']))
                $this->config['active_directory_email_key'] = 'mail';

        return $this->_findUser($request->data['username'], $request->data['password']);
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
            // set up the bind RDN name
            // this will attempt a bind with the given rdns if one wasn't supplied.
            if (strpos($username,"@") === false) {
                foreach (explode(';',$this->config['auth_msad_rdn']) as $rdn) {
                    $rdnUser = "$username@$rdn";
                    $this->putlog('info',  "Trying: $rdnUser");
                    if (ldap_bind($this->ldapConnection,$rdnUser,$password) !== false)
                        break;
                }
            }
            $this->putlog('pass',  "Bind successful using: " . $rdnUser);

            list($login,$domain) = explode('@',$rdnUser);
            if (stripos($domain,"dc=") !== false)
                $searchBase = $domain;
            else
                $searchBase = "dc=" . join(',dc=',explode('.',$domain));

            $this->putlog('pass',  "Search Base: " . $searchBase);
            $this->putlog('pass',  "Search Filter: " . $this->config['active_directory_account_key']."=$login");
          
            $searchResults = null;
            $attrs = [$this->config['active_directory_account_key'], 'dn', $this->config['active_directory_memberof_key'], $this->config['active_directory_email_key']];
            foreach ($attrs as $key)
                $this->putlog('pass',  "Requesting attribute: $key");

            $results = $this->getEntries($this->ldapConnection, $searchBase, $this->config['active_directory_account_key']."=$login",
                    $attrs, $searchResults);

            $mode = $this->_identifyMode($searchResults, $results, $password);

           if ($results['count'] == 1) {
           		$this->putlog('ok',  "Initial user group list:");
           		foreach ($results[0][$this->config['active_directory_memberof_key']] as $dn) {
					if (is_string($dn)) {
						$this->putlog('ok',  "$dn");
					}
				}
           }

            return(array_merge(['username' => $this->request->data['username'], 'method' => 'Active Directory', 'info' => $this->logs], $mode));

        } catch (\ErrorException $e) {
            $this->putlog('fail', $e->getMessage());
        }
        restore_error_handler();
        return ['info' => $this->logs];
    }


}
