<?php
namespace App\Auth;

use Cake\Auth\BaseAuthenticate;
use Cake\Controller\ComponentRegistry;
use Cake\Network\Exception\InternalErrorException;
use Cake\Network\Exception\UnauthorizedException;
use Cake\Network\Request;
use Cake\Network\Response;
use Cake\ORM\TableRegistry;

/**
 * AuthBasic component
 */
class AuthBasicAuthenticate extends BaseAuthenticate
{
	public $optionalParamPrefix;

    protected $config = [];

    public $logs = [];

    protected $prefs;

    protected $controller;

    protected $userPreferences = ['tz' => 'America/Chicago',
                                  'date_format' => 'c',
                                  'lang' => 'eng',
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
        $this->controller = $this->_registry->getController();
        if(isset($this->request->data)){
            set_error_handler(
                function ($errorNumber, $errorText, $errorFile, $errorLine) {
                    throw new \ErrorException($errorText, 0, $errorNumber, $errorFile, $errorLine);
                },
                E_ALL
            );
        }
    
    }
    /**
    * Getting  ethod authentication settings
    * @return array of settings
    **/
   	public function getOptionalParamPrefix() 
    {
        $this->prefs = TableRegistry::get('Prefs'); $configs = [];
        foreach([$this->options['optionalParamPrefix'], $this->options['prefix']] as $value) {
            $opts = $this->prefs->find()->where(['name LIKE' => '%'.$value.'%'])->andWhere(['user_id' => 1])->toArray();
            if(!empty($opts)) {
                foreach ($opts as $opt) {
                    $configs[$opt['name']] = $opt['value'];
                }
            }
        }
        return $configs;
    }

    /**
    * Updating some user settings after loggined
    * @param integer $user_id is user id
    * @return void
    **/
    protected function updatePreferences($user_id) { 
        if(!empty($this->config)) {
            foreach ($this->config as $key => $value) {
               $this->prefs->setPreference($key, $value, $user_id);
            }
        }
    }

    /**
    * Getting user settings after loggined
    * @param integer $user_id is user id
    * @return array of user settings
    **/
    protected function getUserPreferences($user_id) {
        $result = [];
        if($user_id && $this->prefs) {
            foreach ($this->userPreferences as $key => $value) {
                $result[$key] = $this->prefs->getPreference($user_id, $key, $value);
            }
        }
        return $result;
    }

    public function getConfig() 
    {
        return $this->config;
    }

    /**
    * Write some logs messages for testing authentication
    * @param string $message is message
    * @param string $type is type of message
    * @return void
    */
    protected function putlog($type, $message) 
    {
        if($type && $message) {
            if(!is_array($message)){
                array_push($this->logs, ["message" => $message, "type" => $type]);
                if($type == 'fail')
                    $this->controller->Flash->set($message ,['element' => 'error']);
            } else {
                foreach ($message as $value)
                    array_push($this->logs, ["message" => $value, "type" => $type]);
            }
        }
    }

    public function _testConnection($options = []){}

    public function authenticate(Request $request, Response $response) {}
}
