<?php
namespace Pecee\Models\Legacy\User;

use Carbon\Carbon;
use Pecee\Cookie;
use Pecee\DB\PdoHelper;
use Pecee\Guid;
use Pecee\Models\Legacy\ModelData;

class User extends ModelData {

    const COOKIE_NAME = 'ticket';

    // Errors
    const ERROR_TYPE_BANNED = 0x1;
    const ERROR_TYPE_INVALID_LOGIN = 0x2;
    const ERROR_TYPE_EXISTS = 0x3;

    const ORDER_ID_DESC = 'u.`id` DESC';
    const ORDER_ID_ASC = 'u.`id` ASC';
    const ORDER_LASTACTIVITY_ASC = 'u.`last_activity` DESC';
    const ORDER_LASTACTIVITY_DESC = 'u.`last_activity` ASC';

    protected static $instance;

    protected static $ticketExpireMinutes = 60 * 1;

    protected $timestamps = true;

    protected $table = 'user';

    public static $ORDERS = [
        self::ORDER_ID_ASC,
        self::ORDER_ID_DESC,
        self::ORDER_LASTACTIVITY_ASC,
        self::ORDER_LASTACTIVITY_DESC
    ];

    protected $columns = [
        'id',
        'username',
        'password',
        'last_activity',
        'admin_level',
        'deleted'
    ];

    public function __construct($username = null, $password = null, $email = null) {

        parent::__construct();

        $this->username = $username;

        if ($password !== null) {
            $this->password = $this->setPassword($password);
        }

        $this->admin_level = 0;
        $this->last_activity = Carbon::now();
        $this->deleted = false;

        $this->setEmail($email);
    }

    public function setEmail($email) {
        $this->data->email = $email;
    }

    public function getEmail() {
        return $this->data->email;
    }

    public function save() {
        if($this->exists()) {
            throw new UserException(sprintf('The username %s already exists', $this->username), static::ERROR_TYPE_EXISTS);
        }
        parent::save();
    }

    public function updateData() {

        if($this->data !== null) {

            /* @var $userDataClass UserData */
            $userDataClass = static::getUserDataClass();
            $currentFields = $userDataClass::getByUserId($this->id);

            $cf = array();
            foreach($currentFields as $field) {
                $cf[strtolower($field->key)] = $field;
            }

            if(count($this->data->getData())) {
                foreach($this->data->getData() as $key=>$value) {

                    if($value === null) {
                        continue;
                    }

                    if(isset($cf[strtolower($key)])) {
                        if($cf[$key]->value === $value) {
                            unset($cf[$key]);
                            continue;
                        } else {
                            $cf[$key]->value = $value;
                            $cf[$key]->key = $key;
                            $cf[$key]->update();
                            unset($cf[$key]);
                        }
                    } else {
                        $field = new $userDataClass();
                        $field->{$userDataClass::USER_IDENTIFIER_KEY} = $this->id;
                        $field->key = $key;
                        $field->value = $value;
                        $field->save();
                    }
                }
            }

            foreach($cf as $field) {
                $field->delete();
            }
        }
    }

    protected function fetchData() {
        /* @var $class UserData */
        $class = static::getUserDataClass();
        $class = new $class();
        $data = $class::getByUserId($this->id);
        if($data->hasRows()) {
            foreach($data->getRows() as $d) {
                $this->setDataValue($d->key, $d->value);
            }
        }
    }

    public function update() {
        return parent::update();
    }

    public function delete() {
        //UserData::RemoveAll($this->id);
        $this->deleted = true;
        return parent::update();
    }

    public function signOut() {
        if(Cookie::exists(static::COOKIE_NAME)) {
            Cookie::delete(static::COOKIE_NAME);
        }
    }

    public function exists() {
        if($this->{$this->primary} === null) {
            return false;
        }

        return $this->scalar('SELECT u.`username` FROM {table} u WHERE u.`username` = %s && u.`deleted` = 0 LIMIT 1', $this->username);
    }

    public function registerActivity() {
        if($this->isLoggedIn()) {
            static::nonQuery('UPDATE {table} SET `last_activity` = NOW() WHERE `id` = %s', $this->id);
        }
    }

    protected function signIn(){
        static::createTicket($this->id);
    }

    public static function isLoggedIn() {

        $ticket = static::getTicket();

        try {

            if ($ticket === null || Carbon::parse($ticket[1])->diffInMinutes(Carbon::now()) > static::$ticketExpireMinutes) {
                Cookie::delete(static::COOKIE_NAME);

                return false;
            }

            return true;

        } catch (\Exception $e) {
            Cookie::delete(static::COOKIE_NAME);

            return false;
        }

    }

    public static function createTicket($userId)
    {
        /* Remove existing ticket */
        Cookie::delete(static::COOKIE_NAME);

        $ticket = Guid::encrypt(static::getSalt(), join('|', [
            $userId,
            Carbon::now()->addMinutes(static::$ticketExpireMinutes)->toW3cString(),
        ]));

        Cookie::create(static::COOKIE_NAME, $ticket);
    }

    public static function getTicket()
    {
        if (Cookie::exists(static::COOKIE_NAME) === false) {
            return null;
        }

        $ticket = Guid::decrypt(static::getSalt(), Cookie::get(static::COOKIE_NAME));

        if ($ticket !== false) {
            $ticket = explode('|', $ticket);

            return (count($ticket) > 0) ? $ticket : null;
        }

        return null;
    }

    /**
     * Sets users password and encrypts it.
     * @param string $password
     */
    public function setPassword($password) {
        $this->password = password_hash($password, PASSWORD_DEFAULT);
    }

    /**
     * Get current user
     * @return self
     */
    public static function current() {

        if (static::$instance !== null) {
            return static::$instance;
        }

        if (static::isLoggedIn() === true) {

            $ticket = static::getTicket();

            /* @var $user static */
            static::$instance = static::getById($ticket[0]);

            if (static::$instance !== null) {
                /* Refresh ticket */
                static::createTicket($ticket[0]);
            }

        }

        return static::$instance;

    }

    public static function getSalt() {
        return md5(env('APP_SECRET', 'NoApplicationSecretDefined'));
    }

    public static function get($query = null, $adminLevel = null, $deleted = null, $order = null, $rows = null, $page = null) {
        $order = (is_null($order) || !in_array($order, static::$ORDERS)) ? static::ORDER_ID_DESC : $order;

        $where = array('1=1');

        if($adminLevel !== null) {
            $where[] = PdoHelper::formatQuery('u.`admin_level` = %s', array($adminLevel));
        }
        if($deleted !== null) {
            $where[] = PdoHelper::formatQuery('u.`deleted` = %s', array($deleted));
        }
        if($query !== null) {
            $userData = static::getUserDataClass();
            $where[] = '(`username` LIKE \'%%' . PdoHelper::escape($query).'%%\' OR (SELECT `' .  $userData::USER_IDENTIFIER_KEY . '` FROM `'.$userData.'` WHERE `'. $userData::USER_IDENTIFIER_KEY .'` = u.`id` && `value` LIKE \'%%'.PdoHelper::escape($query).'%%\' LIMIT 1))';
        }
        return static::fetchPage('SELECT u.* FROM {table} u WHERE ' . join(' && ', $where) . ' ORDER BY '.$order, $rows, $page);
    }

    /**
     * Get user by user id.
     * @param int $id
     * @return self
     */
    public static function getById($id) {
        return static::fetchOne('SELECT u.* FROM {table} u WHERE u.`id` = %s && u.`deleted` = 0', array($id));
    }

    /**
     * @param array $ids
     * @return self
     */
    public static function getByIds(array $ids) {
        return static::fetchAll('SELECT u.* FROM {table} u WHERE u.`id` IN ('.PdoHelper::joinArray($ids).')' );
    }

    /**
     * @param $username
     * @return self
     */
    public static function getByUsername($username) {
        return static::fetchOne('SELECT u.* FROM {table} u WHERE u.`username` = %s && u.`deleted` = 0', $username);
    }

    public static function getByKeyValue($key, $value) {
        $userDataClass = static::getUserDataClass();
        return static::fetchOne('SELECT u.* FROM {table} u JOIN `'. $userDataClass .'` ud ON(ud.`'. $userDataClass::USER_IDENTIFIER_KEY .'` = u.`id`) WHERE ud.`key` = %s && ud.`value` = %s && u.`deleted` = 0', $key, $value);
    }

    public function auth() {
        return static::authenticate($this->username, $this->password, false);
    }

    /**
     * @param string $username
     * @param string $password
     * @param bool $remember
     * @return static
     * @throws UserException
     */
    public static function authenticate($username, $password) {
        static::onLoginStart();
        $user = static::fetchOne('SELECT u.* FROM {table} u WHERE u.`deleted` = 0 && u.`username` = %s', $username);
        if(!$user->hasRows()) {
            throw new UserException('Invalid login', static::ERROR_TYPE_INVALID_LOGIN);
        }
        // Incorrect user login.
        if(strtolower($user->username) != strtolower($username) || password_verify($password, $user->password) === false) {
            static::onLoginFailed($user);
            throw new UserException('Invalid login', static::ERROR_TYPE_INVALID_LOGIN);
        }
        static::onLoginSuccess($user);
        $user->signIn();
        return $user;
    }

    /**
     * @return string
     */
    public static function getUserDataClass() {
        return UserData::class;
    }

    // Events
    protected static function onLoginFailed(self $user){
        UserBadLogin::track($user->username);
    }

    protected static function onLoginSuccess(self $user) {
        UserBadLogin::reset();
    }

    protected static function onLoginStart() {
        if(UserBadLogin::checkBadLogin()) {
            throw new UserException('User has been banned', static::ERROR_TYPE_BANNED);
        }
    }
}