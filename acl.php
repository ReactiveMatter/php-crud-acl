<?php

/* Note: Some thigs can be done directly in Adminer. Hence those features of will not be implemented
*/

// Auth Middleware - Custom middle ware to handle authorization and related tasks
namespace Tqdev\PhpCrudApi\Middleware {

    use Psr\Http\Message\ResponseInterface;
    use Psr\Http\Message\ServerRequestInterface;
    use Psr\Http\Server\RequestHandlerInterface;
    use Tqdev\PhpCrudApi\Column\ReflectionService;
    use Tqdev\PhpCrudApi\Config\Config;
    use Tqdev\PhpCrudApi\Controller\Responder;
    use Tqdev\PhpCrudApi\Database\GenericDB;
    use Tqdev\PhpCrudApi\Middleware\Base\Middleware;
    use Tqdev\PhpCrudApi\Middleware\Router\Router;
    use Tqdev\PhpCrudApi\Record\Condition\ColumnCondition;
    use Tqdev\PhpCrudApi\Record\Condition\NoCondition;
    use Tqdev\PhpCrudApi\Record\ErrorCode;
    use Tqdev\PhpCrudApi\Record\OrderingInfo;
    use Tqdev\PhpCrudApi\RequestUtils;

    //This handles the Access Control Layer
    class ACLMiddleware extends Middleware
    {
        private $reflection;
        private $db;
        private $ordering;
        private $isLoggedIn;
        private $isAdmin;
        private $loggedInUser;

        private function checkIfLoggedIn()
        {
            if (!isset($_SESSION['user']) || !$_SESSION['user']){
                return false;
            }
            else {
                return true;
            }
        }

        private function getuser($username)
        {
            $tableName = $this->getProperty('usersTable', 'users');
            $table = $this->reflection->getTable($tableName);
            $columnOrdering = $this->ordering->getDefaultColumnOrdering($table);
            $condition = new ColumnCondition($table->getColumn('username'), 'eq', $username);
            $columnNames = $table->getColumnNames();

            $users = $this->db->selectAll($table, $columnNames, $condition, $columnOrdering, 0, 1);
            if (!empty($users)) {

                if(sizeof($users) == 1)
                {
                    return $users[0];
                }
            }

            return false;
        }

        /* Checks whether a particular action is permitted for the user group or not*/
        /* All endpoints will be covered in this */

        private function actionPermitted($action, $group, $table = NULL)
        {
            if(in_array('admin', $group))
            {
                return true;
            }

            if(in_array($action, $this->adminOnlyActions))
            {
                return false;
            }
            
            $table = $this->reflection->getTable('acl');
            $columnOrdering = $this->ordering->getDefaultColumnOrdering($table);

            $condition = new ColumnCondition($table->getColumn('id'), 'eq', $id);
            $columnNames = $table->getColumnNames();

        }

        private function checkIfAdmin()
        {

                if(!$this->checkIfLoggedIn()){
                    return false;
                }

                $user = $_SESSION['user'];

                $user['group'] = explode(',', $user['group']);

                if(in_array('admin',$user['group']))
                {
                    return true;
                }
                else
                {
                    return false;
                }
        }

        private function getUserByID($id)
        {
            $tableName = $this->getProperty('usersTable', 'users');
            $table = $this->reflection->getTable($tableName);
            $columnOrdering = $this->ordering->getDefaultColumnOrdering($table);
            $condition = new ColumnCondition($table->getColumn('id'), 'eq', $id);
            $columnNames = $table->getColumnNames();
            $users = $this->db->selectAll($table, $columnNames, $condition, $columnOrdering, 0, 1);
            if (!empty($users)) {

                if(sizeof($users) == 1)
                {
                    return $users[0];
                }
            }

            return false;
        }


        public function operationPermitted($group, $tableNames, $operation)
        {   
            $table = $this->reflection->getTable('acl');
            $columnOrdering = $this->ordering->getDefaultColumnOrdering($table);
            $columnNames = $table->getColumnNames();
            $condition = new NoCondition();
            $permission = 0;
            $acl = $this->db->selectAll($table, $columnNames, $condition, $columnOrdering, 0, -1);

            foreach ($acl as $rule)
            {   
                $rule['permission'] = (int)$rule['permission'];

                if(in_array($rule['group'],$group) && in_array($rule['table'], $tableNames))
                {
                    if($rule['permission']>$permission)
                    {
                        $permission = $rule['permission'];
                    }
                }

                if($rule['group']=='all' && in_array($rule['table'], $tableNames))
                {
                     if($rule['permission']>$permission)
                    {
                        $permission = $rule['permission'];
                    }
                }

                if(in_array($rule['group'],$group) && $rule['table']=='all')
                {
                     if($rule['permission']>$permission)
                    {
                        $permission = $rule['permission'];
                    }
                }

                if($rule['group']=='all' && $rule['table']=='all')
                {
                     if($rule['permission']>$permission)
                    {
                        $permission = $rule['permission'];
                    }
                }
            }

            if($operation == 'read' || $operation == 'list')
            {
                if($permission >= 1 ) {return true;}
            }
            else if ($operation == 'create')
            {
                if($permission >= 2 ) {return true;}
            }
            else if ($operation == 'update')
            {
                if($permission >= 4 ) {return true;}
            }
            else if ($operation == 'delete')
            {
                if($permission >= 8 ) {return true;}
            }

            return false;
        }

        public function __construct(Router $router, Responder $responder, Config $config, string $middleware, ReflectionService $reflection, GenericDB $db)
        {
            parent::__construct($router, $responder, $config, $middleware);
            $this->reflection = $reflection;
            $this->db = $db;
            $this->ordering = new OrderingInfo();

        }

        public function process(ServerRequestInterface $request, RequestHandlerInterface $next): ResponseInterface
        {
            if (session_status() == PHP_SESSION_NONE) {
                if (!headers_sent()) {
                    $sessionName = $this->getProperty('sessionName', '');
                    if ($sessionName) {
                        session_name($sessionName);
                    }
                    if (!ini_get('session.cookie_samesite')) {
                        ini_set('session.cookie_samesite', 'Lax');
                    }
                    if (!ini_get('session.cookie_httponly')) {
                        ini_set('session.cookie_httponly', 1);
                    }
                    if (!ini_get('session.cookie_secure') && isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off') {
                        ini_set('session.cookie_secure', 1);
                    }
                    session_start();
                }
            }

            /*Privileged user operations */
            $pathForLoggedInOnly = ['changepassword', 'me'];
            $pathForAdminOnly =  ['register','changegroup'];

            $path = RequestUtils::getPathSegment($request, 1);
            $method = $request->getMethod();
            $tableName = $this->getProperty('usersTable', 'users');
            $table = $this->reflection->getTable($tableName);
            $columnOrdering = $this->ordering->getDefaultColumnOrdering($table);
            $columnNames = $table->getColumnNames();
            $passwordLength = $this->getProperty('passwordLength', 8);

            $this->isLoggedIn = $this->checkIfLoggedIn();
            
            if($this->isLoggedIn)
            {    
                $this->isAdmin = $this->checkIfAdmin();
                $this->loggedInUser = $_SESSION['user'];
            }


            if ($method == 'POST' && $path == 'login'){
                $body = $request->getParsedBody();

                if(!isset($body->username))
                {
                    return $this->responder->error(ErrorCode::INPUT_VALIDATION_FAILED, "user");
                }
                if(!isset($body->password))
                {
                    return $this->responder->error(ErrorCode::INPUT_VALIDATION_FAILED, $body->username);
                }

                $username = $body->username;
                $password = $body->password;
                //$this->login($body->username,$body->password);

                $condition = new ColumnCondition($table->getColumn('username'), 'eq', $username);

                $user = $this->getuser($username);
                    if($user){
                        if (password_verify($password, $user['password'])) {
                            if (!headers_sent()) 
                            {
                                session_regenerate_id(true);
                            }
                            unset($user['password']);
                            $_SESSION['user'] = $user;
                            return $this->responder->success($user);
                        }
                    }
                 
                return $this->responder->error(ErrorCode::AUTHENTICATION_FAILED, $username);
                }

            else if ($path == 'logout') {
                session_destroy();
                return $this->responder->success(['message' => "Logged out successfully"]);
            }
            

            if ($path == 'user')
            {
                $path = RequestUtils::getPathSegment($request, 2);
                if (in_array($path, $pathForLoggedInOnly)) {
                    if(!$this->isLoggedIn) {
                        return $this->responder->error(ErrorCode::AUTHENTICATION_REQUIRED, '');
                    }
                }
                
                if(in_array($path, $pathForAdminOnly)){       
                     if(!$this->isAdmin){                   
                        return $this->responder->error(ErrorCode::OPERATION_FORBIDDEN, $this->loggedInUser['username']);
                        }
                }

                if ($path == 'me') {
                    return $this->responder->success($_SESSION['user']);
                }
                else if ($method == 'POST' && $path == 'register') {

                    $body = $request->getParsedBody();
                    $username = $body->username;
                    $password = $body->password;
                    $group = $body->group;

                    if (!isset($username) || strlen(trim($username)) == 0) {
                        return $this->responder->error(ErrorCode::USERNAME_EMPTY, $username);
                    }

                    if ($this->getuser($username)) {
                        return $this->responder->error(ErrorCode::USER_ALREADY_EXIST, $username);
                    }

                    if (!isset($password) || strlen($password) < $passwordLength) {
                        return $this->responder->error(ErrorCode::PASSWORD_TOO_SHORT, $passwordLength);
                    }

                    /* Parsing group of the new user */
                    if (!isset($group)) {
                        $group = ['user'];
                    }
                    else{
                    
                        if(!is_array($group)) {
                            $group = explode(',', $body->group);
                        }

                        if(!in_array('user',$group)){
                            array_push($group,"user");
                        }

                        $group = implode(",",$group);
                    }


                    $data['username'] = $username;
                    $data['password'] = password_hash($password, PASSWORD_DEFAULT);
                    $data['group'] = $group;

                    $this->db->createSingle($table, $data);
                    $users = $this->db->selectAll($table, $columnNames, $condition, $columnOrdering, 0, 1);
                    foreach ($users as $user) {
                            unset($user['password']);
                            return $this->responder->success($user);
                    }
                    return $this->responder->error(ErrorCode::AUTHENTICATION_FAILED, $username);
                }

                //For changing passoword reset
                else if ($method == 'POST' && $path == 'changepassword') {

                    $body = $request->getParsedBody();
                    $user = $this->loggedInUser;
                    $targetid = $user['id'];

                    if(isset($body->id) && $user['id'] != $body->id)
                    {   
                        /*For changing password of other user, the user should be admin */
                         if(!$this->isAdmin) {
                        return $this->responder->error(ErrorCode::OPERATION_FORBIDDEN, $user['username']);
                        }

                        $targetid = $body->id;
                    }

                    if (!isset($body->password) || strlen($body->password) < $passwordLength) {
                        return $this->responder->error(ErrorCode::PASSWORD_TOO_SHORT, $passwordLength);
                    }
                    

                    $data = ['password' => password_hash(trim($body->password), PASSWORD_DEFAULT)];
                    $affect_row = $this->db->updateSingle($table, $data, $targetid);
                    
                    if($affect_row && $affect_row > 0)
                    {
                        return $this->responder->success(['id'=>$targetid, 'message' => "Password changed successfully"]);
                    } 
                    else
                    {
                        return $this->responder->error(ErrorCode::OPERATION_NOT_SUPPORTED, $targetid);
                    }
                }
                
                //For changing group of a user by admin
                else if ($method == 'POST' && $path == 'changegroup') {

                    $user = $this->loggedInUser;


                    if(!$this->isAdmin)
                    {
                        return $this->responder->error(ErrorCode::OPERATION_FORBIDDEN, '');
                    }

                    $body = $request->getParsedBody();

                    if(!isset($body->id) || !isset($body->group))
                    {
                        return $this->responder->error(ErrorCode::INCORRECT_PARAMETERS, '');
                    }
     
                    $targetid = $body->id;

                    // Check if target user exists
                    if(!$this->getUserByID($targetid))
                    {
                        return $this->responder->error(ErrorCode::USER_NOT_EXISTS, $targetid);
                    }
                    
                    if(is_array($body->group))
                    {
                        $group = $body->group;
                    }
                    else
                    {   if(strlen($body->group) == 0)
                        {
                            $body->group = 'user';
                        }
                        
                        $group = explode(',', $body->group);
                    }

                    if(!in_array('user',$group))
                    {
                        array_push($group,"user");
                    }

                    
                    $group = implode(",",$group);
                    
        
                    $data = ['group' => $group];
                    $this->db->updateSingle($table, $data, $targetid);
                            
                    return $this->responder->success(['id'=>$targetid, 'message' => "Group changed successfully"]);

                }
            }

         /*ACL Rules Checking starts here
          Table structure of acl
          group (varchar(32)), table (varchar(32)), permission(tinyiny)
          Values:
          none = 0; read=1; create=2; update=4; delete=8;
          A user having all rights should have permission set to 8
         */

              if(!$this->isLoggedIn) 
             {
               $group = ['all'];
             }
             else
             {
                $group = explode(',',$this->loggedInUser['group']);
             }

          $operation = RequestUtils::getOperation($request);
          $tableNames = RequestUtils::getTableNames($request, $this->reflection);

          if(!$this->operationPermitted($group, $tableNames, $operation))
          {
             return $this->responder->error(ErrorCode::OPERATION_FORBIDDEN, '');
          }

          return $next->handle($request);
        }
    }
}
