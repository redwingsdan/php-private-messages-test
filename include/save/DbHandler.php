<?php

/**
 * Class to handle all db operations
 * This class will have CRUD methods for database tables
 *
 * @author Ravi Tamada
 * @link URL Tutorial link
 */
class DbHandler {

    private $conn;

    function __construct() {
        require_once dirname(__FILE__) . '/DbConnect.php';
        // opening db connection
        $db = new DbConnect();
        $this->conn = $db->connect();
    }

    /* ------------- `users` table method ------------------ */

    /**
     * Creating new user
     * @param String $username User username
     * @param String $email User login email id
     * @param String $password User login password
     */
    public function createUser($username, $password, $email) {
        require_once 'PassHash.php';
        $response = array();

        // First check if user already existed in db
        if (!$this->isUserExists($username)) {
            // Generating password hash
            $password_hash = PassHash::hash($password);

            // Generating API key
            $api_key = $this->generateApiKey();

            // insert query
            $stmt = $this->conn->prepare("INSERT INTO users(username, password_hash, email, api_key, status) values(?, ?, ?, ?, 1)");
            $stmt->bind_param("ssss", $username, $password_hash, $email, $api_key);

            $result = $stmt->execute();

            $stmt->close();

            // Check for successful insertion
            if ($result) {
                // User successfully inserted
                return USER_CREATED_SUCCESSFULLY;
            } else {
                // Failed to create user
                return USER_CREATE_FAILED;
            }
        } else {
            // User with same email already existed in the db
            return USER_ALREADY_EXISTED;
        }

        return $response;
    }

    /**
     * Checking user login
     * @param String $username User login username id
     * @param String $password User login password
     * @return boolean User login status success/fail
     */
    public function checkLogin($username, $password) {
        // fetching user by username
        $stmt = $this->conn->prepare("SELECT password_hash FROM users WHERE username = ?");

        $stmt->bind_param("s", $username);

        $stmt->execute();

        $stmt->bind_result($password_hash);

        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            // Found user with the username
            // Now verify the password

            $stmt->fetch();

            $stmt->close();

            if (PassHash::check_password($password_hash, $password)) {
                // User password is correct
                return TRUE;
            } else {
                // user password is incorrect
                return FALSE;
            }
        } else {
            $stmt->close();

            // user not existed with the username
            return FALSE;
        }
    }

    /**
     * Checking for duplicate user by username address
     * @param String $username username to check in db
     * @return boolean
     */
    private function isUserExists($username) {
        $stmt = $this->conn->prepare("SELECT id from users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }
	
	public function isUserExists2($username){
		return $this->isUserExists($username);
	}

    /**
     * Fetching user by username
     * @param String $username User username id
     */
    public function getUserByUsername($username) {
        $stmt = $this->conn->prepare("SELECT id, username, email, api_key, status, created_at FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        if ($stmt->execute()) {
            $stmt->bind_result($id, $username, $email, $api_key, $status, $created_at);
            $stmt->fetch();
            $user = array();
			$user["id"] = $id;
            $user["username"] = $username;
            $user["email"] = $email;
            $user["api_key"] = $api_key;
            $user["status"] = $status;
            $user["created_at"] = $created_at;
            $stmt->close();
            return $user;
        } else {
            return NULL;
        }
    }

    /**
     * Fetching user api key
     * @param String $user_id user id primary key in user table
     */
    public function getApiKeyById($user_id) {
        $stmt = $this->conn->prepare("SELECT api_key FROM users WHERE id = ?");
        $stmt->bind_param("i", $user_id);
        if ($stmt->execute()) {
            $stmt->bind_result($api_key);
            $stmt->close();
            return $api_key;
        } else {
            return NULL;
        }
    }

    /**
     * Fetching user id by api key
     * @param String $api_key user api key
     */
    public function getUserId($api_key) {
        $stmt = $this->conn->prepare("SELECT id FROM users WHERE api_key = ?");
        $stmt->bind_param("s", $api_key);
        if ($stmt->execute()) {
            $stmt->bind_result($user_id);
            $stmt->fetch();
            $stmt->close();
            return $user_id;
        } else {
            return NULL;
        }
    }

    /**
     * Validating user api key
     * If the api key is there in db, it is a valid key
     * @param String $api_key user api key
     * @return boolean
     */
    public function isValidApiKey($api_key) {
        $stmt = $this->conn->prepare("SELECT id from users WHERE api_key = ?");
        $stmt->bind_param("s", $api_key);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }

    /**
     * Generating random Unique MD5 String for user Api key
     */
    private function generateApiKey() {
        return md5(uniqid(rand(), true));
    }

    /* ------------- `orders` table method ------------------ */

    /**
     * Creating new order
     * @param String $user_id user id to whom order belongs to
     * @param String $order order text
     */
    public function createOrder($user_id, $custName, $buildType, $pdfName, $assignedTo, $status) {
		
		$pdfPath = "//192.168.4.28/test/";
		$pdfPath = $pdfPath . $pdfName;
		$pdfPath = $pdfPath	. ".pdf";
		
		if($pdfName == "" | $pdfName == null){
			$pdfPath = null;
			$pdfName = null;
		}
		if($assignedTo == "" | $assignedTo == null){
			$assignedTo = null;
		}
		
		if($status == null | $status == ""){
			$status = 1;
		}
		
		//$answer = true;
		//while($answer == true){
		$rand = rand(0,9999);
		$id = $rand;
		//$sql = "SELECT * FROM orders o WHERE o.order = ". $id;
		//$answer2 = mysql_query($sql);
		//$num_rows2 = mysql_num_rows($answer2);
		//if($num_rows2 > 0){
		//	$answer = true;
		//	$id = $rand;
		//}
		//else{
		//	$answer = false;
		//}
		//}
		if(($this->isUserExists($assignedTo) == true) | ($assignedTo == null)){
		$stmt = $this->conn->prepare("INSERT INTO `orders`(`order`, customer_name, build_type, pdf_name, pdf_path, assigned_to, status) VALUES(?, ?, ?, ?, ?, ?, ?)");
        $stmt->bind_param("isssssi", $id, $custName, $buildType, $pdfName, $pdfPath, $assignedTo, $status);
		
        $result = $stmt->execute();
        $stmt->close();
		}
		else{
			$result = false;
		}
        if ($result) {
			$stmt = $this->conn->prepare("SELECT id, username, email, api_key, status, created_at FROM users WHERE username = ?");
			$stmt->bind_param("s", $assignedTo);
			if ($stmt->execute()) {
				$stmt->bind_result($id, $username, $email, $api_key, $status, $created_at);
				$stmt->fetch();
				$user = array();
				$user["id"] = $id;
				$user["username"] = $username;
				$user["email"] = $email;
				$user["api_key"] = $api_key;
				$user["status"] = $status;
				$user["created_at"] = $created_at;
				$stmt->close();
				$res = true;
				$id2 = $user["id"];
			}
			else if($assignedTo == null){
				$res = true;
				$id2 = null;
			}			
			else {
				$res = false;
			}
            // order row created
            // now assign the order to user
			if($res == true){
            $stmt = $this->conn->prepare("SELECT o.id from orders o WHERE o.order = ?");
			$stmt->bind_param("s", $rand);
			if ($stmt->execute()) {
				$stmt->bind_result($id);
				$stmt->fetch();
				$stmt->close();
				$user2 = array();
				$user2["id"] = $id;
			}
			}
			if($id2 == null){
			$stmt = $this->conn->prepare("INSERT INTO `user_tasks`(`user_id`, `order_id`) VALUES(15,?) ");
			$stmt->bind_param("i", $user2["id"]);	
			}
			else{
			$stmt = $this->conn->prepare("INSERT INTO `user_tasks`(`user_id`, `order_id`) VALUES(?,?) ");
			$stmt->bind_param("ii", $id2, $user2["id"]);
			}
			$stmt->execute();
            return $user2["id"];
			}
         else {
            // order failed to create
            return NULL;
        }

    }
	
	public function createUserTask($user_id, $new_order_id){
		$stmt = $this->conn->prepare("INSERT INTO `user_tasks`(`user_id`, `order_id`) VALUES(?,?) ");
        $stmt->bind_param("ii", $user_id, $new_order_id);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
	}

    /**
     * Fetching single order
     * @param String $order_id id of the order
     */
    public function getOrder() {
        $stmt = $this->conn->prepare("SELECT o.id, o.order, o.customer_name, o.build_type, o.pdf_name, o.pdf_path, o.status, o.created_at from orders o");

        if ($stmt->execute()) {
            $res = array();
            $stmt->bind_result($id, $order, $customer_name, $build_type, $pdf_name, $pdf_path, $status, $created_at);
            $stmt->fetch();
            $res["id"] = $id;
            $res["order"] = $order;
			$res["customer_name"] = $customer_name;
			$res["build_type"] = $build_type;
			$res["pdf_name"] = $pdf_name;
			$res["pdf_path"] = $pdf_path;
            $res["status"] = $status;
            $res["created_at"] = $created_at;
            $stmt->close();
            return $res;
        } else {
            return NULL;
        }
    }
	
	/**
     * Fetching all orders
     * @param String $order_id id of the order
     */
	public function getAllOrders() {
		$stmt = $this->conn->prepare("SELECT * FROM orders");
        $stmt->execute();
        $orders = $stmt->get_result();
		$result = count($orders);
        $stmt->close();
        return $orders;
    }
	
	/**
     * Fetching all orders from a particular id
     * @param String $order_id id of the order
     */
	public function getAllOrders2($order_id) {
		$stmt = $this->conn->prepare("SELECT o.* FROM orders o, user_tasks ut WHERE ut.user_id = ? AND ut.order_id = o.id");
        $stmt->bind_param("i", $order_id);
		$stmt->execute();
        $orders = $stmt->get_result();
		$result = count($orders);
        $stmt->close();
        return $orders;
    }

    /**
     * Fetching all user orders
     * @param String $user_id id of the user
     */
    public function getAllUserTasks($user_id) {
        $stmt = $this->conn->prepare("SELECT o.* FROM order o, user_tasks ut WHERE o.id = ut.order_id AND ut.user_id = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $orders = $stmt->get_result();
        $stmt->close();
        return $orders;
    }

    /**
     * Updating order
     * @param String $order_id id of the order
     * @param String $order order text
     * @param String $status order status
	 */
    public function updateOrder($user_id, $order_id, $assignedTo, $status) {
	   if($assignedTo == "" | $assignedTo == null){
			$assignedTo = null;
		}
		if(($this->isUserExists($assignedTo) == true) | ($assignedTo == null)){
	    $stmt = $this->conn->prepare("UPDATE orders o, user_tasks ut set o.status = ?, o.assigned_to = ? WHERE (o.id = ? AND o.id = ut.order_id AND ut.user_id = ?) OR(15 = ? AND o.id = ?)");
		$stmt->bind_param("isiiii",$status, $assignedTo, $order_id, $user_id, $user_id, $order_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
		
		if($assignedTo == null){
		$stmt = $this->conn->prepare("UPDATE user_tasks ut set ut.user_id = 15 WHERE ut.order_id = ?");
        $stmt->bind_param("i", $order_id);
        $stmt->execute();
		}
		else{
		$stmt = $this->conn->prepare("SELECT id, username, email, api_key, status, created_at FROM users WHERE username = ?");
        $stmt->bind_param("s", $assignedTo);
        if ($stmt->execute()) {
            $stmt->bind_result($id, $username, $email, $api_key, $status, $created_at);
            $stmt->fetch();
            $user = array();
			$user["id"] = $id;
            $user["username"] = $username;
            $user["email"] = $email;
            $user["api_key"] = $api_key;
            $user["status"] = $status;
            $user["created_at"] = $created_at;
            $stmt->close();
            $res = true;
        } else {
            $res = false;
        }
		if($res){
			$stmt = $this->conn->prepare("UPDATE user_tasks ut set ut.user_id = ? WHERE ut.order_id = ?");
			$stmt->bind_param("ii", $user["id"], $order_id);
			$stmt->execute();
		}
		else{
			return false;
		}
		}
		}
        return $num_affected_rows > 0;
    }
	
	
    /**
     * Deleting an order
     * @param String $order_id id of the order to delete
     */
    public function deleteOrder($user_id, $id) {   
		$stmt = $this->conn->prepare("DELETE o FROM orders o, user_tasks ut WHERE o.id = ? AND ut.order_id = o.id");
        $test = $stmt;
		if($test === false){
			}
			else{
		$stmt->bind_param("i", $id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
		
		if($num_affected_rows > 0){
			$stmt = $this->conn->prepare("DELETE FROM `user_tasks` WHERE `user_tasks` . `order_id` = ?");
			$stmt->bind_param("i", $id);
			$stmt->execute();
		}
			}
        return $num_affected_rows > 0;
    }

    /* ------------- `user_tasks` table method ------------------ */

    /**
     * Function to assign an order to user
     * @param String $user_id id of the user
     * @param String $order_id id of the order
     */
    public function assignUserTask($user_id, $order_id) {
        $stmt = $this->conn->prepare("INSERT INTO user_tasks(user_id, order_id) values(?, ?)");
        $stmt->bind_param("ii", $user_id, $order_id);
        $result = $stmt->execute();

        if (false === $result) {
            die('execute() failed: ' . htmlspecialchars($stmt->error));
        }
        $stmt->close();
        return $result;
    }
	
	public function updateUserTask($user_id, $order_id) {
		$stmt = $this->conn->prepare("UPDATE user_tasks ut set ut.user_id = ? WHERE ut.order_id = ?");
        $stmt->bind_param("ii", $user_id, $order_id);
        $result = $stmt->execute();

        if (false === $result) {
            die('execute() failed: ' . htmlspecialchars($stmt->error));
        }
        $stmt->close();
        return $result;
    }
	
	public function unAssignUserTask($user_id, $order_id) {
		$stmt = $this->conn->prepare("UPDATE user_tasks ut set ut.user_id = 15 WHERE ut.order_id = ?");
        $stmt->bind_param("i", $order_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
	}

}

?>

