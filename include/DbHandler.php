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

		if($username == "" | $username == null){
			return USER_CREATE_FAILED;
		}
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
    public function createOrder($user_id, $custName, $buildType, $pdfName, $assignedTo, $status, $idval, $num_builds, $buildType1, $num_builds1) {
		
		$pdfPath = "//" . $_SERVER['SERVER_ADDR'] . "/test/";
		#$pdfPath = "//192.168.4.28/test/";
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
		
		$id = $idval;
		$idreal = $id;
		$size2 = count($num_builds1);
		
		if(($this->isUserExists($assignedTo) == true) | ($assignedTo == null)){
		$stmt = $this->conn->prepare("INSERT INTO `orders`(`order`, customer_name, build_type, pdf_name, pdf_path, assigned_to, status, num_builds) VALUES(?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->bind_param("isssssii", $id, $custName, $buildType, $pdfName, $pdfPath, $assignedTo, $status, $size2);
		
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
			$stmt->bind_param("s", $idreal);
			if ($stmt->execute()) {
				$stmt->bind_result($id);
				$stmt->fetch();
				$stmt->close();
				$user2 = array();
				$user2["id"] = $id;
			}
			}
			if($id2 == null){
			$stmt = $this->conn->prepare("INSERT INTO `user_tasks`(`user_id`, `order_id`) VALUES(0,?) ");
			$stmt->bind_param("i", $user2["id"]);	
			}
			else{
			$stmt = $this->conn->prepare("INSERT INTO `user_tasks`(`user_id`, `order_id`) VALUES(?,?) ");
			$stmt->bind_param("ii", $id2, $user2["id"]);
			}
			$stmt->execute();
			$stmt->close();
			
			for($i = 0, $size = count($buildType1); $i < $size; ++$i){
					$stmt = $this->conn->prepare("SELECT p.id from parts p WHERE p.name = ?");
					$stmt->bind_param("s", $buildType1[$i]);	
					if ($stmt->execute()) {
						$stmt->bind_result($id);
						$stmt->fetch();
						$stmt->close();
						$ids = array();
						$ids["id"] = $id;
					}
				//$stmt = $this->conn->prepare("INSERT INTO `orders_parts`(`order_id`, `part_id`, 'count') VALUES(?,?,?)");
				//$stmt->bind_param("iii", $user2["id"], $ids["id"], $num_builds[$i]);
				$stmt = $this->conn->prepare("INSERT INTO `orders_parts`(`order_id`, `part_id`, `count`, `val`) VALUES(?,?,?,?)");
				$stmt->bind_param("iiii", $user2["id"], $ids["id"], $num_builds1[$i], $i);
				$stmt->execute();
				$stmt->close();
			}
			
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
     * Creating new part
     * @param String $user_id user id to whom order belongs to
     * @param String $order order text
     */
    public function createPart($name, $chassis, $motherboard, $cpu, $memory) {

		$stmt = $this->conn->prepare("INSERT INTO `roles`(role, team, killpower, assigned_to, targets) VALUES(?, ?, ?, ?, ?)");
        $stmt->bind_param("siisi", $name, $chassis, $motherboard, $cpu, $memory);
        $stmt->execute();
		$stmt->store_result();
		$num_rows = $stmt->num_rows;
        $stmt->close();
		
		$stmt = $this->conn->prepare("SELECT id, username, email, api_key, status, created_at FROM users WHERE username = ?");
        $stmt->bind_param("s", $cpu);
        if ($stmt->execute()) {
            $stmt->bind_result($id, $username, $email, $api_key, $status, $created_at);
            $stmt->fetch();
            $user = array();
			$user["id"] = $id;
            $user["username"] = $username;
            $stmt->close();
        }
		
		$stmt = $this->conn->prepare("SELECT id FROM roles WHERE role = ?");
        $stmt->bind_param("s", $name);
        if ($stmt->execute()) {
            $stmt->bind_result($id);
            $stmt->fetch();
            $user2 = array();
			$user2["id"] = $id;
            $stmt->close();
        }
	
		$stmt = $this->conn->prepare("INSERT INTO `targets`(role_id, user_id) VALUES(?, ?)");
        $stmt->bind_param("ii", $user2["id"], $user["id"]);
        $stmt->execute();
		$stmt->close();
		return true;
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
	
	public function getAllUsers() {
		$stmt = $this->conn->prepare("SELECT * FROM users ORDER BY id ASC");
        $stmt->execute();
        $users = $stmt->get_result();
		$result = count($users);
        $stmt->close();
        return $users;
	}
	
	
	/**
     * Fetching all parts
     * @param String $order_id id of the order
     */
	public function getAllParts() {
		$stmt = $this->conn->prepare("SELECT * FROM roles ORDER BY id ASC");
        $stmt->execute();
        $parts = $stmt->get_result();
		$result = count($parts);
        $stmt->close();
        return $parts;
    }
	
	/**
     * Fetching all orders
     * @param String $order_id id of the order
     */
	public function getAllOrders() {
		$stmt = $this->conn->prepare("SELECT * FROM orders ORDER BY id ASC");
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
	public function getAllOrders2($order) {
		$stmt = $this->conn->prepare("SELECT `count` FROM orders_parts WHERE order_id = ? ORDER BY id ASC");
		$stmt->bind_param("s", $order);
        $stmt->execute();
        $parts = $stmt->get_result();
        $stmt->close();
        return $parts;
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
    public function updateOrder($user_id, $order_id, $assignedTo, $status, $numbuilds, $orderid, $pdf, $build, $cust, $numBuilds2, $builds2) {
	   if($assignedTo == "" | $assignedTo == null){
			$assignedTo = null;
		}
		$pdfPath = "//" . $_SERVER['SERVER_ADDR'] . "/test/";
		$pdfPath = $pdfPath . $pdf;
		$pdfPath = $pdfPath	. ".pdf";
		
		if($pdf == "" | $pdf == null){
			$pdfPath = null;
			$pdf = null;
		}
		$size2 = (count($numBuilds2) - 1);
		if(($this->isUserExists($assignedTo) == true) | ($assignedTo == null)){
	    //$stmt = $this->conn->prepare("UPDATE orders o, user_tasks ut set o.status = ?, o.assigned_to = ? WHERE (o.id = ? AND o.id = ut.order_id AND ut.user_id = ?) OR(15 = ? AND o.id = ?)");
		//$stmt->bind_param("isiiii",$status, $assignedTo, $order_id, $user_id, $user_id, $order_id);
		
		$stmt = $this->conn->prepare("UPDATE orders o, user_tasks ut set o.order = ?, o.pdf_name = ?, o.pdf_path = ?, o.build_type = ?, o.customer_name = ?, o.num_builds = ?, o.status = ?, o.assigned_to = ? WHERE (o.id = ? AND o.id = ut.order_id)");
		$stmt->bind_param("issssiisi", $orderid, $pdf, $pdfPath, $build, $cust, $size2, $status, $assignedTo, $order_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
		
		if($assignedTo == null){
		$stmt = $this->conn->prepare("UPDATE user_tasks ut set ut.user_id = 0 WHERE ut.order_id = ?");
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
			$stmt->close();
		}
		}
		$arr = array();
		$stmt = $this->conn->prepare("SELECT COUNT(val) FROM orders_parts WHERE order_id = ? ORDER BY id ASC");
		$stmt->bind_param("s", $order_id);
        if ($stmt->execute()) {
            $stmt->bind_result($counter);
			$stmt->fetch();
            $stmt->close();
			$vals = array();
			$vals["count"] = $counter;
		}
		
				$stmt = $this->conn->prepare("DELETE FROM `orders_parts` WHERE `orders_parts` . `order_id` = ?");
				$stmt->bind_param("i", $order_id);
				$stmt->execute();
				$stmt->close();
				
		for($i = 1, $size = count($builds2); $i < $size; ++$i){
					$z = $i - 1;
					$stmt = $this->conn->prepare("SELECT p.id from parts p WHERE p.name = ?");
					$stmt->bind_param("s", $builds2[$i]);	
					if ($stmt->execute()) {
						$stmt->bind_result($id);
						$stmt->fetch();
						$stmt->close();
						$ids = array();
						$ids["id"] = $id;
					}
			//	if($z >= $vals["count"]){
				$stmt = $this->conn->prepare("INSERT INTO `orders_parts`(`order_id`, `part_id`, `count`, `val`) VALUES(?,?,?,?)");
				$stmt->bind_param("iiii", $order_id, $ids["id"], $numBuilds2[$i], $z);
				$stmt->execute();
				$stmt->close();
			//	}

			//	else{		
			//	$stmt = $this->conn->prepare("UPDATE orders_parts op set op.part_id = ?, op.count = ? WHERE (op.order_id = ? AND op.val = ?)");
			//	$stmt->bind_param("iiii", $ids["id"], $numBuilds2[$i], $order_id, $z);
			//	$stmt->execute();
			//	$stmt->close();
			//	}
				
			}
			if($num_affected_rows <= 0){
					$num_affected_rows = 1;
				}
		}
        return $num_affected_rows > 0;
    }
	
	/////////////////////////////////////////
	
	public function updateOrder2($status, $assignedTo, $pdf, $build, $cust, $user_id, $order_id) {
		$order = $order_id + 1;
		$user = $user_id;
		
		$stmt = $this->conn->prepare("SELECT id FROM roles WHERE role = ?");	//id of doctor(person doing the action)
        $stmt->bind_param("s", $cust);
        if ($stmt->execute()) {
            $stmt->bind_result($id);
            $stmt->fetch();
            $user2 = array();
			$user2["id"] = $id;
            $stmt->close();
        }
		
		$stmt = $this->conn->prepare("SELECT role FROM roles WHERE id = ?");	//id of user
        $stmt->bind_param("i", $user);
        if ($stmt->execute()) {
            $stmt->bind_result($id2);
            $stmt->fetch();
            $user = array();
			$user["id"] = $id2;
            $stmt->close();
        }
		
		$stmt = $this->conn->prepare("SELECT role FROM roles WHERE assigned_to = ?");	//id of user
        $stmt->bind_param("s", $assignedTo);
        if ($stmt->execute()) {
            $stmt->bind_result($id3);
            $stmt->fetch();
            $val = array();
			$val["id"] = $id3;
            $stmt->close();
        }
		
		if($val["id"] == null | $assignedTo == "admin"){
		//$stmt = $this->conn->prepare("UPDATE roles r, targets t set r.role = ?, r.team = ?, r.killpower = ?, r.assigned_to = ?, r.targets = ?, t.role_id = ?, t.user_id = ?, t.val = ? WHERE (r.id = ?)");
		//$stmt->bind_param("siisiiiii", $cust, $build, $pdf, $assignedTo, $status, $user2["id"], $user, $order, $user2["id"]);
		$stmt = $this->conn->prepare("UPDATE roles r set r.role = ?, r.team = ?, r.killpower = ?, r.assigned_to = ?, r.targets = ? WHERE (r.id = ?)");
		$stmt->bind_param("siisii", $cust, $build, $pdf, $assignedTo, $status, $user2["id"]);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();

		if($num_affected_rows <= 0){
				$num_affected_rows = 1;
			}
        return $num_affected_rows > 0;
		}
		else{
			return false;
		}
    }
	
	public function updateOrder3($user_id, $order_id) {
		$order = $order_id;
		$user = $user_id;
		
		$stmt = $this->conn->prepare("UPDATE targets t set t.user_id = ?, t.val = ? WHERE (t.user_id = ?)");
		$stmt->bind_param("iii", $user, $order, $user);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
		
		$stmt = $this->conn->prepare("SELECT * FROM targets ORDER BY id ASC");
		$stmt->execute();
        $users = $stmt->get_result();
		$result = count($users);
        $stmt->close();
        return $users;
     

		if($num_affected_rows <= 0){
				$num_affected_rows = 1;
			}
        //return $num_affected_rows > 0;
    }
	
	public function updateOrder4() {
		
		$stmt = $this->conn->prepare("UPDATE targets set val = 0");
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();

		if($num_affected_rows <= 0){
				$num_affected_rows = 1;
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
		if($num_affected_rows > 0){
			$stmt = $this->conn->prepare("DELETE FROM `orders_parts` WHERE `orders_parts` . `order_id` = ?");
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
		$stmt = $this->conn->prepare("UPDATE user_tasks ut set ut.user_id = 0 WHERE ut.order_id = ?");
        $stmt->bind_param("i", $order_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
	}

}

?>

