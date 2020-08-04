<?php

require_once '../include/DbHandler.php';
require_once '../include/PassHash.php';
require '.././libs/Slim/Slim.php';

\Slim\Slim::registerAutoloader();

$app = new \Slim\Slim();

// User id from db - Global Variable
$user_id = NULL;

/**
 * Adding Middle Layer to authenticate every request
 * Checking if the request has valid api key in the 'Authorization' header
 */
function authenticate(\Slim\Route $route) {

	// Getting request headers
    $headers = apache_request_headers();
    $response = array();
    $app = \Slim\Slim::getInstance();

    // Verifying Authorization Header
    if (isset($headers['Authorization'])) {
        $db = new DbHandler();

        // get the api key
		global $api_key2;
        $api_key = $headers['Authorization'];
        // validating api key
        if (!$db->isValidApiKey($api_key)) {
            // api key is not present in users table
            $response["error"] = true;
            $response["message"] = "Access Denied. Invalid Api key";
            echoResponse(401, $response);
            $app->stop();
        } else {
            global $user_id;
            // get user primary key id
            $user_id = $db->getUserId($api_key);
        }
    } else {
        // api key is missing in header
        $response["error"] = true;
        $response["message"] = "Api key is missing";
        echoResponse(400, $response);
        $app->stop();
    }
}

/**
 * ----------- METHODS WITHOUT AUTHENTICATION ---------------------------------
 */
/**
 * User Registration
 * url - /register
 * method - POST
 * params - name, email, password
 */
$app->post('/register', function() use ($app) {
            // check for required params

			$request = $app->request();
			$body = $request->getBody();
			$input = json_decode($body);
			
			$username = (string)$input->username;
            $password = (string)$input->password;
			$email = (string)$input->email;
			
            $response = array();

            // validating email address
            validateEmail($email);

            $db = new DbHandler();
            $res = $db->createUser($username, $password, $email);
			

            if ($res == USER_CREATED_SUCCESSFULLY) {
                $response["error"] = false;
                $response["message"] = "You are successfully registered";
            } else if ($res == USER_CREATE_FAILED) {
                $response["error"] = true;
                $response["message"] = "Oops! An error occurred while registereing";
            } else if ($res == USER_ALREADY_EXISTED) {
                $response["error"] = true;
                $response["message"] = "Sorry, this email already existed";
            }
            echoResponse(201, $response);
        });

/**
 * User Login
 * url - /login
 * method - POST
 * params - username, password
 */
$app->post('/login', function() use ($app) {
            // check for required params

			$request = $app->request();
			$body = $request->getBody();
			$input = json_decode($body);
            // reading post params
            $username = (string)$input->username;
            $password = (string)$input->password;
			
            $response = array();

            $db = new DbHandler();
            // check for correct username and password
            if ($db->checkLogin($username, $password)) {
                // get the user by username
                $user = $db->getUserByUsername($username);

                if ($user != NULL) {
                    $response["error"] = false;
					$response['message'] = "Logged in Successfully!";
                    $response['username'] = $user['username'];
                    $response['email'] = $user['email'];
                    $response['apiKey'] = $user['api_key'];
                    $response['createdAt'] = $user['created_at'];
					$response['id'] = $user['id'];
                } else {
                    // unknown error occurred
                    $response['error'] = true;
                    $response['message'] = "An error occurred. Please try again";
                }
            } else {
                // user credentials are wrong
                $response['error'] = true;
                $response['message'] = 'Login failed. Incorrect credentials';
            }
            echoResponse(200, $response);
        });

/*
 * ------------------------ METHODS WITH AUTHENTICATION ------------------------
 */
		 
/**
 * Listing all orders
 * method GET
 * url /orders         
 */
$app->get('/orders', 'authenticate', function() {
            $response = array();
            $db = new DbHandler();

            // fetching all user orders
            $result = $db->getAllOrders3();

            $response["error"] = false;
            $response["orders"] = array();

            // looping through result and preparing tasks array
            while ($order = $result->fetch_assoc()) {
                $tmp = array();
				$tmp["id"] = $order["id"];
				$tmp["username"] = $order["username"];
				$tmp["email"] = $order["email"];
				$tmp["api_key"] = $order["api_key"];
				$tmp["status"] = $order["status"];
				$tmp["created_at"] = $order["created_at"];
                array_push($response["orders"], $tmp);
            }
            echoResponse(200, $response);
        });

/**
 * Listing single order of particual user
 * method GET
 * url /orders/:id
 * Will return 404 if the order doesn't belongs to user
 */
$app->get('/orders/:id', 'authenticate', function($order_id) {
            global $user_id;
            $response = array();
            $db = new DbHandler();

			
			//$result = $db->getAllOrders2($order_id);
			$result = $db->getAllOrders();

            $response["error"] = false;
            $response["orders"] = array();

            // looping through result and preparing tasks array
            while ($order = $result->fetch_assoc()) {
                $tmp = array();
                $tmp["id"] = $order["id"];
                $tmp["order"] = $order["order"];
				$tmp["customer_name"] = $order["customer_name"];
				$tmp["build_type"] = $order["build_type"];
				$tmp["pdf_path"] = $order["pdf_path"];
                $tmp["status"] = $order["status"];
                $tmp["createdAt"] = $order["created_at"];
				$tmp["assigned_to"] = $order["assigned_to"];
				$user_test = $db->getUserByUsername($order["assigned_to"]);
				$id_test = $user_test["id"];
				if($user_id == $id_test){
                array_push($response["orders"], $tmp);
				}
            }
            echoResponse(200, $response);
        });

/**
 * Creating new order in db
 * method POST
 * params - name
 * url - /orders/
 */
$app->post('/orders', 'authenticate', function() use ($app) {
            // check for required params
            verifyRequiredParams(array('order'));
					
			$request = $app->request();
			$body = $request->getBody();
			$input = json_decode($body,true);

			$r1 = $input['custName'];
			$r2 = $input['buildType'];
			$r3 = $input['pdfName'];
			$r4 = $input['assignedTo'];
			$r5 = $input['status'];
			global $user_id;
            $db = new DbHandler();		
			if($user_id == 15){
			$order_id = $db->createOrder($user_id, $r1, $r2, $r3, $r4, $r5);
			}
			else{
				$order_id = NULL;
			}
            if ($order_id != NULL) {
				$response["error"] = false;
				$response["message"] = "order created successfully";
				$response["order_id"] = $order_id;
				$response["status"] = $r5;
				echoResponse(201, $response);
            } else {
                $response["error"] = true;
                $response["message"] = "Failed to create order. Please try again";
				$response["order_id"] = $order_id;
                echoResponse(200, $response);
            }       
        });

/**
 * Updating existing order
 * method PUT
 * params order, status
 * url - /orders/:id
 */
$app->put('/orders/:id', 'authenticate', function($order_id) use($app) {
            // check for required params
            verifyRequiredParams(array('order', 'status'));
			$request = $app->request();
			$body = $request->getBody();
			$input = json_decode($body,true);
			$r1 = $input['custName'];
		    $r2 = $input['buildType'];
			$r3 = $input['pdfName'];
			$r4 = $input['assignedTo'];
			$r5 = $input['status'];
			$r6 = $input['position'];
			
            global $user_id;            
			$status = $r5;
			$order_id = $r6;
			$assignedTo = $r4;

            $db = new DbHandler();
            $response = array();

            $result = $db->updateOrder($user_id, $order_id, $assignedTo, $status);

            if ($result) {
                // order updated successfully
                $response["error"] = false;
                $response["message"] = "order updated successfully";
				$response["order_id"] = $order_id;
				$response["assign"] = $assignedTo;
				$response["status"] = $status;
            } else {
                // order failed to update
                $response["error"] = true;
                $response["message"] = "order failed to update. Please try again!";
				$response["msg1"] = $user_id;
				$response["msg2"] = $order_id;
				$response["msg3"] = $assignedTo;
				$response["msg4"] = $status;
				$response["msg5"] = $test;
            }
            echoResponse(200, $response);
        });

/**
 * Deleting order. Users can delete only their orders
 * method DELETE
 * url /orders
 */
 $app->delete('/orders/:id', 'authenticate', function($id) use($app) {
			global $user_id;
            $db = new DbHandler();
            $response = array();
			if($user_id == 15){
            $result = $db->deleteOrder($user_id, $id);
			}
			else{
				$result = false;
			}
            if ($result) {
                // order deleted successfully
                $response["error"] = false;
                $response["message"] = "order deleted succesfully";
				$response["order_id"] = $id;
            } else {
                // order failed to delete
                $response["error"] = true;
                $response["message"] = "order failed to delete. Please try again!";
            }
            echoResponse(200, $response);
        });

/**
 * Verifying required params posted or not
 */
function verifyRequiredParams($required_fields) {
    $error = false;
    $error_fields = "";
    $request_params = array();
    $request_params = $_REQUEST;
    // Handling PUT request params
    if ($_SERVER['REQUEST_METHOD'] == 'PUT') {
        $app = \Slim\Slim::getInstance();
        parse_str($app->request()->getBody(), $request_params);
    }
    foreach ($required_fields as $field) {
        if (!isset($request_params[$field]) || strlen(trim($request_params[$field])) <= 0) {
            #$error = true;
            $error_fields .= $field . ', ';
        }
    }

    if ($error) {
        // Required field(s) are missing or empty
        // echo error json and stop the app
        $response = array();
        $app = \Slim\Slim::getInstance();
        $response["error"] = true;
        $response["message"] = 'Required field(s) ' . substr($error_fields, 0, -2) . ' is missing or empty';
        echoResponse(400, $response);
        $app->stop();
    }
}

/**
 * Validating email address
 */
function validateEmail($email) {
    $app = \Slim\Slim::getInstance();
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $response["error"] = true;
        $response["message"] = 'Email address is not valid';
        echoResponse(400, $response);
        $app->stop();
    }
}

/**
 * Echoing json response to client
 * @param String $status_code Http response code
 * @param Int $response Json response
 */
function echoResponse($status_code, $response) {
    $app = \Slim\Slim::getInstance();
    // Http response code
    $app->status($status_code);

    // setting response content type to json
    $app->contentType('application/json');
	
    echo json_encode($response);
}

$app->run();
?>