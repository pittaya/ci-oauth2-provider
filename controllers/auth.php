<?php  if ( ! defined('BASEPATH')) exit('No direct script access allowed');

class Auth extends CI_Controller {
	function __construct() {
		parent::__construct();
		$this->load->helper('url');
		$this->load->library('oauth_server');
	}
	
	function token() {
		$grant_type = trim($this->input->post('grant_type'));
		$client_id = trim($this->input->post('client_id'));
		$client_secret = trim($this->input->post('client_secret'));

		if ($grant_type == 'password') {			
			if (!$client_id || !$client_secret) {
				$this->_fail(400, 'invalid_grant');
				return;
			}
			
			// check client credentials
			$client = $this->oauth_server->validate_client($client_id, $client_secret);
			if ($client === FALSE) {
				$this->_fail(400, 'unauthorized_client');
				return;
			}
			
			// check user credentials
			$username = trim($this->input->post('username'));
			$password = trim($this->input->post('password'));
			$userid = $this->oauth_server->validate_user($username, $password);
			if ($userid === FALSE) {
				$this->_fail(400, 'invalid_grant');
				return;
			}
			
			// 'scope' is not implemented. All clients have same scope for now.
			// As long as we have only home-grown clients, we don't care.
			
			// seems ok. now generate token for user
			$result = $this->oauth_server->create_access_token($userid, $client_id);
			
			$this->output->set_status_header(200);
			$this->output->set_output(json_encode($result));
		
		} else if ($grant_type == 'refresh_token') {
			// check client credentials
			$client = $this->oauth_server->validate_client($client_id, $client_secret);
			if ($client === FALSE) {
				$this->_fail(400, 'unauthorized_client');
				return;
			}

			$refresh_token = trim($this->input->post('refresh_token'));
			$result = $this->oauth_server->refresh_access_token($refresh_token);
			if ($result === FALSE) {
				$this->_fail(400, 'invalid_request');
				return;
			} else {
				$this->output->set_status_header(200);
				$this->output->set_output(json_encode($result));
			}			
			
		} else {
			$this->_fail(400, 'unsupported_grant_type');
		}
	}
	
	private function _fail($status, $errmsg) {
		$this->output->set_status_header($status);
		$this->output->set_output(json_encode(array(
			'error' => $errmsg
		)));
	}
	
	function test() {
		$user_id = $this->oauth_server->verify_token();
		if ($user_id != FALSE) {
			echo "user id = $user_id\n";
		} else {
			$this->oauth_server->auth_fail();
		} 
	}
}