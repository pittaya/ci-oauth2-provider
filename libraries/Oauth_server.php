<?php  if ( ! defined('BASEPATH')) exit('No direct script access allowed');
class Oauth_server {
	protected $ci;
	protected $token_expire = 604800; // expire in 7 days
	
	public function __construct() {
		$this->ci = get_instance();
	}
	
	private function generate_token() {
		return sha1(uniqid('', TRUE).mt_rand());
	}
	
	public function verify_token() {
		// assume we use apache
		$raw_headers = apache_request_headers();
		// also verify from POST data
		$token = $this->ci->input->post('access_token');
		
		if (array_key_exists('Authorization', $raw_headers)) {
			$bearer = explode(' ', $raw_headers['Authorization']);
			if (sizeof($bearer) == 2) {
				$token = $bearer[1];
			}
		}
		
		if (!$token) {
			return FALSE;
		}
		
		$q = $this->ci->db->select(array('user_id', 'expires_in'))->get_where('oauth_tokens', array('access_token' => $token));
		if ($q->num_rows === 1) {
			$row = $q->row();
			if (strtotime($row->expires_in) > time()) {
				return $row->user_id;
			}
		}
		return FALSE;
	}
	
	public function auth_fail() {
		$res['WWW-Authenticate'] = 'Bearer realm="PlayBlog REST API"';
		$this->ci->output->set_status_header(403);
		$this->ci->output->set_header('WWW-Authenticate: Bearer realm="PlayBlog REST API"');
		$this->ci->output->set_output(json_encode(array('error' => 'invalid_token')));		
	}
	
	public function create_access_token($user_id, $client_id) {
		$access_token = $this->generate_token();
		$refresh_token = $this->generate_token();
		
		// remove old expired tokens
		$this->ci->db->query("DELETE FROM oauth_tokens WHERE user_id=? AND expires_in < ?", array($user_id, time()));
		
		// store token in database
		$expires_in = time() + $this->token_expire;
		$this->ci->db->insert('oauth_tokens', array(
			'client_id' => $client_id,
			'token_type' => 'Bearer',
			'user_id' => $user_id,
			'access_token' => $access_token,
			'refresh_token' => $refresh_token,
			'expires_in' => date('c', $expires_in)
		));
		
		return array(
			'token_type' => 'Bearer',
			'access_token' => $access_token,
			'refresh_token' => $refresh_token,
			'expires_in' => $expires_in
		);
	}
	
	public function refresh_access_token($token) {
		$params = array(
			'refresh_token' => $token
		);
		$q = $this->ci->db->select(array('user_id', 'client_id', 'expires_in'))->get_where('oauth_tokens', $params);
		if ($q->num_rows() === 1) {
			$row = $q->row();
			if (strtotime($row->expires_in) < time()) {
				// cannot refresh expired token. delete this
				$this->ci->db->delete('oauth_tokens', array('refresh_token' => $token));
				return FALSE;
			} else {
				// remove this token and generate new one
				$this->ci->db->delete('oauth_tokens', array('refresh_token' => $token));
				return $this->create_access_token($row->user_id, $row->client_id);
			}
		}
		return FALSE;
	}
	
	public function validate_client($client_id, $client_secret) {
		$params = array(
			'client_id' => $client_id,
			'client_secret' => $client_secret
		);
		$q = $this->ci->db->select(array('title', 'client_id'))->get_where('oauth_clients', $params);
		if ($q->num_rows() === 1) {
			return $q->row();
		} else {
			return FALSE;
		}
	}
	
	// TODO - implement this
	public function validate_user($username, $password) {
		if ($username == 'foo' && $password == 'bar') {
			return '100';
		}
		return false;
	}
}
