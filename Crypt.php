<?php

class Crypt {

	/**
	 * The encryption cipher
	 *
	 * @var string
	 */
	static public $cipher = MCRYPT_RIJNDAEL_256;


	/**
	 * The encryption mode
	 *
	 * @var string
	 */
	static public $mode = MCRYPT_MODE_CBC;


	/**
	 * The block size of the cipher
	 *
	 * @var int
	 */
	static public $block = 24;


	/**
	 * Default hash algorithm
	 *
	 * @var string
	 */
	static public $algo = 'sha256';


	/**
	 * Salt key
	 *
	 * @var string
	 */
	static public $key = '';


	/**
	 * Set salt key
	 *
	 * @param   string  $key
	 */
	static public function key($key = '') {
		if ( ! empty($key) && is_string($key)) {
			self::$key = $key;
		}
	}


	/**
	 * Encrypt a string using the AES-256 scheme and base64 (URL safe) encoded
	 *
	 * @param  string  $value
	 * @param  string  $key
	 * @return string
	 */
	static public function encrypt($value = '', $key = NULL) {
		$iv = mcrypt_create_iv(self::_ivSize(), self::_randomizer());

		$value = self::_pad($value);

		$value = mcrypt_encrypt(self::$cipher, self::_key($key), $value, self::$mode, $iv);

		return self::_b64encodeSafe($iv.$value);
	}


	/**
	 * Decrypt a string
	 *
	 * @param  string  $value
	 * @param  string  $key
	 * @return string
	 */
	static public function decrypt($value = '', $key = NULL) {
		$value = self::_b64decodeSafe($value);

		// Extract the input vector and the encrypted value
		$iv = substr($value, 0, self::_ivSize());

		$value = substr($value, self::_ivSize());

		$key = self::_key($key);

		$value = mcrypt_decrypt(self::$cipher, $key, $value, self::$mode, $iv);

		return self::_unpad($value);
	}


	/**
	 * General hashing of a string
	 *
	 * @param   string  $data
	 * @param   string  $algo
	 * @param   bool    $raw_output
	 * @return  string
	 */
	static public function hash($data = '', $algo = '', $raw_output = false) {
		// Algorithm
		$algo = self::_algo($algo);

		return hash($algo, $data, (bool) $raw_output);
	}


	/**
	 * Determine if an unhashed value matches a hashed value
	 *
	 * @param   string  $data
	 * @param   string  $hash
	 * @param   string  $algo
	 * @return  bool
	 */
	static public function check($data = '', $hash = '', $algo = '') {
		$algo = self::_algo($algo);

		return self::hash($data, $algo) === $hash;
	}


	/**
	 * Get the most secure random number generator for the system
	 *
	 * @return  int
	 */
	static private function _randomizer() {
		if (defined('MCRYPT_DEV_URANDOM')) {
			return MCRYPT_DEV_URANDOM;
		}

		elseif (defined('MCRYPT_DEV_RANDOM')) {
			return MCRYPT_DEV_RANDOM;
		}

		else {
			mt_srand();

			return MCRYPT_RAND;
		}
	}


	/**
	 * Get the input vector size for the cipher and mode
	 *
	 * @return  int
	 */
	static private function _ivSize() {
		return mcrypt_get_iv_size(self::$cipher, self::$mode);
	}


	/**
	 * Add compatible padding on the given value
	 *
	 * @param  string  $value
	 * @return string
	 */
	static private function _pad($value) {
		$block = self::_block();

		$pad = $block - (self::_length($value) % $block);

		$value .= str_repeat(chr($pad), $pad);

		return $value;
	}


	/**
	 * Remove the compatible padding from the given value
	 *
	 * @param   string  $value
	 * @return  string
	 * @throws  Exception
	 */
	static private function _unpad($value = '') {
		$block = self::_block();

		$pad = ord($value[($length = self::_length($value)) - 1]);

		if ($pad and $pad < $block) {
			if (preg_match('/'.chr($pad).'{'.$pad.'}$/', $value)) {
				return substr($value, 0, $length - $pad);
			}

			else {
				throw new Exception('Decryption error. Padding is invalid.');
			}
		}

		return $value;
	}


	/**
	 * Get the encryption key from the application configuration
	 *
	 * @param  string  $key
	 * @return string
	 */
	static private function _key($key = NULL) {
		if ( ! empty($key)) {
			return $key;
		}

		// Common key
		return self::$key;
	}


	/**
	 * Base64 encode and make URL safe
	 *
	 * @param   string  $value
	 * @return  string
	 */
	static private function _b64encodeSafe($value) {
		$data = base64_encode($value);
		$data = str_replace(array('+', '/', '='), array('-', '_', ''), $data);

		return $data;
	}


	/**
	 * Base64 decode URL safe string
	 *
	 * @param   string  $value
	 * @return  string
	 */
	static private function _b64decodeSafe($value) {
		$data = str_replace(array('-', '_'), array('+', '/'), $value);
		$mod4 = strlen($data) % 4;

		if ($mod4) {
			$data .= substr('====', $mod4);
		}

		return base64_decode($data);
	}


	/**
	 * Block size
	 *
	 * @return  int
	 */
	static private function _block() {
		self::$block || self::$block = 24;

		return self::$block;
	}


	/**
	 * Find hash algorithm
	 *
	 * @param   string  $algo
	 * @return  string
	 */
	static private function _algo($algo = '') {
		// Force to lower case and trim it
		$algo = strtolower(trim((string) $algo));

		// Algorithm not specified, use the fallback
		if ( ! $algo) {
			$algo = self::$algo;
		}

		// Algorithm not recognized. Set to a default
		if ( ! in_array($algo, hash_algos())) {
			$algo = 'sha256';
		}

		return $algo;
	}


	/**
	 * Get the length of a string
	 *
	 * @param   string  $value
	 * @param   string  $encoding
	 * @return  int
	 */
	static private function _length($value = '', $encoding = 'UTF-8') {
		return (function_exists('mb_get_info')) ? mb_strlen($value, $encoding) : strlen($value);
	}

}
