<?php
class LCA{
	private function gcd($a, $b) {
		while ($b != 0) {
			$t = $b;
			$b = $a % $b;
			$a = $t;
		}
		return $a;
	}
	private function modInverse($a, $m) {
		for ($x = 1; $x < $m; $x++) {
			if (($a * $x) % $m == 1) {
				return $x;
			}
		}
		return null;
	}
	private function modExp($base, $exp, $mod) {
		$result = 1;
		$base = $base % $mod;
		while ($exp > 0) {
			if ($exp % 2 == 1) {
				$result = ($result * $base) % $mod;
			}
			$exp = floor($exp / 2);
			$base = ($base * $base) % $mod;
		}
		return $result;
	}
	private function isPrime($num) {
		if ($num <= 1) {
			return false;
		}
		if ($num <= 3) {
			return true;
		}
		if ($num % 2 == 0 || $num % 3 == 0) {
			return false;
		}
		for ($i = 5; $i * $i <= $num; $i += 6) {
			if ($num % $i == 0 || $num % ($i + 2) == 0) {
				return false;
			}
		}
		return true;
	}
	private function generateUniquePrimes($count, $min = 2, $max = 1700) {
		$primes = [];
		if ($count > ($max - $min + 1)) {
			throw new Exception("Cannot generate more unique primes than the range allows.");
		}
		return $primes;
	}
	private function generateRandomExponent($phi, $min = 3, $max = 65537) {
		do {
			$e = random_int($min, $max);
		} while ($this->gcd($e, $phi) !== 1);

		return $e;
	}
	function generateKeys(int $bit_length = 512) : array{
		if($bit_length % 8 != 0){
			throw new Exception("Invalid bit length");
		}
		$length = $bit_length/8;
		$key = [
			'public' => '',
			'private' => ''
		];
		$pass = false;
		$comp = 0;
		while(!$pass){
			while(true){
				$p = random_int(2, 256);
				if($this->isPrime($p))
					break;
			}
			while(true){
				$q = random_int(2, 256);
				if($this->isPrime($q))
					break;
			}
			$n = $p * $q;
			$phi = ($p - 1) * ($q - 1);
			$e = $this->generateRandomExponent($phi);
			$d = $this->modInverse($e, $phi);
			if($this->check_num($d, $e, $n)){
				$comp++;
				$key['public'] .= pack("S",$e);
				$key['public'] .= pack("S",$n);
				$key['private'] .= pack("S",$d);
				$key['private'] .= pack("S",$n);
			}
			if($comp == $length){
				$pass = true;
			}
		}
		return [
			"private" => 
				"-----BEGIN LCA PRIVATE KEY-----\n".
				chunk_split(base64_encode($key['private']), 64, "\n").
				"-----END LCA PRIVATE KEY-----",
			"public" => 
				"-----BEGIN LCA PUBLIC KEY-----\n".
				chunk_split(base64_encode($key['public']), 64, "\n").
				"-----END LCA PUBLIC KEY-----"
		];
	}
	private function check_num($d, $e, $n){
		$pass = 0;
		for($i = 0; $i < 255; $i++){
			$cipher_num = $this->modExp($i, $e, $n);
			$decrypt_num = $this->modExp($cipher_num, $d, $n);
			if($i == $decrypt_num)
				$pass++;
		}
		return ($pass == 255);
	}
	private function parse_key(string $key) : array{
		$rp = ["-----BEGIN LCA PRIVATE KEY-----","-----END LCA PRIVATE KEY-----","-----BEGIN LCA PUBLIC KEY-----","-----END LCA PUBLIC KEY-----","\n","\r"];
		$is_private_key = (strpos($key, $rp[0]) !== false && strpos($key, $rp[1]) !== false);
		$is_public_key = (strpos($key, $rp[2]) !== false && strpos($key, $rp[3]) !== false);
		if($is_private_key || $is_public_key){
			$key = str_replace($rp,'',$key);
			if(base64_encode(base64_decode($key)) != $key){
				throw new Exception("Invalid key base64 format");
			}
			$key = base64_decode($key);
			$magic_number_bytes = str_split($key,4);
			$key = [];
			foreach($magic_number_bytes as $key_numbers){
				$pack_bytes = str_split($key_numbers,2);
				$e = unpack('S',$pack_bytes[0])[1];
				$n = unpack('S',$pack_bytes[1])[1];
				$key[] = [$e,$n];
			}
			return $key;
		}else{
			if(base64_encode(base64_decode($key)) == $key){
				$key = base64_decode($key);
			}
			$magic_number_bytes = str_split($key,4);
			$key = [];
			foreach($magic_number_bytes as $key_numbers){
				$pack_bytes = str_split($key_numbers,2);
				$e = unpack('S',$pack_bytes[0])[1];
				$n = unpack('S',$pack_bytes[1])[1];
				$key[] = [$e,$n];
			}
			return $key;
		}
	}
	public function encrypt(string $plaintext, string $key) : string {
		$key = $this->parse_key($key);
		$keysize = count($key);
		$textsize = strlen($plaintext);
		if($textsize > $keysize){
			throw new Exception("Plaintext is too long for the specified key size");
		}
		$ciphertext = "";
		for($i = 0; $i < $textsize; $i++){
			$e = $key[$i][0];
			$n = $key[$i][1];
			$ciphertext .= pack('I',$this->modExp(ord($plaintext[$i]), $e, $n));
		}
		return $ciphertext;
	}

	public function decrypt(string $ciphertext, string $key) : string {
		if(strlen($ciphertext) % 4 != 0){
			throw new Exception("Invalid ciphertext length");
		}
		$key = $this->parse_key($key);
		$keysize = count($key);
		$textsize = strlen($ciphertext)/4;
		if($textsize > $keysize){
			throw new Exception("Plaintext is too long for the specified key size");
		}
		$plaintextNumeric = "";
		$split = str_split($ciphertext, 4);
		for($i = 0; $i < count($split); $i++){
			$d = $key[$i][0];
			$n = $key[$i][1];
			$plaintextNumeric .= chr($this->modExp(unpack('I',$split[$i])[1], $d, $n));
		}
		return $plaintextNumeric;
	}
}
?>
