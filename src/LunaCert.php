<?php
class LUNACert{
	public static $VERSION						= 1;
	// Extended Key Usage
	public static $EKU_ServerAuthentication		= 1;
	public static $EKU_ClientAuthentication		= 2;
	public static $EKU_CodeSigning				= 8;
	public static $EKU_EmailProtection			= 16;
	public static $EKU_TimeStamping				= 32;
	public static $EKU_OCSPSigning				= 64;
	public static $EKU_DocumentSigning			= 128;
	public static $EKU_EmailSigning				= 256;
	// Key type
	public static $KEY_TYPE_LCA					= 1;

	// SignatureAlgorithm
	// LCA
	public static $SA_LCA						=
	[
		"sha1WithLCAEncryption",
		"sha224WithLCAEncryption",
		"sha256WithLCAEncryption",
		"sha384WithLCAEncryption",
		"sha512WithLCAEncryption",
		"md5WithLCAEncryption"
	];
	public function __construct(){
		require_once __DIR__ . "/LCA.php";
		$this->LCA = new LCA();
		$this->EKU = 
		[
			"ServerAuthentication"	=> 1,
			"ClientAuthentication"	=> 2,
			"CodeSigning"			=> 8,
			"EmailProtection"		=> 16,
			"TimeStamping"			=> 32,
			"OCSPSigning"			=> 64,
			"DocumentSigning"		=> 128,
			"EmailSigning"			=> 256
			// "?" => 512,
			// "?" => 1024,
			// "?" => 2048,
			// "?" => 4096,
			// "?" => 8192,
			// "?" => 16384
		];
		$this->CP = 
		[
			1	=> "OV", // Organization Validated
			2	=> "EV", // Extended Validation
			3	=> "DV"  // Domain Validated
		];
		$this->KA = 
		[
			1	=> "LCA", // LCA (Luna Crypto Algorithm)
		];
		$this->SignatureAlgorithm = 
		[
			// LCA
			"sha1WithLCAEncryption"			=> "\xca\xc1",
			"sha224WithLCAEncryption"		=> "\xca\xc2",
			"sha256WithLCAEncryption"		=> "\xca\xc3",
			"sha384WithLCAEncryption"		=> "\xca\xc4",
			"sha512WithLCAEncryption"		=> "\xca\xc5",
			"md5WithLCAEncryption"			=> "\xca\xc6"
		];
	}
	public function sign_certificate(
		array $Subject = [
			"CN" => "",
			"O"  => "",
			"OU" => "",
			"L"  => "",
			"ST" => "",
			"C"  => "",
			"E"  => ""
		],
		int $Validity = 2592000,
		array $Extensions = [
			"SAN"  => [],
			"EKU"  => 0,
			"BA"   => [
				"CA" => false,
				"PathLength" => 1
			],
			"CP"   => [
				"policy" => 0,
				"policy_url" => "https://minosuko.id.vn/policy"
			],
			"AIA"   => [
				"ocsp" => "https://ocsp.minosuko.id.vn/",
				"ca_issuers" => "https://minosuko.id.vn/ca_cert.pem"
			]
		],
		string $SignatureAlgorithm,
		array $Key,
		array $CA = null
	) {
		// Validate Signature Algorithm
		$SA = $this->SignatureAlgorithm;
		if (!isset($SA[$SignatureAlgorithm])) {
			$this->exc_error("Unknown Signature Algorithm");
		}
	
		// Validate Key
		if (!isset($Key["PRIVATE_KEY"]) || !isset($Key["PUBLIC_KEY"]) || !isset($Key["KEY_TYPE"])) {
			$this->exc_error("PublicKey PRIVATE/PUBLIC_KEY and/or KEY_TYPE must not be empty");
		}
		if (!isset($this->KA[$Key["KEY_TYPE"]])) {
			$this->exc_error("Unknown KEY_TYPE.");
		}
	
		// Validate Subject
		if (empty($Subject["CN"])) {
			$this->exc_error("Common Name must not be empty");
		}
	
		// Prepare Subject Fields
		$CN = $Subject["CN"];
		$O = $Subject["O"] ?? '';
		$OU = $Subject["OU"] ?? '';
		$L = $Subject["L"] ?? '';
		$ST = $Subject["ST"] ?? '';
		$C = $Subject["C"] ?? '';
		$E = $Subject["E"] ?? '';
	
		// Prepare Subject Alternative Names
		$SAN = '';
		if (isset($Extensions["SAN"]) && is_array($Extensions["SAN"])) {
			foreach ($Extensions["SAN"] as $SANe) {
				if (!is_string($SANe) || strlen($SANe) > 255) {
					$this->exc_error("Subject Alternative Name must be an array of strings, each not longer than 255 characters");
				}
				$SAN .= chr(strlen($SANe)) . $SANe;
			}
			$SANc = count($Extensions["SAN"]);
		} else {
			$SANc = 0;
		}
	
		// Generate Serial Number and Dates
		$serial = random_bytes(16);
		$date = time();
		$NotBefore = date("d/m/Y H:i:s", $date);
		$NotAfter = date("d/m/Y H:i:s", $date + $Validity);
		$VERSION = self::$VERSION;
	
		// Prepare Issuer Information
		if ($CA == null) {
			$I_CN = $CN;
			$I_O = $O;
			$I_OU = $OU;
			$I_L = $L;
			$I_ST = $ST;
			$I_C = $C;
			$I_E = $E;
		} else {
			$parse_cert = $this->parse_certificate($CA['certificate']);
			$I_CN = $parse_cert['subject']['CN'];
			$I_O = $parse_cert['subject']['O'];
			$I_OU = $parse_cert['subject']['OU'];
			$I_L = $parse_cert['subject']['L'];
			$I_ST = $parse_cert['subject']['ST'];
			$I_C = $parse_cert['subject']['C'];
			$I_E = $parse_cert['subject']['E'];
		}
	
		// Build Certificate Body
		$bin = '';
		$bin .= $serial;
		$bin .= $SA[$SignatureAlgorithm];
		$bin .= "\x10"; // Issuer bit identifier
		$bin .= pack('i', 21 + strlen($I_CN) + strlen($I_O) + strlen($I_OU) + strlen($I_L) + strlen($I_ST) + strlen($I_C) + strlen($I_E));
		$bin .= "\xf1" . pack('S', strlen($I_CN)) . $I_CN;    $bin .= "\xf2" . pack('S', strlen($I_O)) . $I_O;
		$bin .= "\xf3" . pack('S', strlen($I_OU)) . $I_OU;
		$bin .= "\xf4" . pack('S', strlen($I_L)) . $I_L;
		$bin .= "\xf5" . pack('S', strlen($I_ST)) . $I_ST;
		$bin .= "\xf6" . pack('S', strlen($I_C)) . $I_C;
		$bin .= "\xf7" . pack('S', strlen($I_E)) . $I_E;
	
		// Add validity dates
		$bin .= "\x20"; // Date bit identifier
		$bin .= chr(strlen($NotBefore)) . $NotBefore;
		$bin .= chr(strlen($NotAfter)) . $NotAfter;
	
		// Prepare Subject Information
		$bin .= "\x30"; // Subject bit identifier
		$bin .= pack('i', 23 + strlen($CN) + strlen($O) + strlen($OU) + strlen($L) + strlen($ST) + strlen($C) + strlen($E));
		$bin .= "\xf1" . pack('S', strlen($CN)) . $CN;
		$bin .= "\xf2" . pack('S', strlen($O)) . $O;
		$bin .= "\xf3" . pack('S', strlen($OU)) . $OU;
		$bin .= "\xf4" . pack('S', strlen($L)) . $L;
		$bin .= "\xf5" . pack('S', strlen($ST)) . $ST;
		$bin .= "\xf6" . pack('S', strlen($C)) . $C;
		$bin .= "\xf7" . pack('S', strlen($E)) . $E;
	
		// Add Public Key
		$parse_key = $this->parse_key($Key["PUBLIC_KEY"]);
		$bin .= "\x40"; // Public key bit identifier
		$bin .= chr($Key["KEY_TYPE"]); // Public key type bit identifier
		$bin .= pack('i', strlen($parse_key)); // Public key length
		$bin .= $parse_key;
	
		// Add Extensions
		$bin .= "\x50"; // Extensions bit identifier
		$bin .= "\x51"; // Extensions Key Identifier
		$bin .= "\x5a" . hash('sha256', $parse_key, true); // Subject Key Identifier
		$bin .= "\x5b"; // Authority Key Identifier
		$bin .= ($CA == null) ? hash('sha256', $parse_key, true) : hash('sha256', $parse_cert['publickey'], true);
	
		// Add Subject Alternative Name
		if (isset($SAN)) {
			$bin .= "\x52" . chr($SANc) . $SAN;
		}
	
		// Add Extended Key Usage
		if (isset($Extensions["EKU"])) {
			$bin .= "\x53" . pack('S', $Extensions["EKU"]);
		}
	
		// Add Basic Constraints
		if (isset($Extensions["BA"])) {
			$bin .= "\x54";
			if (isset($Extensions["BA"]["CA"])) {
				$bin .= "\x5a" . ($Extensions["BA"]["CA"] ? "\x1" : "\x0");
			}
			if (isset($Extensions["BA"]["PathLength"])) {
				$bin .= "\x5b" . chr($Extensions["BA"]["PathLength"]);
			}
		}
	
		// Add Certificate Policy
		if (isset($Extensions["CP"])) {
			$bin .= "\x55";
			if (isset($Extensions["CP"]["policy"])) {
				$bin .= "\x5a" . chr($Extensions["CP"]["policy"]);
			}
			if (isset($Extensions["CP"]["policy_url"])) {
				$bin .= "\x5b" . chr(strlen($Extensions["CP"]["policy_url"])) . $Extensions["CP"]["policy_url"];
			}
		}
	
		// Add Authority Information Access
		if (isset($Extensions["AIA"])) {
			$bin .= "\x56";
			if (isset($Extensions["AIA"]["ocsp"])) {
				$bin .= "\x5a" . chr(strlen($Extensions["AIA"]["ocsp"])) . $Extensions["AIA"]["ocsp"];
			}
			if (isset($Extensions["AIA"]["ca_issuers"])) {
				$bin .= "\x5b" . chr(strlen($Extensions["AIA"]["ca_issuers"])) . $Extensions["AIA"]["ca_issuers"];
			}
		}
	
		// Add Signature
		$bin .= "\x60"; // Signature bit identifier
		$bin .= $SA[$SignatureAlgorithm];
	
		// Prepare data to sign
		$issuer_data = "CN=$I_CN;O=$I_O;OU=$I_OU;L=$I_L;ST=$I_ST;C=$I_C;E=$I_E";
		$subject_data = "CN=$CN;O=$O;OU=$OU;L=$L;ST=$ST;C=$C;E=$E";
		$dataToSign = $VERSION .
					  $serial .
					  $SignatureAlgorithm .
					  pack('i', strlen($issuer_data)) . $issuer_data .
					  pack('i', strlen($subject_data)) . $subject_data .
					  chr(strlen($NotBefore)) . $NotBefore .
					  chr(strlen($NotAfter)) . $NotAfter .
					  chr($Key["KEY_TYPE"]) .
					  pack('i', strlen($parse_key)) . $parse_key;
	
		// Add Extensions to the data to sign
		if (isset($SAN)) {
			$dataToSign .= "\x52" . chr($SANc) . $SAN;
		}
		if (isset($Extensions["EKU"])) {
			$dataToSign .= "\x53" . pack('S', $Extensions["EKU"]);
		}
		if (isset($Extensions["BA"])) {
			$dataToSign .= "\x54";
			if (isset($Extensions["BA"]["CA"])) {
				$dataToSign .= "\x5a" . ($Extensions["BA"]["CA"] ? "\x1" : "\x0");
			}
			if (isset($Extensions["BA"]["PathLength"])) {
				$dataToSign .= "\x5b" . chr($Extensions["BA"]["PathLength"]);
			}
		}
		if (isset($Extensions["CP"])) {
			$dataToSign .= "\x55";
			if (isset($Extensions["CP"]["policy"])) {
				$dataToSign .= "\x5a" . chr($Extensions["CP"]["policy"]);
			}
			if (isset($Extensions["CP"]["policy_url"])) {
				$dataToSign .= "\x5b" . chr(strlen($Extensions["CP"]["policy_url"])) . $Extensions["CP"]["policy_url"];
			}
		}
		if (isset($Extensions["AIA"])) {
			$dataToSign .= "\x56";
			if (isset($Extensions["AIA"]["ocsp"])) {
				$dataToSign .= "\x5a" . chr(strlen($Extensions["AIA"]["ocsp"])) . $Extensions["AIA"]["ocsp"];
			}
			if (isset($Extensions["AIA"]["ca_issuers"])) {
				$dataToSign .= "\x5b" . chr(strlen($Extensions["AIA"]["ca_issuers"])) . $Extensions["AIA"]["ca_issuers"];
			}
		}
	
		// Sign the data
		$sign_data = $this->sign($dataToSign, $Key["PRIVATE_KEY"], $SignatureAlgorithm);
		$bin .= pack('s',strlen($sign_data)) . $sign_data;
		if ($CA != null) {
			if (!isset($CA['private_key'])) {
				$this->exc_error("Empty private key");
			}
			$sign_data = $this->sign($dataToSign, $CA['private_key'], $SignatureAlgorithm);
			$bin .= pack('s',strlen($sign_data)) . $sign_data;
		}
	
		// Finalize the certificate
		$base_cert = chr($VERSION) . pack('i', strlen($bin)) . $bin;
		$fingerprint = sha1($base_cert, true);
		$signed_cert = "-----BEGIN LCA CERTIFICATE-----\n" .
					   chunk_split(base64_encode($base_cert . $fingerprint), 64, "\n") .
					   "-----END LCA CERTIFICATE-----";
	
		return $signed_cert;
	}
	public function parse_certificate(string $certificate): array {
		// Clean up PEM format
		$certificate = str_replace(["-----BEGIN LCA CERTIFICATE-----", "-----END LCA CERTIFICATE-----", "\r", "\n"], '', $certificate);
		$decoded = base64_decode($certificate, true);
	
		if ($decoded === false || strlen($decoded) < 21) {
			$this->exc_error("Invalid certificate format");
		}
	
		// Extract fingerprint
		$fingerprint = substr($decoded, -20); // SHA-1 is 20 bytes
		$data = substr($decoded, 0, -20);
	
		// Extract version and binary length
		$offset = 0;
		$version = ord($data[$offset]);
		$offset += 1;
	
		$binLength = unpack('i', substr($data, $offset, 4))[1];
		$offset += 4;
	
		// Sanity check
		if ($binLength !== strlen($data) - 5) {
			$this->exc_error("Invalid certificate length");
		}
	
		// Serial number (16 bytes)
		$serial = bin2hex(substr($data, $offset, 16));
		$offset += 16;
	
		// Signature Algorithm (assumed to be 2 bytes like in sign_certificate)
		$sigAlg = bin2hex(substr($data, $offset, 2));
		$offset += 2;
	
		// Issuer
		if (ord($data[$offset]) !== 0x10) {
			$this->exc_error("Invalid Issuer section");
		}
		$offset += 1;
	
		$issuerLen = unpack('i', substr($data, $offset, 4))[1];
		$offset += 4;
	
		$issuer = [];
		for ($i = 0; $i < 7; $i++) {
			$type = ord($data[$offset]);
			$offset += 1;
			$len = unpack('S', substr($data, $offset, 2))[1];
			$offset += 2;
			$value = substr($data, $offset, $len);
			$offset += $len;
			$key = match($type) {
				0xf1 => "CN",
				0xf2 => "O",
				0xf3 => "OU",
				0xf4 => "L",
				0xf5 => "ST",
				0xf6 => "C",
				0xf7 => "E",
				default => "UNKNOWN"
			};
			$issuer[$key] = $value;
		}
		// Validity
		if (ord($data[$offset]) !== 0x20) {
			$this->exc_error("Invalid Validity section");
		}
		$offset += 1;
	
		$notBeforeLen = ord($data[$offset]);
		$offset += 1;
		$notBefore = substr($data, $offset, $notBeforeLen);
		$offset += $notBeforeLen;
	
		$notAfterLen = ord($data[$offset]);
		$offset += 1;
		$notAfter = substr($data, $offset, $notAfterLen);
		$offset += $notAfterLen;
	
		// Subject
		if (ord($data[$offset]) !== 0x30) {
			$this->exc_error("Invalid Subject section");
		}
		$offset += 1;
	
		$subjectLen = unpack('i', substr($data, $offset, 4))[1];
		$offset += 4;
	
		$subject = [];
		for ($i = 0; $i < 7; $i++) {
			$type = ord($data[$offset]);
			$offset += 1;
			$len = unpack('S', substr($data, $offset, 2))[1];
			$offset += 2;
			$value = substr($data, $offset, $len);
			$offset += $len;
			$key = match($type) {
				0xf1 => "CN",
				0xf2 => "O",
				0xf3 => "OU",
				0xf4 => "L",
				0xf5 => "ST",
				0xf6 => "C",
				0xf7 => "E",
				default => "UNKNOWN"
			};
			$subject[$key] = $value;
		}
		// Public Key
		if (ord($data[$offset]) !== 0x40) {
			$this->exc_error("Invalid Public Key section");
		}
		$offset += 1;
	
		$keyType = ord($data[$offset]);
		$offset += 1;
	
		$keyLen = unpack('i', substr($data, $offset, 4))[1];
		$offset += 4;
	
		$publicKey = substr($data, $offset, $keyLen);
		$offset += $keyLen;
	
		// Extensions
		$extensions = [];
		while ($offset < strlen($data) && ord($data[$offset]) !== 0x60) {
			$extType = ord($data[$offset]);
			$offset += 1;
	
			switch ($extType) {
				case 0x51: // Extensions Key Identifier
					break;
				case 0x5a:
					$extensions['subject_key_identifier'] = bin2hex(substr($data, $offset, 32));
					$offset += 32;
					break;
				case 0x5b:
					$extensions['authority_key_identifier'] = bin2hex(substr($data, $offset, 32));
					$offset += 32;
					break;
				case 0x52:
					$sanCount = ord($data[$offset++]);
					$san = [];
					for ($i = 0; $i < $sanCount; $i++) {
						$len = ord($data[$offset++]);
						$san[] = substr($data, $offset, $len);
						$offset += $len;
					}
					$extensions['SAN'] = $san;
					break;
				case 0x53:
					$eku = unpack('S', substr($data, $offset, 2))[1];
					$offset += 2;
					$extensions['EKU'] = [];
					if(($eku & self::$EKU_ServerAuthentication) != 0)	$extensions['EKU'][] = "ServerAuthentication";
					if(($eku & self::$EKU_ClientAuthentication) != 0)	$extensions['EKU'][] = "ClientAuthentication";
					if(($eku & self::$EKU_CodeSigning)			!= 0)	$extensions['EKU'][] = "CodeSigning";
					if(($eku & self::$EKU_EmailProtection)		!= 0)	$extensions['EKU'][] = "EmailProtection";
					if(($eku & self::$EKU_TimeStamping)			!= 0)	$extensions['EKU'][] = "TimeStamping";
					if(($eku & self::$EKU_OCSPSigning)			!= 0)	$extensions['EKU'][] = "OCSPSigning";
					if(($eku & self::$EKU_DocumentSigning)		!= 0)	$extensions['EKU'][] = "DocumentSigning";
					if(($eku & self::$EKU_EmailSigning) 		!= 0)	$extensions['EKU'][] = "EmailSigning";
					break;
				case 0x54:
					$ba = [];
					if (ord($data[$offset]) === 0x5a) {
						$offset++;
						$ba['CA'] = ord($data[$offset++]) === 1;
					}
					if (ord($data[$offset]) === 0x5b) {
						$offset++;
						$ba['PathLength'] = ord($data[$offset++]);
					}
					$extensions['BA'] = $ba;
					break;
				case 0x55:
					$cp = [];
					if (ord($data[$offset]) === 0x5a) {
						$offset++;
						$cp['policy'] = ord($data[$offset++]);
					}
					if (ord($data[$offset]) === 0x5b) {
						$offset++;
						$len = ord($data[$offset++]);
						$cp['policy_url'] = substr($data, $offset, $len);
						$offset += $len;
					}
					$extensions['CP'] = $cp;
					break;
				case 0x56:
					$aia = [];
					if (ord($data[$offset]) === 0x5a) {
						$offset++;
						$len = ord($data[$offset++]);
						$aia['ocsp'] = substr($data, $offset, $len);
						$offset += $len;
					}
					if (ord($data[$offset]) === 0x5b) {
						$offset++;
						$len = ord($data[$offset++]);
						$aia['ca_issuers'] = substr($data, $offset, $len);
						$offset += $len;
					}
					$extensions['AIA'] = $aia;
					break;
			}
		}
	
		// Signature
		if (ord($data[$offset]) !== 0x60) {
			$this->exc_error("Missing signature section");
		}
		$offset += 1;
	
		$sigAlgFinal = array_search(substr($data, $offset, 2), $this->SignatureAlgorithm);
		$offset += 2;
	
		$signatureData = substr($data, $offset);
		$sdl = strlen($signatureData);
		$signLength = unpack('s',$signatureData[0].$signatureData[1])[1];
		$signature = [];
		$signature["signature"] = bin2hex(substr($signatureData,2,$signLength));
		if((strlen($signatureData)-2) > $signLength){
			$signature["CA_signature"] = bin2hex(
				substr($signatureData,
				($signLength+4),
				unpack('s',$signatureData[$signLength+2].$signatureData[$signLength+3])[1])
			);
		}
		return [
			'version'      => $version,
			'serial'       => $serial,
			'signature_algorithm' => $sigAlgFinal,
			'subject'      => $subject,
			'issuer'       => $issuer,
			'valid_from'   => $notBefore,
			'valid_to'     => $notAfter,
			'publickey'    => bin2hex($publicKey),
			'key_type'     => $keyType,
			'extensions'   => $extensions,
			'signature'    => $signature,
			'fingerprint'  => bin2hex($fingerprint),
		];
	}
	public function verify_signature(string $certificate) : array
	{
		// Remove PEM header/footer and decode base64
		$cert = preg_replace('/-----BEGIN LCA CERTIFICATE-----|-----END LCA CERTIFICATE-----|\s+/', '', $certificate);
		$cert_bin = base64_decode($cert);

		if ($cert_bin === false || strlen($cert_bin) < 21) {
			return ["valid" => false, "message" => "Invalid certificate format or too short"];
		}

		// Extract version
		$version = ord($cert_bin[0]);
		$offset = 1;

		// Extract body length
		$body_len = unpack('i', substr($cert_bin, $offset, 4))[1];
		$offset += 4;

		// Get body
		$body = substr($cert_bin, $offset, $body_len);
		$offset += $body_len;

		// Get fingerprint
		$fingerprint = substr($cert_bin, $offset, 20);
		if ($fingerprint !== sha1(chr($version) . pack('i', $body_len) . $body, true)) {
			return ["valid" => false, "message" => "Fingerprint mismatch. Certificate might be tampered."];
		}

		// Parse the body to get required sections
		$parsed = $this->parse_certificate("-----BEGIN LCA CERTIFICATE-----\n" . chunk_split(base64_encode(chr($version) . pack('i', $body_len) . $body . $fingerprint), 64, "\n") . "-----END LCA CERTIFICATE-----");

		$SignatureAlgorithm = $parsed['signature_algorithm'];
		$PublicKey = hex2bin($parsed['publickey']);
		$KEY_TYPE = $parsed['key_type'];
		$Signature = hex2bin($parsed['signature']['signature']);

		// Validate algorithm and key type
		if (!isset($this->SignatureAlgorithm[$SignatureAlgorithm])) {
			return ["valid" => false, "message" => "Unknown signature algorithm."];
		}

		if (!isset($this->KA[$KEY_TYPE])) {
			return ["valid" => false, "message" => "Unknown key type."];
		}

		// Reconstruct data that was originally signed
		$issuer_data = "CN={$parsed['issuer']['CN']};O={$parsed['issuer']['O']};OU={$parsed['issuer']['OU']};L={$parsed['issuer']['L']};ST={$parsed['issuer']['ST']};C={$parsed['issuer']['C']};E={$parsed['issuer']['E']}";
		$subject_data = "CN={$parsed['subject']['CN']};O={$parsed['subject']['O']};OU={$parsed['subject']['OU']};L={$parsed['subject']['L']};ST={$parsed['subject']['ST']};C={$parsed['subject']['C']};E={$parsed['subject']['E']}";

		$dataToSign = $version .
					hex2bin($parsed['serial']) .
					$SignatureAlgorithm .
					pack('i', strlen($issuer_data)) . $issuer_data .
					pack('i', strlen($subject_data)) . $subject_data .
					chr(strlen($parsed['valid_from'])) . $parsed['valid_from'] .
					chr(strlen($parsed['valid_to'])) . $parsed['valid_to'] .
					chr($KEY_TYPE) .
					pack('i', strlen($PublicKey)) . $PublicKey;

		// Add extensions in order if they exist
		if (isset($parsed['extensions'])) {
			$ext = $parsed['extensions'];

			if (isset($ext['SAN'])) {
				$dataToSign .= "\x52" . chr(count($ext['SAN'])) . implode('', array_map(function ($e) {
					return chr(strlen($e)) . $e;
				}, $ext['SAN']));
			}

			if (isset($ext['EKU'])) {
				$eku = 0;
				if(in_array("ServerAuthentication",$ext['EKU']))	$eku += self::$EKU_ServerAuthentication;
				if(in_array("ClientAuthentication",$ext['EKU']))	$eku += self::$EKU_ClientAuthentication;
				if(in_array("CodeSigning",$ext['EKU']))				$eku += self::$EKU_CodeSigning;
				if(in_array("EmailProtection",$ext['EKU']))			$eku += self::$EKU_EmailProtection;
				if(in_array("TimeStamping",$ext['EKU']))			$eku += self::$EKU_TimeStamping;
				if(in_array("OCSPSigning",$ext['EKU']))				$eku += self::$EKU_OCSPSigning;
				if(in_array("DocumentSigning",$ext['EKU']))			$eku += self::$EKU_DocumentSigning;
				if(in_array("EmailSigning",$ext['EKU']))			$eku += self::$EKU_EmailSigning;
				$dataToSign .= "\x53" . pack('S', $eku);
			}

			if (isset($ext['BA'])) {
				$dataToSign .= "\x54";
				if(isset($ext['BA']['CA']))
					$dataToSign .= "\x5a" . ($ext['BA']['CA'] ? "\x1" : "\x0");
				if(isset($ext['BA']['PathLength']))
					$dataToSign .= "\x5b" . chr($ext['BA']['PathLength']);
			}

			if (isset($ext['CP'])) {
				$dataToSign .= "\x55";
				if(isset($ext['CP']['policy']))
					$dataToSign .= "\x5a" . chr($ext['CP']['policy']);
				if(isset($ext['CP']['policy_url']))
					$dataToSign .= "\x5b" . chr(strlen($ext['CP']['policy_url'])) . $ext['CP']['policy_url'];
			}

			if (isset($ext['AIA'])) {
				$dataToSign .= "\x56";
				if(isset($ext['AIA']['ocsp']))
					$dataToSign .= "\x5a" . chr(strlen($ext['AIA']['ocsp'])) . $ext['AIA']['ocsp'];
				if(isset($ext['AIA']['ca_issuers']))
					$dataToSign .= "\x5b" . chr(strlen($ext['AIA']['ca_issuers'])) . $ext['AIA']['ca_issuers'];
			}
		}

		// Now verify the signature
		$verify = $this->verify($dataToSign, $Signature, $PublicKey, $SignatureAlgorithm);
		if (!$verify) {
			return ["valid" => false, "message" => "Signature verification failed."];
		}

		return ["valid" => true, "message" => "Valid Certificate"];
	}
	public function verify_chain(array $cert_chain)
	{
		if (count($cert_chain) < 1) {
			$this->exc_error("Empty certificate chain");
		}

		$parsed_chain = [];
		foreach ($cert_chain as $cert) {
			$parsed = $this->parse_certificate($cert);
			if (!$parsed) {
				$this->exc_error("Failed to parse one of the certificates");
			}
			$parsed_chain[] = $parsed;
		}

		$chain_length = count($parsed_chain);

		for ($i = 0; $i < $chain_length - 1; $i++) {
			$child = $parsed_chain[$i];
			$parent = $parsed_chain[$i + 1];

			// Check issuer == parent subject
			if ($child['issuer'] !== $parent['subject']) {
				return ["valid" => false, "message" => "Issuer and Subject mismatch between cert #$i and cert #" . ($i + 1)];
			}

			// Inline build of dataToSign
			$version = $child['version'];
			$serial = hex2bin($child['serial']);
			$SignatureAlgorithm = $child['signature_algorithm'];
			$issuer_data = "CN={$child['issuer']['CN']};O={$child['issuer']['O']};OU={$child['issuer']['OU']};L={$child['issuer']['L']};ST={$child['issuer']['ST']};C={$child['issuer']['C']};E={$child['issuer']['E']}";
			$subject_data = "CN={$child['subject']['CN']};O={$child['subject']['O']};OU={$child['subject']['OU']};L={$child['subject']['L']};ST={$child['subject']['ST']};C={$child['subject']['C']};E={$child['subject']['E']}";
			$valid_from = $child['valid_from'];
			$valid_to = $child['valid_to'];
			$KEY_TYPE = $child['key_type'];
			$PublicKey = hex2bin($child['publickey']);

			$dataToSign = $version .
						$serial .
						$SignatureAlgorithm .
						pack('i', strlen($issuer_data)) . $issuer_data .
						pack('i', strlen($subject_data)) . $subject_data .
						chr(strlen($valid_from)) . $valid_from .
						chr(strlen($valid_to)) . $valid_to .
						chr($KEY_TYPE) .
						pack('i', strlen($PublicKey)) . $PublicKey;
			
			// Re-append extensions if any
			if (isset($child['extensions']['SAN'])) {
				$san_bin = '';
				foreach ($child['extensions']['SAN'] as $san) {
					$san_bin .= chr(strlen($san)) . $san;
				}
				$dataToSign .= "\x52" . chr(count($child['extensions']['SAN'])) . $san_bin;
			}
			
			if (isset($child['extensions']['EKU'])) {
				$eku = 0;
				if(in_array("ServerAuthentication",$child['extensions']['EKU']))	$eku += self::$EKU_ServerAuthentication;
				if(in_array("ClientAuthentication",$child['extensions']['EKU']))	$eku += self::$EKU_ClientAuthentication;
				if(in_array("CodeSigning",$child['extensions']['EKU']))			$eku += self::$EKU_CodeSigning;
				if(in_array("EmailProtection",$child['extensions']['EKU']))		$eku += self::$EKU_EmailProtection;
				if(in_array("TimeStamping",$child['extensions']['EKU']))			$eku += self::$EKU_TimeStamping;
				if(in_array("OCSPSigning",$child['extensions']['EKU']))			$eku += self::$EKU_OCSPSigning;
				if(in_array("DocumentSigning",$child['extensions']['EKU']))		$eku += self::$EKU_DocumentSigning;
				if(in_array("EmailSigning",$child['extensions']['EKU']))			$eku += self::$EKU_EmailSigning;
				$dataToSign .= "\x53" . pack('S', $eku);
			}

			if (isset($child['extensions']['BA'])) {
				$dataToSign .= "\x54";
				if (isset($child['extensions']['BA']['CA'])) {
					$dataToSign .= "\x5a" . ($child['extensions']['BA']['CA'] ? "\x1" : "\x0");
				}
				if (isset($child['extensions']['BA']['PathLength'])) {
					$CApathLength = $child['extensions']['BA']['PathLength'];
					$dataToSign .= "\x5b" . chr($CApathLength);
				}
			}

			if (isset($child['extensions']['CP'])) {
				$dataToSign .= "\x55";
				if (isset($child['extensions']['CP']['policy'])) {
					$dataToSign .= "\x5a" . chr($child['extensions']['CP']['policy']);
				}
				if (isset($child['extensions']['CP']['policy_url'])) {
					$dataToSign .= "\x5b" . chr(strlen($child['extensions']['CP']['policy_url'])) . $child['extensions']['CP']['policy_url'];
				}
			}

			if (isset($child['extensions']['AIA'])) {
				$dataToSign .= "\x56";
				if (isset($child['extensions']['AIA']['ocsp'])) {
					$dataToSign .= "\x5a" . chr(strlen($child['extensions']['AIA']['ocsp'])) . $child['extensions']['AIA']['ocsp'];
				}
				if (isset($child['extensions']['AIA']['ca_issuers'])) {
					$dataToSign .= "\x5b" . chr(strlen($child['extensions']['AIA']['ca_issuers'])) . $child['extensions']['AIA']['ca_issuers'];
				}
			}
			// Verify child signature using child public key
			if (!$this->verify($dataToSign, hex2bin($child['signature']['signature']), $PublicKey, $SignatureAlgorithm)) {
				return ["valid" => false, "Signature verification failed at cert #$i (invalid certificate signature)"];
			}

			// Verify child signature using parent public key
			if(isset($child['signature']['CA_signature'])){
				if (!$this->verify($dataToSign, hex2bin($child['signature']['CA_signature']), hex2bin($parent['publickey']), $SignatureAlgorithm)) {
					return ["valid" => false, "Signature verification failed at cert #$i (invalid certificate parent signature)"];
				}
			}
			// Verify Path Length
			if(isset($CApathLength)){
				if(($chain_length-($i+1)) > $CApathLength){
					return ["valid" => false, "Chain is longer than CA allowed length at cert #$i"];
				}
				unset($CApathLength);
			}
		}

		// Verify root (last cert in chain)
		$root = end($parsed_chain);
		if ($root['issuer'] !== $root['subject']) {
			return ["valid" => false, "Root certificate is not self-issued"];
		}

		$version = $root['version'];
		$serial = hex2bin($root['serial']);
		$SignatureAlgorithm = $root['signature_algorithm'];
		$issuer_data = "CN={$root['issuer']['CN']};O={$root['issuer']['O']};OU={$root['issuer']['OU']};L={$root['issuer']['L']};ST={$root['issuer']['ST']};C={$root['issuer']['C']};E={$root['issuer']['E']}";
		$subject_data = "CN={$root['subject']['CN']};O={$root['subject']['O']};OU={$root['subject']['OU']};L={$root['subject']['L']};ST={$root['subject']['ST']};C={$root['subject']['C']};E={$root['subject']['E']}";
		$valid_from = $root['valid_from'];
		$valid_to = $root['valid_to'];
		$KEY_TYPE = $root['key_type'];
		$PublicKey = hex2bin($root['publickey']);

		$dataToSign = $version .
					$serial .
					$SignatureAlgorithm .
					pack('i', strlen($issuer_data)) . $issuer_data .
					pack('i', strlen($subject_data)) . $subject_data .
					chr(strlen($valid_from)) . $valid_from .
					chr(strlen($valid_to)) . $valid_to .
					chr($KEY_TYPE) .
					pack('i', strlen($PublicKey)) . $PublicKey;

		if (isset($root['extensions']['SAN'])) {
			$san_bin = '';
			foreach ($root['extensions']['SAN'] as $san) {
				$san_bin .= chr(strlen($san)) . $san;
			}
			$dataToSign .= "\x52" . chr(count($root['extensions']['SAN'])) . $san_bin;
		}
		if (isset($root['extensions']['EKU'])) {
			$eku = 0;
			if(in_array("ServerAuthentication",$root['extensions']['EKU']))	$eku += self::$EKU_ServerAuthentication;
			if(in_array("ClientAuthentication",$root['extensions']['EKU']))	$eku += self::$EKU_ClientAuthentication;
			if(in_array("CodeSigning",$root['extensions']['EKU']))			$eku += self::$EKU_CodeSigning;
			if(in_array("EmailProtection",$root['extensions']['EKU']))		$eku += self::$EKU_EmailProtection;
			if(in_array("TimeStamping",$root['extensions']['EKU']))			$eku += self::$EKU_TimeStamping;
			if(in_array("OCSPSigning",$root['extensions']['EKU']))			$eku += self::$EKU_OCSPSigning;
			if(in_array("DocumentSigning",$root['extensions']['EKU']))		$eku += self::$EKU_DocumentSigning;
			if(in_array("EmailSigning",$root['extensions']['EKU']))			$eku += self::$EKU_EmailSigning;
			$dataToSign .= "\x53" . pack('S', $eku);

		}
		if (isset($root['extensions']['BA'])) {
			$dataToSign .= "\x54";
			if (isset($root['extensions']['BA']['CA'])) {
				$dataToSign .= "\x5a" . ($root['extensions']['BA']['CA'] ? "\x1" : "\x0");
			}
			if (isset($root['extensions']['BA']['PathLength'])) {
				$pathLength = $root['extensions']['BA']['PathLength'];
				$dataToSign .= "\x5b" . chr($pathLength);
			}
		}
		if (isset($root['extensions']['CP'])) {
			$dataToSign .= "\x55";
			if (isset($root['extensions']['CP']['policy'])) {
				$dataToSign .= "\x5a" . chr($root['extensions']['CP']['policy']);
			}
			if (isset($root['extensions']['CP']['policy_url'])) {
				$dataToSign .= "\x5b" . chr(strlen($root['extensions']['CP']['policy_url'])) . $root['extensions']['CP']['policy_url'];
			}
		}
		if (isset($root['extensions']['AIA'])) {
			$dataToSign .= "\x56";
			if (isset($root['extensions']['AIA']['ocsp'])) {
				$dataToSign .= "\x5a" . chr(strlen($root['extensions']['AIA']['ocsp'])) . $root['extensions']['AIA']['ocsp'];
			}
			if (isset($root['extensions']['AIA']['ca_issuers'])) {
				$dataToSign .= "\x5b" . chr(strlen($root['extensions']['AIA']['ca_issuers'])) . $root['extensions']['AIA']['ca_issuers'];
			}
		}

		// Verify root signature (self-signed)
		if (!$this->verify($dataToSign, hex2bin($root['signature']['signature']), $PublicKey, $SignatureAlgorithm)) {
			return ["valid" => false, "Root certificate signature is invalid"];
		}
		// Verify root path Length
		if(isset($pathLength)){
			if($chain_length > $pathLength){
				return ["valid" => false, "Chain is longer than root CA allowed length"];
			}
		}

		return  ["valid" => true, "Certificate chain is valid"];
	}

	private function verify($data, $signature, $key, $SignatureAlgorithm){
		$LCA = $this->LCA;
		switch($SignatureAlgorithm){
			case "sha1WithLCAEncryption":
				$hash_data = sha1($data,true);
				$sign = $LCA->decrypt($signature,$key);
				break;
			case "sha224WithLCAEncryption":
				$hash_data = hash("sha224", $data,true);
				$sign = $LCA->decrypt($signature,$key);
				break;
			case "sha256WithLCAEncryption":
				$hash_data = hash("sha256", $data, true);
				$sign = $LCA->decrypt($signature,$key);
				break;
			case "sha384WithLCAEncryption":
				$hash_data = hash("sha384", $data,true);
				$sign = $LCA->decrypt($signature,$key);
				break;
			case "sha512WithLCAEncryption":
				$hash_data = hash("sha512", $data,true);
				$sign = $LCA->decrypt($signature,$key);
				break;
			case "md5WithLCAEncryption":
				$hash_data = md5($data,true);
				$sign = $LCA->decrypt($signature,$key);
				break;
		}
		return ($hash_data == $sign);
	}

	private function sign($data, $key, $SignatureAlgorithm){
		$LCA = $this->LCA;
		switch($SignatureAlgorithm){
			case "sha1WithLCAEncryption":
				$hash_data = sha1($data,true);
				$sign = $LCA->encrypt($hash_data,$key);
				break;
			case "sha224WithLCAEncryption":
				$hash_data = hash("sha224", $data,true);
				$sign = $LCA->encrypt($hash_data,$key);
				break;
			case "sha256WithLCAEncryption":
				$hash_data = hash("sha256", $data, true);
				$sign = $LCA->encrypt($hash_data,$key);
				break;
			case "sha384WithLCAEncryption":
				$hash_data = hash("sha384", $data,true);
				$sign = $LCA->encrypt($hash_data,$key);
				break;
			case "sha512WithLCAEncryption":
				$hash_data = hash("sha512", $data,true);
				$sign = $LCA->encrypt($hash_data,$key);
				break;
			case "md5WithLCAEncryption":
				$hash_data = md5($data,true);
				$sign = $LCA->encrypt($hash_data,$key);
				break;
		}
		return $sign;
	}
	private function parse_key($key){
		$pattern = '/-----BEGIN [^-]+ KEY-----\s*(.*?)\s*-----END [^-]+ KEY-----/s';
		if (preg_match($pattern, $key, $matches)) {
			$base64 = str_replace(["\n", "\r"], '', $matches[1]);
		} else {
			$this->exc_error("Invalid PEM format.");
		}
		if(base64_encode(base64_decode($base64)) != $base64){
			$this->exc_error("Invalid base64 encoded key");
		}
		return base64_decode($base64);
	}
	private function exc_error($msg){
		throw new ErrorException($msg);
	}
}
?>
