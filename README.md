# LunaCert

LunaCert is a PHP library for generating and verifying custom digital certificates using the Luna Crypto Algorithm (LCA). This library allows you to create certificates with various attributes, including subject information, validity periods, and extensions, while ensuring secure signing and verification processes.

## Features

- Generate digital certificates with customizable subject fields and extensions.
- Support for multiple signature algorithms.
- Validate and parse existing certificates.
- Verify certificate chains to ensure trustworthiness.
- Easy integration with existing PHP applications.

## Installation

To use LunaCert, you need to have PHP installed on your system. You can include the `LUNACert` class in your project by downloading the source code or using Composer.

### Using Composer

If you are using Composer, you can add LunaCert to your project by running:

```bash
composer require Minosuko/lunacert
```

### Manual Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/Minosuko/LunaCert.git
   ```

2. Include the `LUNACert.php` file in your PHP script:

   ```php
   require_once 'path/to/LunaCert/LUNACert.php';
   ```

## Usage

### Creating a Certificate

To create a new certificate, instantiate the `LUNACert` class and call the `sign_certificate` method:

```php
$lunaCert = new LUNACert();

$subject = [
    "CN" => "John Doe",
    "O"  => "Example Corp",
    "OU" => "IT Department",
    "L"  => "City",
    "ST" => "State",
    "C"  => "US",
    "E"  => "email@example.com"
];

$validity = 2592000; // 30 days in seconds
$extensions = [
    "SAN" => ["www.example.com", "example.com"],
    "EKU" => LUNACert::$EKU_ServerAuthentication | LUNACert::$EKU_ClientAuthentication,
    "BA"  => ["CA" => true, "PathLength" => 1],
    "CP"  => ["policy" => 1, "policy_url" => "https://example.com/policy"],
    "AIA" => ["ocsp" => "https://ocsp.example.com/", "ca_issuers" => "https://example.com/ca_cert.pem"]
];

$key = [
    "PRIVATE_KEY" => "your-private-key",
    "PUBLIC_KEY"  => "your-public-key",
    "KEY_TYPE"    => LUNACert::$KEY_TYPE_LCA
];

$certificate = $lunaCert->sign_certificate($subject, $validity, $extensions, "sha256WithLCAEncryption", $key);
echo $certificate;
```

### Verifying a Certificate

To verify a certificate, use the `verify_signature` method:

```php
$result = $lunaCert->verify_signature($certificate);
if ($result['valid']) {
    echo "The certificate is valid.";
} else {
    echo "Invalid certificate: " . $result['message'];
}
```

### Verifying a Certificate Chain

To verify a chain of certificates, use the `verify_chain` method:

```php
$cert_chain = [
    "-----BEGIN LCA CERTIFICATE-----\n...\n-----END LCA CERTIFICATE-----",
    "-----BEGIN LCA CERTIFICATE-----\n...\n-----END LCA CERTIFICATE-----"
];

$chain_result = $lunaCert->verify_chain($cert_chain);
if ($chain_result['valid']) {
    echo "The certificate chain is valid.";
} else {echo "Invalid certificate chain: " . $chain_result['message'];
}
```

## Contributing

Contributions are welcome! If you have suggestions for improvements or new features, please open an issue or submit a pull request.

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/YourFeature`).
3. Make your changes and commit them (`git commit -m 'Add some feature'`).
4. Push to the branch (`git push origin feature/YourFeature`).
5. Open a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
