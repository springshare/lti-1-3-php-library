<?php
namespace IMSGlobal\LTI;

use phpseclib3\Crypt\RSA;
use phpseclib3\Common\Functions\Strings;
use \Exception;
use \Firebase\JWT\JWT;

class JWKS_Endpoint {

    private $keys;

    public function __construct(array $keys) {
        $this->keys = $keys;
    }

    public static function new($keys) {
        return new JWKS_Endpoint($keys);
    }

    public static function from_issuer(Database $database, $issuer) {
        $registration = $database->find_registration_by_issuer($issuer);
        return new JWKS_Endpoint([$registration->get_kid() => $registration->get_tool_private_key()]);
    }

    public static function from_registration(LTI_Registration $registration) {
        return new JWKS_Endpoint([$registration->get_kid() => $registration->get_tool_private_key()]);
    }

    public function get_public_jwks() {
        $jwks = [];
        foreach ($this->keys as $kid => $private_key) {
            try {
                // Load private key and get the public key
                $key = RSA::load($private_key);
                $public_key = $key->getPublicKey();

                // Extract modulus and exponent using Raw format
                $key_components = $public_key->toString('raw');

                $components = array(
                    'kty' => 'RSA',
                    'alg' => 'RS256',
                    'use' => 'sig',
                    'e' => Strings::base64url_encode($key_components['e']->toBytes()),
                    'n' => Strings::base64url_encode($key_components['n']->toBytes()),
                    'kid' => $kid,
                );
                $jwks[] = $components;
            } catch (Exception $e) {
                // Skip keys that fail to load
                continue;
            }
        }
        return ['keys' => $jwks];
    }

    public function output_jwks() {
        echo json_encode($this->get_public_jwks());
    }

}