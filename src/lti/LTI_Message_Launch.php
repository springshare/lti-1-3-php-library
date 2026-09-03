<?php
declare(strict_types=1);

namespace IMSGlobal\LTI;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;

JWT::$leeway = 5;

class LTI_Message_Launch
{

    private Database $db;
    private Cache $cache;
    private array $request = [];
    private Cookie $cookie;
    private array $jwt = [];
    private ?LTI_Registration $registration = null;
    private string $launch_id = "";

    /**
     * Constructor
     *
     * @param Database $database Instance of the database interface used for looking up registrations and deployments.
     * @param Cache $cache Instance of the Cache interface used to loading and storing launches. If non is provided launch data will be store in $_SESSION.
     * @param Cookie $cookie Instance of the Cookie interface used to set and read cookies. Will default to using $_COOKIE and setcookie.
     */
    public function __construct(Database $database, ?Cache $cache = null, ?Cookie $cookie = null) {
        $this->db = $database;

        $this->launch_id = uniqid("lti1p3_launch_", true);

        if ($cache === null) {
            $cache = new Cache();
        }
        $this->cache = $cache;

        if ($cookie === null) {
            $cookie = new Cookie();
        }
        $this->cookie = $cookie;
    }

    public static function new(Database $database, ?Cache $cache = null, ?Cookie $cookie = null): self {
        return new self($database, $cache, $cookie);
    }

    public static function from_cache(string $launch_id, Database $database, ?Cache $cache = null, mixed $launch_data = null): self {
        $new = new self($database, $cache, null);
        $new->launch_id = $launch_id;
        $new->jwt = ['body' => ($launch_data ?? $new->cache->get_launch_data($launch_id))];
        return $new->validate_registration();
    }

    public function validate(bool $skip_state = false, bool $allow_self_signed = false): self
    {
        $this->request = $_POST;

        return $this->validate_state($skip_state)
            ->validate_jwt_format()
            ->validate_nonce()
            ->validate_registration()
            ->validate_jwt_signature($allow_self_signed)
            ->validate_deployment()
            ->validate_message()
            ->cache_launch_data();
    }

    public function has_nrps(): bool {
        return !empty($this->jwt['body']['https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice']['context_memberships_url']);
    }

    public function get_nrps(): LTI_Names_Roles_Provisioning_Service {
        return new LTI_Names_Roles_Provisioning_Service(
            new LTI_Service_Connector($this->registration),
            $this->jwt['body']['https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice']);
    }

    public function has_gs(): bool {
        return !empty($this->jwt['body']['https://purl.imsglobal.org/spec/lti-gs/claim/groupsservice']['context_groups_url']);
    }

    public function get_gs(): LTI_Course_Groups_Service {
        return new LTI_Course_Groups_Service(
            new LTI_Service_Connector($this->registration),
            $this->jwt['body']['https://purl.imsglobal.org/spec/lti-gs/claim/groupsservice']);
    }

    public function has_ags(): bool {
        return !empty($this->jwt['body']['https://purl.imsglobal.org/spec/lti-ags/claim/endpoint']);
    }

    public function get_ags(): LTI_Assignments_Grades_Service {
        return new LTI_Assignments_Grades_Service(
            new LTI_Service_Connector($this->registration),
            $this->jwt['body']['https://purl.imsglobal.org/spec/lti-ags/claim/endpoint']);
    }

    public function get_deep_link(): LTI_Deep_Link {
        return new LTI_Deep_Link(
            $this->registration,
            (string)$this->jwt['body']['https://purl.imsglobal.org/spec/lti/claim/deployment_id'],
            $this->jwt['body']['https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings']);
    }

    public function is_deep_link_launch(): bool {
        return $this->jwt['body']['https://purl.imsglobal.org/spec/lti/claim/message_type'] === 'LtiDeepLinkingRequest';
    }

    public function is_submission_review_launch(): bool {
        return $this->jwt['body']['https://purl.imsglobal.org/spec/lti/claim/message_type'] === 'LtiSubmissionReviewRequest';
    }

    public function is_resource_launch(): bool {
        return $this->jwt['body']['https://purl.imsglobal.org/spec/lti/claim/message_type'] === 'LtiResourceLinkRequest';
    }

    public function get_launch_data(): array {
        return $this->jwt['body'];
    }

    public function get_launch_id(): string {
        return $this->launch_id;
    }

    private function get_public_key(bool $allow_self_signed = false): mixed {
        $key_set_url = $this->registration->get_key_set_url();

        // Download key set
        $public_key_set = json_decode(
            @file_get_contents(
                $key_set_url,
                false,
                stream_context_create([
                    "ssl" => [
                        "allow_self_signed" => $allow_self_signed     // verify_peer => false will also work here
                    ],
                    "http" => [
                        "user_agent" => "LTI-1-3-PHP-Library"
                    ]
                ])
            ),
            true
        );

        if (empty($public_key_set)) {
            // Failed to fetch public keyset from URL.
            error_log("LTI: Failed to fetch JWKS from: " . $key_set_url);
            throw new LTI_Exception("Failed to fetch public key", 1);
        }

        // Find key used to sign the JWT (matches the KID in the header)
        foreach ($public_key_set['keys'] as $key) {
            if (isset($this->jwt['header']['kid']) && $key['kid'] == $this->jwt['header']['kid']) {
                try {
                    // Some LMS (like D2L) don't include "alg" in their JWKS, so add it from the JWT header
                    if (!isset($key['alg']) && isset($this->jwt['header']['alg'])) {
                        $key['alg'] = $this->jwt['header']['alg'];
                    }

                    $parsedKeys = JWK::parseKeySet([
                        'keys' => [$key]
                    ]);
                    $parsedKey = $parsedKeys[$key['kid']];

                    // Return the Key object directly for firebase/php-jwt v7.x
                    return $parsedKey;
                } catch (\Exception $e) {
                    error_log("LTI: Failed to parse key (kid=" . ($key['kid'] ?? 'N/A') . "): " . $e->getMessage());
                    return false;
                }
            }
        }

        // Could not find public key with a matching kid and alg.
        error_log("LTI: No matching kid found in JWKS. Looking for: " . ($this->jwt['header']['kid'] ?? 'N/A'));
        throw new LTI_Exception("Unable to find public key", 1);
    }

    private function cache_launch_data(): self
    {
        $this->cache->cache_launch_data($this->launch_id, $this->jwt['body']);
        return $this;
    }

    private function validate_state(bool $skip_state = false): self {
        // State check bypass
        if ($skip_state) {
            return $this;
        }

        // Error if state is missing from request
        if (empty($this->request['state'])) {
            throw new LTI_Exception("Missing state", 1);
        }

        // Error if state is missing from cookie
        if (empty($this->cookie->get_cookie('lti1p3_' . $this->request['state']))) {
            throw new LTI_Exception("Missing state cookie", 1);
        }

        // Error if state doesn't match cookie
        if ($this->cookie->get_cookie('lti1p3_' . $this->request['state']) !== $this->request['state']) {
            throw new LTI_Exception("Invalid state", 1);
        }
        return $this;
    }

    private function validate_jwt_format(): self {
        // Get id_token; throw exception on missing / empty value.
        $jwt = ($this->request['id_token'] ?? null);
        if (empty($jwt)) {
            error_log("=== JWT Validation Debug ===");
            error_log('$this->request='.json_encode($this->request));
            throw new LTI_Exception("Missing id_token", 1);
        }

        // Get parts of JWT; throw exception on invalid number of parts.
        $jwt_parts = explode('.', $jwt);
        if (count($jwt_parts) !== 3) {
            throw new LTI_Exception("Invalid id_token, JWT must contain 3 parts", 1);
        }

        // Decode JWT headers and body
        $this->jwt['header'] = json_decode(JWT::urlsafeB64Decode($jwt_parts[0]), true);
        $this->jwt['body'] = json_decode(JWT::urlsafeB64Decode($jwt_parts[1]), true);

        return $this;
    }

    private function validate_nonce(): self {
        if (!$this->cache->check_nonce($this->jwt['body']['nonce'])) {
            //throw new LTI_Exception("Invalid Nonce");
        }
        return $this;
    }

    private function validate_registration(): self {
        // Find registration.
        $iss = $this->jwt['body']['iss'];
        $this->registration = $this->db->find_registration_by_issuer($iss);
        if (empty($this->registration)) {
            throw new LTI_Exception('Registration not found for issuer (' . $iss . ')', 1);
        }

        // Check client id; marcbertone disabled the exception here since it may not apply to our use of the client_id
        $client_id_from_jwt = is_array($this->jwt['body']['aud']) ? $this->jwt['body']['aud'][0] : $this->jwt['body']['aud'];
        $client_id_from_registration = $this->registration->get_client_id();
        if ($client_id_from_jwt !== $client_id_from_registration) {
            # throw new LTI_Exception(
            #    'Client id extracted from JWT (' . $client_id_from_jwt . ') does not match client id from registration ' .
            #    '(' . $client_id_from_registration . ')',
            #    1
            #);
        }

        return $this;
    }

    private function validate_jwt_signature(bool $allow_self_signed = false): self {
        // Fetch public key.
        $public_key = $this->get_public_key($allow_self_signed);

        if ($public_key === false) {
            throw new LTI_Exception("Invalid signature on id_token", 1);
        }

        // Validate JWT signature using firebase/php-jwt v7.x API
        try {
            JWT::decode($this->request['id_token'], $public_key);
        } catch (\Exception $e) {
            // Error validating signature.
            error_log("LTI: JWT signature validation failed: " . $e->getMessage());
            throw new LTI_Exception("Invalid signature on id_token", 1);
        }

        return $this;
    }

    private function validate_deployment(): self {
        // Find deployment.
        $deployment = $this->db->find_deployment(
            ($this->jwt['body']['iss'] ?? ''),
            ($this->jwt['body']['https://purl.imsglobal.org/spec/lti/claim/deployment_id'] ?? '')
        );

        if (empty($deployment)) {
            // deployment not recognized.
            throw new LTI_Exception("Unable to find deployment", 1);
        }

        return $this;
    }

    private function validate_message(): self {
        if (empty($this->jwt['body']['https://purl.imsglobal.org/spec/lti/claim/message_type'])) {
            // Unable to identify message type.
            throw new LTI_Exception("Invalid message type", 1);
        }

        // Do message type validation

        // Import all validators
        foreach (glob(__DIR__ . "/message_validators/*.php") as $filename) {
            include_once $filename;
        }

        // Create instances of all validators
        $classes = get_declared_classes();
        $validators = array();
        foreach ($classes as $class_name) {
            // Check the class implements message validator
            $reflect = new \ReflectionClass($class_name);
            if ($reflect->implementsInterface('\IMSGlobal\LTI\Message_Validator')) {
                // Create instance of class
                $validators[] = new $class_name();
            }
        }

        $message_validator = false;
        foreach ($validators as $validator) {
            if ($validator->can_validate($this->jwt['body'])) {
                if ($message_validator !== false) {
                    // Can't have more than one validator apply at a time.
                    throw new LTI_Exception("Validator conflict", 1);
                }
                $message_validator = $validator;
            }
        }

        if ($message_validator === false) {
            throw new LTI_Exception("Unrecognized message type.", 1);
        }

        if (!$message_validator->validate($this->jwt['body'])) {
            throw new LTI_Exception("Message validation failed.", 1);
        }

        return $this;

    }
}

?>
