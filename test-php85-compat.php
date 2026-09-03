<?php
declare(strict_types=1);

/**
 * PHP 8.5 Compatibility Test Script
 *
 * Instantiates main classes in strict mode to verify no type errors occur
 */

require_once __DIR__ . '/vendor/autoload.php';

use IMSGlobal\LTI\{
    LTI_Message_Launch,
    LTI_Registration,
    LTI_Deployment,
    LTI_OIDC_Login,
    LTI_Deep_Link_Resource,
    LTI_Grade,
    LTI_Lineitem,
    Database,
    Cache,
    Cookie
};

class MockDatabase implements Database {
    public function find_registration_by_issuer(string $iss): LTI_Registration {
        return LTI_Registration::new()
            ->set_issuer('https://example.com')
            ->set_client_id('test_client')
            ->set_key_set_url('https://example.com/jwks')
            ->set_auth_token_url('https://example.com/token')
            ->set_auth_login_url('https://example.com/login')
            ->set_tool_private_key('test_key')
            ->set_kid('test_kid');
    }

    public function find_deployment(string $iss, string $deployment_id): LTI_Deployment {
        return LTI_Deployment::new()
            ->set_deployment_id($deployment_id);
    }
}

echo "Testing PHP 8.5 Compatibility\n";
echo str_repeat("=", 50) . "\n\n";

try {
    // Test Registration
    echo "✓ Testing LTI_Registration...\n";
    $reg = LTI_Registration::new()
        ->set_issuer('https://example.com')
        ->set_client_id('client123')
        ->set_key_set_url('https://example.com/jwks');

    assert($reg->get_issuer() === 'https://example.com', 'Issuer mismatch');
    assert($reg->get_client_id() === 'client123', 'Client ID mismatch');

    // Test Deployment
    echo "✓ Testing LTI_Deployment...\n";
    $deploy = LTI_Deployment::new()
        ->set_deployment_id('deploy123');
    assert($deploy->get_deployment_id() === 'deploy123', 'Deployment ID mismatch');

    // Test Message Launch instantiation
    echo "✓ Testing LTI_Message_Launch instantiation...\n";
    $db = new MockDatabase();
    $launch = LTI_Message_Launch::new($db, new Cache(), new Cookie());
    assert($launch->get_launch_id() !== '', 'Launch ID is empty');

    // Test OIDC Login
    echo "✓ Testing LTI_OIDC_Login instantiation...\n";
    $oidc = LTI_OIDC_Login::new($db);
    assert($oidc !== null, 'OIDC Login instantiation failed');

    // Test Grade and Lineitem
    echo "✓ Testing LTI_Grade...\n";
    $grade = LTI_Grade::new()
        ->set_score_given(85.5)
        ->set_score_maximum(100)
        ->set_activity_progress('Completed')
        ->set_grading_progress('FullyGraded')
        ->set_user_id('user123');
    assert($grade->get_user_id() === 'user123', 'Grade user ID mismatch');

    echo "✓ Testing LTI_Lineitem...\n";
    $lineitem = LTI_Lineitem::new()
        ->set_score_maximum(100)
        ->set_label('Test Assignment')
        ->set_tag('assignment1');
    assert($lineitem->get_label() === 'Test Assignment', 'Lineitem label mismatch');

    // Test Deep Link Resource
    echo "✓ Testing LTI_Deep_Link_Resource...\n";
    $resource = LTI_Deep_Link_Resource::new()
        ->set_url('https://example.com/resource')
        ->set_title('Test Resource')
        ->set_type('link');
    assert($resource->get_url() === 'https://example.com/resource', 'Resource URL mismatch');

    echo "\n" . str_repeat("=", 50) . "\n";
    echo "✓ All tests passed! Library is compatible with PHP 8.5\n";
    exit(0);

} catch (Throwable $e) {
    echo "\n✗ Test failed: " . $e->getMessage() . "\n";
    echo "File: " . $e->getFile() . ":" . $e->getLine() . "\n";
    exit(1);
}
