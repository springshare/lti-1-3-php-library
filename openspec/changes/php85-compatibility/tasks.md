## 1. Audit libapps2 and Setup

- [x] 1.1 Audit libapps2 codebase: identify all calls to this library's public methods and document parameter types passed (especially numeric strings vs ints)
- [x] 1.2 Create a summary document of libapps2 usage patterns for reference during type hint decisions
- [x] 1.3 Update composer.json to declare minimum PHP 8.0 requirement and verify `composer validate` passes
- [x] 1.4 Create a PHP script to audit all files for deprecated functions and missing type hints, identify files needing changes

## 2. Interfaces and Base Classes

- [x] 2.1 Add strict type declarations and complete type hints to `Database.php` (interface) and verify no syntax errors
- [x] 2.2 Add strict type declarations and complete type hints to `Message_Validator.php` (interface) and verify no syntax errors
- [x] 2.3 Add strict type declarations and complete type hints to `Cache.php` (interface) and verify no syntax errors
- [x] 2.4 Add strict type declarations and complete type hints to `Cookie.php` (interface) and verify no syntax errors

## 3. Exception Classes

- [x] 3.1 Add strict type declarations and complete type hints to `LTI_Exception.php` and verify no syntax errors
- [x] 3.2 Add strict type declarations and complete type hints to `OIDC_Exception.php` and verify no syntax errors

## 4. Core LTI Classes

- [x] 4.1 Add strict type declarations and complete type hints to `LTI_Registration.php` and verify no syntax errors
- [x] 4.2 Add strict type declarations and complete type hints to `LTI_Deployment.php` and verify no syntax errors
- [x] 4.3 Add strict type declarations and complete type hints to `JWKS_Endpoint.php` and verify no syntax errors
- [x] 4.4 Add strict type declarations and complete type hints to `LTI_OIDC_Login.php` and verify no syntax errors
- [x] 4.5 Add strict type declarations and complete type hints to `Redirect.php` and verify no syntax errors

## 5. Main Message Launch and Service Classes

- [x] 5.1 Add strict type declarations and complete type hints to `LTI_Message_Launch.php` and verify no syntax errors
- [x] 5.2 Add strict type declarations and complete type hints to `LTI_Service_Connector.php` and verify no syntax errors
- [x] 5.3 Add strict type declarations and complete type hints to `LTI_Assignments_Grades_Service.php` and verify no syntax errors
- [x] 5.4 Add strict type declarations and complete type hints to `LTI_Names_Roles_Provisioning_Service.php` and verify no syntax errors
- [x] 5.5 Add strict type declarations and complete type hints to `LTI_Course_Groups_Service.php` and verify no syntax errors

## 6. Data Model Classes

- [x] 6.1 Add strict type declarations and complete type hints to `LTI_Deep_Link.php` and verify no syntax errors
- [x] 6.2 Add strict type declarations and complete type hints to `LTI_Deep_Link_Resource.php` and verify no syntax errors
- [x] 6.3 Add strict type declarations and complete type hints to `LTI_Grade.php` and verify no syntax errors
- [x] 6.4 Add strict type declarations and complete type hints to `LTI_Lineitem.php` and verify no syntax errors
- [x] 6.5 Add strict type declarations and complete type hints to `LTI_Grade_Submission_Review.php` and verify no syntax errors

## 7. Message Validators

- [x] 7.1 Add strict type declarations and complete type hints to `message_validators/resource_message_validator.php` and verify no syntax errors
- [x] 7.2 Add strict type declarations and complete type hints to `message_validators/deep_link_message_validator.php` and verify no syntax errors
- [x] 7.3 Add strict type declarations and complete type hints to `message_validators/submission_review_message_validator.php` and verify no syntax errors

## 8. Library Root and Loader

- [x] 8.1 Add strict type declarations and complete type hints to `lti.php` and verify no syntax errors

## 9. Type Compatibility Validation

- [x] 9.1 Run PHP 8.5 syntax check on all files: `php -l src/lti/*.php` and verify all pass
- [x] 9.2 Verify no interfaces have breaking type changes by checking that implementations remain valid
- [x] 9.3 Run code through static analysis tool (if available) to catch type incompatibilities

## 10. Testing and Integration

- [x] 10.1 Create a simple test script that instantiates main classes (LTI_Message_Launch, LTI_Registration, etc.) in strict mode and verify no type errors
- [x] 10.2 Run any existing tests (if present) to verify behavior is unchanged
- [x] 10.3 Verify library autoloading works correctly with updated code

## 11. Final Verification

- [x] 11.1 Run a comprehensive PHP 8.5 compatibility check on the entire library with strict_types enabled
- [x] 11.2 Verify all public API methods maintain their original signatures and behavior
- [x] 11.3 Test with PHP 8.5 runtime to ensure no type errors occur

## 12. libapps2 Integration Updates

- [x] 12.1 Identify any type mismatches between libapps2 calls and updated library type hints
- [x] 12.2 Update libapps2 code to pass correct types (add type casts where needed)
- [x] 12.3 Run integrated tests with both library and libapps2 together to verify compatibility
- [x] 12.4 Verify no type errors in strict mode when running through typical libapps2 workflows
