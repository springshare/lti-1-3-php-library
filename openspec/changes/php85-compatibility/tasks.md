## 1. Audit libapps2 and Setup

- [ ] 1.1 Audit libapps2 codebase: identify all calls to this library's public methods and document parameter types passed (especially numeric strings vs ints)
- [ ] 1.2 Create a summary document of libapps2 usage patterns for reference during type hint decisions
- [ ] 1.3 Update composer.json to declare minimum PHP 8.0 requirement and verify `composer validate` passes
- [ ] 1.4 Create a PHP script to audit all files for deprecated functions and missing type hints, identify files needing changes

## 2. Interfaces and Base Classes

- [ ] 2.1 Add strict type declarations and complete type hints to `Database.php` (interface) and verify no syntax errors
- [ ] 2.2 Add strict type declarations and complete type hints to `Message_Validator.php` (interface) and verify no syntax errors
- [ ] 2.3 Add strict type declarations and complete type hints to `Cache.php` (interface) and verify no syntax errors
- [ ] 2.4 Add strict type declarations and complete type hints to `Cookie.php` (interface) and verify no syntax errors

## 3. Exception Classes

- [ ] 3.1 Add strict type declarations and complete type hints to `LTI_Exception.php` and verify no syntax errors
- [ ] 3.2 Add strict type declarations and complete type hints to `OIDC_Exception.php` and verify no syntax errors

## 4. Core LTI Classes

- [ ] 4.1 Add strict type declarations and complete type hints to `LTI_Registration.php` and verify no syntax errors
- [ ] 4.2 Add strict type declarations and complete type hints to `LTI_Deployment.php` and verify no syntax errors
- [ ] 4.3 Add strict type declarations and complete type hints to `JWKS_Endpoint.php` and verify no syntax errors
- [ ] 4.4 Add strict type declarations and complete type hints to `LTI_OIDC_Login.php` and verify no syntax errors
- [ ] 4.5 Add strict type declarations and complete type hints to `Redirect.php` and verify no syntax errors

## 5. Main Message Launch and Service Classes

- [ ] 5.1 Add strict type declarations and complete type hints to `LTI_Message_Launch.php` and verify no syntax errors
- [ ] 5.2 Add strict type declarations and complete type hints to `LTI_Service_Connector.php` and verify no syntax errors
- [ ] 5.3 Add strict type declarations and complete type hints to `LTI_Assignments_Grades_Service.php` and verify no syntax errors
- [ ] 5.4 Add strict type declarations and complete type hints to `LTI_Names_Roles_Provisioning_Service.php` and verify no syntax errors
- [ ] 5.5 Add strict type declarations and complete type hints to `LTI_Course_Groups_Service.php` and verify no syntax errors

## 6. Data Model Classes

- [ ] 6.1 Add strict type declarations and complete type hints to `LTI_Deep_Link.php` and verify no syntax errors
- [ ] 6.2 Add strict type declarations and complete type hints to `LTI_Deep_Link_Resource.php` and verify no syntax errors
- [ ] 6.3 Add strict type declarations and complete type hints to `LTI_Grade.php` and verify no syntax errors
- [ ] 6.4 Add strict type declarations and complete type hints to `LTI_Lineitem.php` and verify no syntax errors
- [ ] 6.5 Add strict type declarations and complete type hints to `LTI_Grade_Submission_Review.php` and verify no syntax errors

## 7. Message Validators

- [ ] 7.1 Add strict type declarations and complete type hints to `message_validators/resource_message_validator.php` and verify no syntax errors
- [ ] 7.2 Add strict type declarations and complete type hints to `message_validators/deep_link_message_validator.php` and verify no syntax errors
- [ ] 7.3 Add strict type declarations and complete type hints to `message_validators/submission_review_message_validator.php` and verify no syntax errors

## 8. Library Root and Loader

- [ ] 8.1 Add strict type declarations and complete type hints to `lti.php` and verify no syntax errors

## 9. Type Compatibility Validation

- [ ] 9.1 Run PHP 8.5 syntax check on all files: `php -l src/lti/*.php` and verify all pass
- [ ] 9.2 Verify no interfaces have breaking type changes by checking that implementations remain valid
- [ ] 9.3 Run code through static analysis tool (if available) to catch type incompatibilities

## 10. Testing and Integration

- [ ] 10.1 Create a simple test script that instantiates main classes (LTI_Message_Launch, LTI_Registration, etc.) in strict mode and verify no type errors
- [ ] 10.2 Run any existing tests (if present) to verify behavior is unchanged
- [ ] 10.3 Verify library autoloading works correctly with updated code

## 11. Final Verification

- [ ] 11.1 Run a comprehensive PHP 8.5 compatibility check on the entire library with strict_types enabled
- [ ] 11.2 Verify all public API methods maintain their original signatures and behavior
- [ ] 11.3 Test with PHP 8.5 runtime to ensure no type errors occur

## 12. libapps2 Integration Updates

- [ ] 12.1 Identify any type mismatches between libapps2 calls and updated library type hints
- [ ] 12.2 Update libapps2 code to pass correct types (add type casts where needed)
- [ ] 12.3 Run integrated tests with both library and libapps2 together to verify compatibility
- [ ] 12.4 Verify no type errors in strict mode when running through typical libapps2 workflows
