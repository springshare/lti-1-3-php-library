## Why

The library is a critical LTI 1.3 tool provider library used across multiple projects, but currently has no specified minimum PHP version and contains code patterns that may not be fully compatible with modern PHP versions. Ensuring compatibility with PHP 8.5 (the latest stable release) will enable users to run this library in modern environments and take advantage of performance improvements and security fixes in recent PHP versions.

## What Changes

- Add strict type declarations to all PHP files for consistency with modern PHP practices
- Update function signatures to include full type hints (parameters and return types)
- Replace deprecated function usage and patterns that are no longer supported in PHP 8.5
- Fix any code that violates PHP 8+ strict type checking rules
- Update `composer.json` to explicitly declare the minimum PHP version requirement (8.0 or higher)
- Verify all dependencies are compatible with PHP 8.5
- Remove or update code that depends on PHP features removed in PHP 8.x versions

## Capabilities

### New Capabilities

- `php-8-5-compatibility`: Library is fully compatible with PHP 8.5, with strict type declarations, modern type hints, and no deprecated function usage

### Modified Capabilities

(None - this is purely a modernization effort, not a feature change)

## Impact

- **Code**: All PHP files in `src/lti/` directory
- **APIs**: No breaking changes to public APIs; existing client code should continue to work
- **Dependencies**: The `firebase/php-jwt` and `phpseclib/phpseclib` packages are already compatible with PHP 8.5
- **Minimum PHP version**: Will require PHP 8.0+ (with full compatibility up to 8.5)
