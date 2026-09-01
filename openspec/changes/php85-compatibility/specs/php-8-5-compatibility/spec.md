## Purpose

Enable this library to run reliably on PHP 8.5 by ensuring all code uses modern type declarations, removes deprecated patterns, and maintains compatibility with strict PHP type checking.

## ADDED Requirements

### Requirement: All PHP files declare strict types
The library SHALL include `declare(strict_types=1);` at the beginning of every PHP source file to enforce strict type checking and ensure compatibility with modern PHP practices.

#### Scenario: A file is loaded in strict mode
- **WHEN** a PHP file from the library is parsed
- **THEN** it contains `declare(strict_types=1);` as the first statement after the opening `<?php` tag

### Requirement: All functions have complete type hints
Every function and method in the library SHALL have type hints for all parameters and a return type. Type hints SHALL use modern PHP type declaration syntax compatible with PHP 8.5.

#### Scenario: Function is called with correct types
- **WHEN** a function is called with arguments matching its parameter type hints
- **THEN** the function executes without type errors

#### Scenario: Function is called with incompatible type in strict mode
- **WHEN** a function is called with an argument that does not match its parameter type hint
- **THEN** a TypeError is thrown

#### Scenario: Function return value matches declared type
- **WHEN** a function completes execution
- **THEN** the returned value matches the function's declared return type

### Requirement: No deprecated PHP functions are used
The library code SHALL not use any functions that are deprecated or removed in PHP 8.5, including but not limited to: `each()`, `split()`, `ereg*()` functions, and other functions removed in PHP 8.0+.

#### Scenario: Code is analyzed for deprecated functions
- **WHEN** the library source code is scanned for deprecated function usage
- **THEN** no deprecated functions are found

### Requirement: Library is installable on PHP 8.5
The library's `composer.json` SHALL declare a minimum PHP version requirement that is compatible with PHP 8.0 or higher, and all declared dependencies SHALL be compatible with PHP 8.5.

#### Scenario: Composer install on PHP 8.5
- **WHEN** running `composer install` in a PHP 8.5 environment
- **THEN** all dependencies are resolved and installed successfully

#### Scenario: Autoloader works correctly
- **WHEN** the Composer autoloader is required and classes are accessed
- **THEN** all classes in the `IMSGlobal\LTI` namespace are available

### Requirement: Type compatibility across the codebase
The library SHALL use consistent, modern type declarations throughout, including union types, nullable types, and mixed types where appropriate for PHP 8.5 compatibility.

#### Scenario: Interface implementation matches parent types
- **WHEN** a class implements an interface
- **THEN** method signatures in the implementation are compatible with the interface declaration

#### Scenario: Private and public properties are properly typed
- **WHEN** properties are declared on classes
- **THEN** they have type declarations compatible with PHP 8.5

### Requirement: No breaking changes to public API
The library's public API and behavior SHALL remain unchanged for users of the library, with modernizations being internal only.

#### Scenario: Existing client code continues to work
- **WHEN** client code that uses the library is run on PHP 8.5
- **THEN** the code executes without modification

#### Scenario: Factory methods and fluent interfaces work unchanged
- **WHEN** code calls static factory methods like `LTI_Message_Launch::new()` or fluent setters
- **THEN** they return the expected object types and behavior is preserved
