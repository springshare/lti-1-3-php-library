## Context

The LTI library was created several years ago and uses older PHP patterns. It currently lacks:
- Explicit `declare(strict_types=1);` statements
- Complete type hints on all functions (some methods have partial type hints)
- An explicit minimum PHP version declaration in `composer.json`

The dependencies (`firebase/php-jwt` and `phpseclib/phpseclib`) already support PHP 8.5, so this effort is focused on the library's own code.

## Goals / Non-Goals

**Goals:**
- Add `declare(strict_types=1);` to every PHP file in `src/lti/`
- Add complete type hints to all functions, methods, and properties
- Update any code using deprecated PHP functions or patterns
- Update `composer.json` to declare minimum PHP version 8.0
- Ensure all existing public APIs work unchanged with client code
- Enable the library to pass PHP 8.5 strict type checking

**Non-Goals:**
- Refactor code architecture or design patterns
- Add new features or functionality
- Break backward compatibility with existing code using the library
- Update examples or external documentation (outside the library itself)
- Modernize code style beyond what is required for PHP 8.5 compatibility (e.g., no reformatting for style alone)

## Decisions

### Decision 1: Approach - Per-file modernization with incremental validation

**Choice**: Modernize all files in `src/lti/` incrementally, validating type compatibility as we go.

**Rationale**: This approach allows us to:
- Test each file's changes independently
- Catch type incompatibility issues early
- Maintain incremental commits if desired
- Parallelize work across multiple files

**Alternatives considered**:
- All-at-once approach: Would be faster but harder to debug if type errors appear
- Dependency-order approach: Would be more complex since the library has interdependencies

### Decision 2: Type hints - Use strict parameter and return types consistently

**Choice**: Use explicit scalar types (`int`, `string`, `bool`, `float`, `array`) and class types for all parameters and returns. Use `mixed` only when a value truly can be any type, `null` for nullable types, and union types where appropriate.

**Rationale**:
- Aligns with PHP 8 best practices
- Provides IDE autocomplete and static analysis benefits
- Makes code safer by catching type errors at runtime

**Alternatives considered**:
- Minimal changes with only method returns: Would provide less safety and IDE benefit
- Omit `mixed` and use `|` for all unions: `mixed` is more explicit for true "any type" cases

### Decision 3: Interface modifications - Maintain backward compatibility

**Choice**: When updating interface methods to add type hints, ensure client implementations remain compatible. Since adding type hints to interface methods can break implementations, we will be careful to use compatible types.

**Rationale**: Existing implementations of our interfaces must continue to work. In PHP, return type covariance and parameter type contravariance allow safe widening of types, but we must verify this.

### Decision 4: Deprecated function handling - Replace with modern equivalents

**Choice**: Any deprecated functions (like `array_key_exists()` used with objects in certain ways) will be replaced with their modern equivalents. For functions removed in PHP 8, we will replace them entirely.

**Rationale**: Ensures code runs on PHP 8.5 without deprecation warnings or errors.

## Risks / Trade-offs

**Risk 1: Third-party code that extends the library**
→ **Mitigation**: We will maintain public method signatures to ensure subclasses continue to work. Any interface changes will be made carefully to not break Liskov Substitution Principle.

**Risk 2: Array vs object type handling**
→ **Mitigation**: Some methods may currently accept either arrays or objects. We will carefully review each case and use appropriate union types or separate methods as needed.

**Risk 3: Performance impact from strict type checking**
→ **Mitigation**: Strict type checking has minimal performance impact in modern PHP. Benefits (safety, IDE support) outweigh costs.

**Risk 4: Incomplete type information in legacy code**
→ **Mitigation**: Where parameter or return types are unclear, we will review usage patterns in the code and tests to infer correct types. If ambiguous, we will use `mixed` temporarily with a note for manual verification.

## Migration Plan

1. **Audit Phase**: Scan all files to identify which need type hints and which use deprecated functions
2. **Implementation Phase**: For each file:
   - Add `declare(strict_types=1);` at the top
   - Add missing type hints to all methods and functions
   - Replace deprecated functions
   - Verify no internal type conflicts
3. **Validation Phase**: Run through code with PHP 8.5 parser to verify strict type compatibility
4. **Testing Phase**: Run any existing tests to ensure behavior is unchanged
5. **Deployment**: Update `composer.json` to declare PHP 8.0+ requirement
6. **Documentation**: Update README if needed to reflect PHP version support

## Open Questions

- Should we also support PHP 8.0, 8.1, 8.2, 8.3, 8.4, or only 8.5+? (Assumption: 8.0+ is sufficient based on the request; can adjust if we discover breaking changes in specific versions)
