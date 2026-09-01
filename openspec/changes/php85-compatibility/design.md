## Context

The LTI library was created several years ago and uses older PHP patterns. It currently lacks:
- Explicit `declare(strict_types=1);` statements
- Complete type hints on all functions (some methods have partial type hints)
- An explicit minimum PHP version declaration in `composer.json`

The dependencies (`firebase/php-jwt` and `phpseclib/phpseclib`) already support PHP 8.5, so this effort is focused on the library's own code.

**Important**: This library is used only internally by Springshare. The sole consuming codebase is `libapps2`. This allows us to use strict type hints without breaking external clients—we can audit and update `libapps2` as needed to ensure compatibility.

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
- Update examples or external documentation (outside the library itself)
- Modernize code style beyond what is required for PHP 8.5 compatibility (e.g., no reformatting for style alone)

Note: Since this library is only used internally by libapps2, type hint changes will be audited against that codebase and updated as needed. We prioritize correct, strict types over false backward compatibility.

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

### Decision 2: Type hints - Use strict, single-type hints where possible

**Choice**: Use explicit scalar types (`int`, `string`, `bool`, `float`, `array`) and class types for all parameters and returns. Use `mixed` only when a value truly can be any type, `null` for nullable types, and union types **only when the method legitimately handles multiple types**. Avoid union types simply to accommodate ambiguous calling patterns.

**Rationale**:
- Since libapps2 is the only consumer, we can audit and update calling code to match strict types
- Strict single types catch errors early and improve IDE support
- Makes code intent and contracts clearer
- If `libapps2` passes the wrong type, we'll fix it there rather than weakening the contract here

**Alternatives considered**:
- Liberal use of union types for flexibility: Would weaken type safety without benefit since we can update callers
- Maintain ambiguity with `mixed`: Would defeat the purpose of modernization

### Decision 3: Interface modifications - Audit and update implementations

**Choice**: Add strict type hints to interface methods. Any classes implementing these interfaces (only within this library and in libapps2) will be updated to match the new type hints.

**Rationale**: Since libapps2 is the only external consumer, we can audit its implementations and update them to match strict types. This results in cleaner, safer code throughout the codebase.

### Decision 4: Deprecated function handling - Replace with modern equivalents

**Choice**: Any deprecated functions (like `array_key_exists()` used with objects in certain ways) will be replaced with their modern equivalents. For functions removed in PHP 8, we will replace them entirely.

**Rationale**: Ensures code runs on PHP 8.5 without deprecation warnings or errors.

## Risks / Trade-offs

**Risk 1: Ambiguous type hints in libapps2 calls**
→ **Mitigation**: Audit libapps2 for all calls to this library. Where type mismatches exist (e.g., passing string instead of int), update the calling code in libapps2 to pass the correct type.

**Risk 2: Legacy code patterns in this library**
→ **Mitigation**: Where methods currently accept mixed or ambiguous types, we will determine the intended type from actual usage in libapps2 and implement strict types accordingly.

**Risk 3: Performance impact from strict type checking**
→ **Mitigation**: Strict type checking has minimal performance impact in modern PHP. Benefits (safety, IDE support) outweigh costs.

**Risk 4: Array vs object type handling**
→ **Mitigation**: If methods accept both arrays and objects, audit libapps2 to see which is actually used. If only one is used, use that strict type. If both are legitimately needed, use a union type.

## Migration Plan

1. **Audit libapps2 Phase**: Scan libapps2 codebase to understand how it calls this library. Document type patterns for ambiguous parameters (e.g., does it pass strings or ints for numeric values?).
2. **Audit Library Phase**: Scan all files in this library to identify which need type hints and which use deprecated functions.
3. **Implementation Phase**: For each file in this library:
   - Add `declare(strict_types=1);` at the top
   - Add type hints based on actual usage patterns in libapps2 (prefer strict types)
   - Replace deprecated functions
   - Verify no internal type conflicts
4. **Validation Phase**: Run through code with PHP 8.5 parser to verify strict type compatibility
5. **libapps2 Updates**: Fix any type mismatches in libapps2 calls (type casting where needed)
6. **Testing Phase**: Test library + libapps2 together to ensure behavior is unchanged
7. **Deployment**: Update `composer.json` to declare PHP 8.0+ requirement

## Open Questions

(None—the approach and strategy are clear. libapps2 audit will resolve any ambiguous type decisions before implementation.)
