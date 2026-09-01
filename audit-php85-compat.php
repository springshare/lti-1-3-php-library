<?php
declare(strict_types=1);

/**
 * PHP 8.5 Compatibility Audit Script
 *
 * This script scans all PHP files in src/lti for:
 * 1. Missing declare(strict_types=1)
 * 2. Functions/methods without type hints
 * 3. Deprecated PHP functions
 */

class PHP85CompatAudit {
    private const LTI_SRC_DIR = __DIR__ . '/src/lti';
    private array $deprecatedFunctions = [
        'each', 'split', 'ereg', 'eregi', 'ereg_replace', 'eregi_replace',
        'define_syslog_variables', 'mysql_', 'dl', 'dl', 'call_user_func_array',
        'move_uploaded_file', 'mcrypt_', 'mhash_', 'fgetcsv', 'fputcsv',
    ];

    private array $findings = [];

    public function run(): void {
        echo "PHP 8.5 Compatibility Audit\n";
        echo str_repeat("=", 50) . "\n\n";

        $files = $this->getPhpFiles();
        echo "Scanning " . count($files) . " PHP files...\n\n";

        foreach ($files as $file) {
            $this->auditFile($file);
        }

        $this->printReport();
    }

    private function getPhpFiles(): array {
        $files = [];
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator(self::LTI_SRC_DIR)
        );

        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }

    private function auditFile(string $filepath): void {
        $filename = str_replace(self::LTI_SRC_DIR . '/', '', $filepath);
        $content = file_get_contents($filepath);
        $lines = file($filepath, FILE_IGNORE_NEW_LINES);

        $issues = [];

        // Check for declare(strict_types=1)
        if (!preg_match('/declare\s*\(\s*strict_types\s*=\s*1\s*\)/i', $content)) {
            $issues[] = [
                'type' => 'MISSING_STRICT_TYPES',
                'line' => 1,
                'message' => 'Missing declare(strict_types=1)'
            ];
        }

        // Check for deprecated functions
        foreach ($this->deprecatedFunctions as $func) {
            $pattern = '/\b' . preg_quote($func) . '\s*\(/i';
            if (preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
                foreach ($matches[0] as $match) {
                    $line = substr_count($content, "\n", 0, $match[1]) + 1;
                    $issues[] = [
                        'type' => 'DEPRECATED_FUNCTION',
                        'line' => $line,
                        'message' => "Deprecated function: {$func}()"
                    ];
                }
            }
        }

        // Check for functions/methods without type hints (simplified check)
        $functionPattern = '/(?:public|private|protected)?\s+(?:static)?\s+function\s+(\w+)\s*\((.*?)\)\s*(?::\s*(\w+|\?|\|))?\s*{/';
        if (preg_match_all($functionPattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
            foreach ($matches[0] as $idx => $match) {
                $params = $matches[2][$idx][0];
                $returnType = $matches[3][$idx][0] ?? '';
                $line = substr_count($content, "\n", 0, $match[1]) + 1;

                // Check if parameters have types
                if (!empty($params) && !preg_match('/\w+\s+\$/', $params)) {
                    $funcName = $matches[1][$idx][0];
                    $issues[] = [
                        'type' => 'MISSING_PARAM_TYPES',
                        'line' => $line,
                        'message' => "Function '$funcName' missing parameter type hints"
                    ];
                }

                // Check if return type is missing (simplified)
                if (empty($returnType) && strpos($params, '$') !== false) {
                    // Only flag if there are parameters
                }
            }
        }

        if (!empty($issues)) {
            $this->findings[$filename] = $issues;
        }
    }

    private function printReport(): void {
        if (empty($this->findings)) {
            echo "\n✓ No issues found!\n";
            return;
        }

        echo "\nFindings:\n\n";

        foreach ($this->findings as $filename => $issues) {
            echo "File: $filename\n";
            foreach ($issues as $issue) {
                echo "  Line {$issue['line']}: [{$issue['type']}] {$issue['message']}\n";
            }
            echo "\n";
        }

        $totalFiles = count($this->findings);
        $totalIssues = array_reduce($this->findings, fn($sum, $issues) => $sum + count($issues), 0);
        echo "\nSummary:\n";
        echo "  Files with issues: $totalFiles\n";
        echo "  Total issues: $totalIssues\n";
    }
}

$audit = new PHP85CompatAudit();
$audit->run();
