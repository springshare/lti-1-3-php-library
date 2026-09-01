<?php
declare(strict_types=1);

namespace IMSGlobal\LTI;

class Cookie {
    public function get_cookie(string $name): string|bool {
        if (isset($_COOKIE[$name])) {
            return $_COOKIE[$name];
        }
        if (isset($_COOKIE["LEGACY_" . $name])) {
            return $_COOKIE["LEGACY_" . $name];
        }
        return false;
    }

    public function set_cookie(string $name, string $value, int $exp = 3600, array $options = []): self {
        $cookie_options = [
            'expires' => time() + $exp
        ];

        if (!isset($cookie_options['path'])) {
            $cookie_options['path'] = '/';
        }

        $same_site_options = [
            'samesite' => 'None',
            'secure' => true
        ];

        setcookie($name, $value, array_merge($cookie_options, $same_site_options, $options));
        setcookie("LEGACY_" . $name, $value, array_merge($cookie_options, $options));
        return $this;
    }
}
