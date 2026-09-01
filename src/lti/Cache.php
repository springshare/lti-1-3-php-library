<?php
declare(strict_types=1);

namespace IMSGlobal\LTI;

class Cache {

    private ?array $cache = null;

    public function get_launch_data(string $key): mixed {
        $this->load_cache();
        return $this->cache[$key] ?? null;
    }

    public function cache_launch_data(string $key, mixed $jwt_body): self {
        $this->cache[$key] = $jwt_body;
        $this->save_cache();
        return $this;
    }

    public function cache_nonce(string $nonce): self {
        $this->cache['nonce'][$nonce] = true;
        $this->save_cache();
        return $this;
    }

    public function check_nonce(string $nonce): bool {
        $this->load_cache();
        if (!isset($this->cache['nonce'][$nonce])) {
            return false;
        }
        return true;
    }

    private function load_cache(): void {
        $cache = @file_get_contents(sys_get_temp_dir() . '/lti_cache.txt');
        if (empty($cache)) {
            @file_put_contents(sys_get_temp_dir() . '/lti_cache.txt', '{}');
            $this->cache = [];
            return;
        }
        $this->cache = json_decode($cache, true) ?: [];
    }

    private function save_cache(): void {
        @file_put_contents(sys_get_temp_dir() . '/lti_cache.txt', json_encode($this->cache));
    }
}