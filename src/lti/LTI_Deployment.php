<?php
declare(strict_types=1);

namespace IMSGlobal\LTI;

class LTI_Deployment {

    private ?string $deployment_id = null;

    public static function new(): self {
        return new self();
    }

    public function get_deployment_id(): ?string {
        return $this->deployment_id;
    }

    public function set_deployment_id(string $deployment_id): self {
        $this->deployment_id = $deployment_id;
        return $this;
    }

}

?>