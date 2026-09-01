<?php
declare(strict_types=1);

namespace IMSGlobal\LTI;

class LTI_Grade_Submission_Review {
    private ?string $reviewable_status = null;
    private ?string $label = null;
    private ?string $url = null;
    private mixed $custom = null;

    public static function new(): self {
        return new self();
    }

    public function get_reviewable_status(): ?string {
        return $this->reviewable_status;
    }

    public function set_reviewable_status(string $value): self {
        $this->reviewable_status = $value;
        return $this;
    }

    public function get_label(): ?string {
        return $this->label;
    }

    public function set_label(string $value): self {
        $this->label = $value;
        return $this;
    }

    public function get_url(): ?string {
        return $this->url;
    }

    public function set_url(string $url): self {
        $this->url = $url;
        return $this;
    }

    public function get_custom(): mixed {
        return $this->custom;
    }

    public function set_custom(mixed $value): self {
        $this->custom = $value;
        return $this;
    }

    public function __toString(): string {
        return json_encode(array_filter([
            "reviewableStatus" => $this->reviewable_status,
            "label" => $this->label,
            "url" => $this->url,
            "custom" => $this->custom,
        ]));
    }
}
?>