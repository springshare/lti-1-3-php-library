<?php
declare(strict_types=1);

namespace IMSGlobal\LTI;

class LTI_Deep_Link_Resource {

    private string $type = 'ltiResourceLink';
    private ?string $title = null;
    private ?string $url = null;
    private ?LTI_Lineitem $lineitem = null;
    private array $custom_params = [];
    private array $iframe = [];
    private string $target = 'iframe';

    public static function new(): self {
        return new self();
    }

    public function get_type(): string {
        return $this->type;
    }

    public function set_type(string $value): self {
        $this->type = $value;
        return $this;
    }

    public function get_title(): ?string {
        return $this->title;
    }

    public function set_title(string $value): self {
        $this->title = $value;
        return $this;
    }

    public function get_url(): ?string {
        return $this->url;
    }

    public function set_url(string $value): self {
        $this->url = $value;
        return $this;
    }

    public function get_lineitem(): ?LTI_Lineitem {
        return $this->lineitem;
    }

    public function set_lineitem(LTI_Lineitem $value): self {
        $this->lineitem = $value;
        return $this;
    }

    public function get_custom_params(): array {
        return $this->custom_params;
    }

    public function set_custom_params(array $value): self {
        $this->custom_params = $value;
        return $this;
    }

    public function get_iframe(): array {
        return $this->iframe;
    }

    public function set_iframe(array $value): self {
        $this->iframe = $value;
        return $this;
    }

    public function get_target(): string {
        return $this->target;
    }

    public function set_target(string $value): self {
        $this->target = $value;
        return $this;
    }

    public function to_array(): array {
        $resource = [
            "type" => $this->type,
            "title" => $this->title,
            "url" => $this->url,
            "presentation" => [
                "documentTarget" => $this->target,
            ],
            "custom" => $this->custom_params,
            "iframe" => $this->iframe,
        ];
        if ($this->lineitem !== null) {
            $resource["lineItem"] = [
                "scoreMaximum" => $this->lineitem->get_score_maximum(),
                "label" => $this->lineitem->get_label(),
            ];
        }
        return $resource;
    }
}
?>
