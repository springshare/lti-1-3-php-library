<?php
declare(strict_types=1);

namespace IMSGlobal\LTI;

interface Message_Validator {
    public function validate(array $jwt_body): Message_Validator;
    public function can_validate(array $jwt_body): bool;
}