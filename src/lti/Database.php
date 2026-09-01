<?php
declare(strict_types=1);

namespace IMSGlobal\LTI;

interface Database {
    public function find_registration_by_issuer(string $iss): LTI_Registration;
    public function find_deployment(string $iss, string $deployment_id): LTI_Deployment;
}