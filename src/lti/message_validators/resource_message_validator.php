<?php
namespace IMSGlobal\LTI;

class Resource_Message_Validator implements Message_Validator
{
    public function can_validate($jwt_body)
    {
        return $jwt_body['https://purl.imsglobal.org/spec/lti/claim/message_type'] === 'LtiResourceLinkRequest';
    }

    public function validate($jwt_body)
    {
        if (!isset($jwt_body['https://purl.imsglobal.org/spec/lti/claim/version'])) {
            throw new LTI_Exception('Missing Version Claim');
        }
        if ($jwt_body['https://purl.imsglobal.org/spec/lti/claim/version'] !== '1.3.0') {
            throw new LTI_Exception('Incorrect version, expected 1.3.0');
        }
        if (!isset($jwt_body['https://purl.imsglobal.org/spec/lti/claim/roles'])) {
            throw new LTI_Exception('Missing Roles Claim');
        }
        # allow missing sub only for anonymous launches per https://www.imsglobal.org/spec/lti/v1p3#user-identity-claims
        if (empty($jwt_body['sub']) && !in_array('http://purl.imsglobal.org/vocab/lis/v2/system/person#None',$jwt_body['https://purl.imsglobal.org/spec/lti/claim/roles'])) {
            die($jwt_body['https://purl.imsglobal.org/spec/lti/claim/roles']);
            throw new LTI_Exception('Must have a user (sub)');
        }
        if (empty($jwt_body['https://purl.imsglobal.org/spec/lti/claim/resource_link']['id'])) {
            throw new LTI_Exception('Missing Resource Link Id');
        }

        return true;
    }
}

?>
