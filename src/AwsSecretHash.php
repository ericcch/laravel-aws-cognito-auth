<?php

namespace Pallant\LaravelAwsCognitoAuth;

trait AwsSecretHash
{
    /**
     * Creates the Cognito secret hash
     *
     * @param string $username
     * @return string
     */
    public function secretHash($username)
    {
        return $this->hash($username . $this->getDefaultAppConfig()['client-id']);
    }

    /**
     * Creates a HMAC from a string
     *
     * @param string $message
     * @return string
     */
    protected function hash($message)
    {
        $hash = hash_hmac(
            'sha256',
            $message,
            $this->getDefaultAppConfig()['client-secret'],
            true
        );

        return base64_encode($hash);
    }
}
