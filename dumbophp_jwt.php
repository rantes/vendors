<?php
/**
 * JSON Web Token implementation
 *
 * Minimum implementation used by Realtime auth, based on this spec:
 * http://self-issued.info/docs/draft-jones-json-web-token-01.html.
 *
 * @author Javier Serrano <rantes.javier@gmail.com>
 * @package Vendor
 * @subpackage JSON_tools
 */
class DumboPHPJWT {
    /**
     * @param string $jwt The JWT
     * @param string|null $key The secret key
     * @param bool $verify Don't skip verification process
     *
     * @return object The JWT's payload as a PHP object
     */
    public function decode($jwt, $key = null, $verify = true) {
        $tks = explode('.', $jwt);
        if (sizeof($tks) != 3):
            throw new UnexpectedValueException('Wrong number of segments');
        endif;

        if (null === ($header = $this->jsonDecode($this->urlsafeB64Decode($tks[0])))):
            throw new UnexpectedValueException('Invalid segment encoding');
        endif;

        if (null === $payload = $this->jsonDecode($this->urlsafeB64Decode($tks[1]))):
            throw new UnexpectedValueException('Invalid segment encoding');
        endif;

        $sig = $this->urlsafeB64Decode($tks[2]);
        if ($verify):
            if (empty($header->alg)):
                throw new DomainException('Empty algorithm');
            endif;

            if ($sig != $this->sign("{$tks[0]}.{$tks[1]}", $key, $header->alg)):
                throw new UnexpectedValueException('Signature verification failed');
            endif;
        endif;
        return $payload;
    }
    /**
     * @param object|array $payload PHP object or array
     * @param string $key The secret key
     * @param string $algo    The signing algorithm
     *
     * @return string A JWT
     */
    public function encode($payload, $key, $algo = 'HS256') {
        $header = ['typ' => 'JWT', 'alg' => $algo];
        $segments = [];
        $segments[] = $this->urlsafeB64Encode($this->jsonEncode($header));
        $segments[] = $this->urlsafeB64Encode($this->jsonEncode($payload));
        $signing_input = implode('.', $segments);
        $signature = $this->sign($signing_input, $key, $algo);
        $segments[] = $this->urlsafeB64Encode($signature);
        return implode('.', $segments);
    }
    /**
     * @param string $msg    The message to sign
     * @param string $key    The secret key
     * @param string $method The signing algorithm
     *
     * @return string An encrypted message
     */
    public function sign($msg, $key, $method = 'HS256') {
        $methods = [
            'HS256' => 'sha256',
            'HS384' => 'sha384',
            'HS512' => 'sha512',
        ];

        if (empty($methods[$method])):
            throw new DomainException('Algorithm not supported');
        endif;

        return hash_hmac($methods[$method], $msg, $key, true);
    }
    /**
     * @param string $input JSON string
     *
     * @return object Object representation of JSON string
     */
    public function jsonDecode($input) {
        $obj = json_decode($input);

        if (function_exists('json_last_error') and $errno = json_last_error()):
            $this->handleJsonError($errno);
        elseif ($obj === null and $input !== 'null'):
            throw new DomainException('Null result with non-null input');
        endif;

        return $obj;
    }
    /**
     * @param object|array $input A PHP object or array
     *
     * @return string JSON representation of the PHP object or array
     */
    public function jsonEncode($input) {
        $json = json_encode($input);

        if (function_exists('json_last_error') and $errno = json_last_error()):
            $this->handleJsonError($errno);
        elseif ($json === 'null' and $input !== null):
            throw new DomainException('Null result with non-null input');
        endif;

        return $json;
    }
    /**
     * @param string $input A base64 encoded string
     *
     * @return string A decoded string
     */
    public function urlsafeB64Decode($input) {
        $remainder = strlen($input) % 4;

        if ($remainder):
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        endif;

        return base64_decode(strtr($input, '-_', '+/'));
    }
    /**
     * @param string $input Anything really
     *
     * @return string The base64 encode of what you passed in
     */
    public function urlsafeB64Encode($input) {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }
    /**
     * @param int $errno An error number from json_last_error()
     *
     * @return void
     */
    private function handleJsonError($errno) {
        $messages = [
            JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
            JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
            JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON'
        ];

        throw new DomainException(isset($messages[$errno]) ? $messages[$errno] : 'Unknown JSON error: ' . $errno);
    }
}
