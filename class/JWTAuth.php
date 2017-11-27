<?php
use Firebase\JWT\JWT;
/**
 * Class Auth
 */
class JWTAuth
{
    public $userId;

    public function hasAccess($secretKey) {
        $headers = $this->getHeaders();

        if( !is_null($headers) ) {
            if( preg_match('/Bearer\s((.*)\.(.*)\.(.*))/', $headers, $matches) ) {
                $jwt =  $matches[1];

                if( $jwt ) {

                    try {
                        $token = JWT::decode($jwt, $secretKey, array('HS512'));
                        $this->userId = $token->data->userId;
                        return [
                            'success'   =>  true,
                            'token'     =>  $token,
                            'id'        =>  $token->data->userId,
                        ];
                    } catch( Exception $e ) {
                        return [
                            'success'   =>  false,
                            'line'      =>  $e->getLine(),
                            'error'     =>  $e->getMessage(),
                        ];
                    }
                }

                return [
                    'success'   =>  false,
                    'error'     =>  'Impossible de lire le token d\'authentification'
                ];
            }

            return [
                'success'   =>  false,
                'error'     =>  'Impossible de lire le token d\'authentification'
            ];
        }
        return [
            'success'   =>  false,
            'error'     =>  'Impossible de lire le token d\'authentification'
        ];
    }

    /**
     * Création du token utilisateur
     *
     * @param User $user
     * @param $cfg
     * @return string
     */
    public function createToken(User $user, $cfg) {
        $tokenId    = $user->getId();
        $issuedAt   = time();
        $notBefore  = $issuedAt + 10;
        $expire     = $issuedAt + 60 * 60;
        $serverName = 'localhost';

        $data = [
            'iat'  => $issuedAt,
            'jti'  => $tokenId,
            'iss'  => $serverName,
            'nbf'  => $notBefore,
            'exp'  => $expire,
            'data' => [
                'userId'   => $user->getId(),
                'userName' => $user->getFirstname()
            ]
        ];

        $token = JWT::encode($data, $cfg['key'], $cfg['algo']);
        return $token;
    }

    /**
     * Permet de raffraichir un token
     *
     * @param $token
     * @param $secretKey
     * @return string
     */
    public function refresh($token, $secretKey) {
        try{
            $decoded = JWT::decode($token, $secretKey, ['HS512']);
            return JWT::encode($decoded, $secretKey);
        }catch ( \Firebase\JWT\ExpiredException $e ) {
            JWT::$leeway = 720000;
            $decoded = (array) JWT::decode($token, $secretKey, ['HS512']);

            $decoded['iat'] = time();
            $decoded['exp'] = time() + 3600;

            return JWT::encode($decoded, $secretKey);
        }catch ( \Exception $e ){
            return $e->getMessage();
        }
    }

    /**
     * @return null|string
     */
    public function getHeaders() {
        $headers = null;
        if (isset($_SERVER['Authorization'])) {
            $headers = trim($_SERVER["Authorization"]);
        }
        else if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
        } elseif (function_exists('apache_request_headers')) {
            $requestHeaders = apache_request_headers();
            $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
            if (isset($requestHeaders['Authorization'])) {
                $headers = trim($requestHeaders['Authorization']);
            }
        }
        return $headers;
    }
}