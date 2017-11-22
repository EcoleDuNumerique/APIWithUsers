<?php
use \Firebase\JWT\JWT;

//require "flight/Flight.php";
require "autoload.php";
require_once('vendor/autoload.php');

$cfg = [
    'key'   =>  'azertyuiop',
    'algo'  =>  'HS512'
];

//Enregistrer en global dans Flight le BddManager
Flight::set('cfg', $cfg);
Flight::set("BddManager", new BddManager());
Flight::set('JWTAuth', new JWTAuth());

//Lire toutes les notes
Flight::route("GET /notes", function(){

    $bddManager = Flight::get("BddManager");
    $repo = $bddManager->getNoteRepository();
    $notes = $repo->getAll();

    echo json_encode ( $notes );

});

//Récuperer la note @id
Flight::route("GET /note/@id", function( $id ){
    
    $status = [
        "success" => false,
        "note" => false
    ];

    $note = new Note();
    $note->setId( $id );

    $bddManager = Flight::get("BddManager");
    $repo = $bddManager->getNoteRepository();
    $note = $repo->getById( $note );

    if( $note != false ){
        $status["success"] = true;
        $status["note"] = $note;
    }

    echo json_encode( $status );

});

/**
 * Notes par utilisateur
 */
Flight::route("GET /users/@id", function($id) {

    $user = new User();
    $user->setId($id);

    $bddManager = Flight::get("BddManager");
    $repo = $bddManager->getNoteRepository();
    $notes = $repo->getByUserId($user);

    if( !$notes ) {
        echo json_encode([
            'success'   =>  false
        ]);
    } else {
        echo json_encode([
            'success'   =>  true,
            'notes'     =>  $notes,
        ]);
    }
});

//Créer une note
Flight::route("POST /note", function(){

    $JWTAuth = Flight::get("JWTAuth");
    $response = $JWTAuth->hasAccess(Flight::get("cfg")['key']);
    if( !$response['success'] ) {
        echo json_encode($response);
        exit;
    }

    $title = Flight::request()->data["title"];
    $content = Flight::request()->data["content"];

    $status = [
        "success" => false,
        "id" => 0
    ];

    if( strlen( $title ) > 0 && strlen( $content ) > 0 ) {

        $note = new Note();
        $note->setTitle( $title );
        $note->setContent( $content );

        $bddManager = Flight::get("BddManager");
        $repo = $bddManager->getNoteRepository();
        $id = $repo->save( $note );

        if( $id != 0 ){
            $status["success"] = true;
            $status["id"] = $id;
        }

    }

    echo json_encode( $status ); 
    
});

//Supprimer la note @id
Flight::route("DELETE /note/@id", function( $id ){

    $JWTAuth = Flight::get("JWTAuth");
    $response = $JWTAuth->hasAccess(Flight::get("cfg")['key']);
    if( !$response['success'] ) {
        echo json_encode($response);
        exit;
    }

    $status = [
        "success" => false
    ];

    $note = new Note();
    $note->setId( $id );

    $bddManager = Flight::get("BddManager");
    $repo = $bddManager->getNoteRepository();

    $note = $repo->getById($note);
    if( $note && $note->getUserId() === $response['token']->data->userId ) {
        $rowCount = $repo->delete( $note );

        if( $rowCount == 1 ){
            $status["success"] = true;
        }

        echo json_encode( $status );
        exit;
    }

    echo json_encode([
        'success'   =>  false,
        'error'     =>  'Vous n\'êtes pas autorisés à réaliser cette action.'
    ]);
    
});

Flight::route("PUT /note/@id", function( $id ){

    $JWTAuth = Flight::get("JWTAuth");
    $response = $JWTAuth->hasAccess(Flight::get("cfg")['key']);
    if( !$response['success'] ) {
        echo json_encode($response);
        exit;
    }

    //Pour récuperer des données PUT -> les données sont encodé en json string
    //avec ajax, puis décodé ici en php
    $json = Flight::request()->getBody();
    $_PUT = json_decode( $json , true);//true pour tableau associatif

    $status = [
        'success'   =>  false,
        'error'     =>  null,
    ];

    $bddManager = Flight::get("BddManager");
    $repo = $bddManager->getNoteRepository();

    $note = new Note();
    $note->setId($id);
    $note = $repo->getById($note);
    if( $note && $note->getUserId() != $response['token']->data->userId ) {
        echo json_encode([
            'success'   =>  false,
            'error'     =>  'Vous n\'êtes pas autorisés à réaliser cette action.'
        ]);
        exit;
    }

    $status['success'] = false;
    $status['error'] = 'Vous n\'êtes pas autorisés à réaliser cette action.';

    if( isset( $_PUT["title"] ) && isset( $_PUT["content"] ) ){

        $title = $_PUT["title"];
        $content = $_PUT["content"];

        $note = new Note();
        $note->setId( $id );
        $note->setTitle( $title );
        $note->setContent( $content );

        $rowCount = $repo->save( $note );

        if( $rowCount == 1 ){
            $status["success"] = true;
        }

    }

    echo json_encode( $status );

});

/**
 * Traitement de la requête de connexion
 */
Flight::route("POST /auth/connexion", function() {

    $cfg = Flight::get("cfg");

    $inputs = [
        'email'     =>  Flight::request()->data->email,
        'password'  =>  Flight::request()->data->password,
    ];

    if( isset($inputs['email']) && isset($inputs['password']) ) {
        $bddManager = Flight::get("BddManager");
        $repo = $bddManager->getUserRepository();

        $user = $repo->login($inputs['email'], $inputs['password']);

        if( $user ) {

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

            echo json_encode([
                'token' =>  $token,
            ]);

        } else {
            echo json_encode([
                'success'   =>  false,
            ]);
        }
    } else {
        echo json_encode([
            'success'   =>  false,
        ]);
    }
});

/**
 * Traitement de la requête d'inscription
 */
Flight::route("POST /auth/inscription", function() {
    $json = Flight::request()->getBody();
    $inputs = json_decode( $json , true);

    $error = false;
    foreach( $inputs as $key => $value ) {
        if( !isset($inputs[$key]) ) {
            $error = true;
        }
    }

    if( !$error ) {
        $bddManager = Flight::get("BddManager");
        $repo = $bddManager->getUserRepository();

        $user = new User();
        $user->setEmail($inputs['email']);
        $user->setFirstName($inputs['firstname']);
        $user->setLastName($inputs['lastname']);
        $user->setPassword($inputs['password']);

        $rowCount = $repo->save();
        if( $rowCount ) {
            echo json_encode([
                'success'   =>  true,
                'firstname' =>  $user->getFirstName(),
            ]);
        } else {
            echo json_encode([
                'success'   =>  false
            ]);
        }
    } else {
        echo json_encode([
            'success'   =>  false
        ]);
    }
});

Flight::route('/', function() {
    echo md5('toto');
});

/**
 * Retourne la liste de tous les utilisateurs
 */
Flight::route('GET /users', function() {
    $bddManager = Flight::get("BddManager");
    $repo = $bddManager->getUserRepository();

    $offset = !is_null(Flight::request()->data->offset) ? Flight::request()->data->offset : 0;
    $users = $repo->getAll(10, $offset);
    echo json_encode($users);
});

/**
 * Permet de raffraichir le token de connexion
 */
Flight::route('GET /refresh', function() {
    $JWTAuth = Flight::get("JWTAuth");
    $response = $JWTAuth->hasAccess(Flight::get('cfg')['key']);
    if( !$response['success'] ) {
        echo json_encode($response);
        exit;
    }

    $newToken = $JWTAuth->refresh($response['token'], Flight::get('cfg')['key']);
    echo json_encode([
        'success'   =>  true,
        'token'     =>  $newToken
    ]);
});

/**
 * Informations de l'utilisateur
 */
Flight::route('GET /account', function() {
    $JWTAuth = Flight::get("JWTAuth");
    $response = $JWTAuth->hasAccess(Flight::get("cfg")['key']);
    if( !$response['success'] ) {
        echo json_encode($response);
        exit;
    }
});

Flight::route('PUT /account/update', function() {
    $JWTAuth = Flight::get("JWTAuth");
    $response = $JWTAuth->hasAccess(Flight::get("cfg")['key']);
    if( !$response['success'] ) {
        echo json_encode($response);
        exit;
    }
});

Flight::route('GET /account/notes', function() {
    $JWTAuth = Flight::get("JWTAuth");

    $response = $JWTAuth->hasAccess(Flight::get("cfg")['key']);
    if( !$response['success'] ) {
        echo json_encode($response);
        exit;
    }
});

Flight::start();