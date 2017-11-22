<?php 
function myautoload( $classname ){ //Note

    $folders = [
        "class/",
        "class/models/",
        "class/repositories/"
    ];

    foreach( $folders as $folder ){

        $file = $folder . $classname . ".php";
        if( file_exists( $file ) ){
            require $file;
            return;
        }

    }

}
spl_autoload_register( "myautoload" );