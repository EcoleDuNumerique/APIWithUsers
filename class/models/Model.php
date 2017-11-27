<?php 
abstract class Model {

    protected $id;

    function __construct( $datas=[] ){
        $this->hydrate( $datas );
    }

    function getId(){
        return $this->id;
    }

    function setId( $id ){
        $this->id = $id;
    }

    protected function hydrate( $datas ){   
        foreach( $datas as $key => $data ){

            if( preg_match('/_/', $key) ) {
                $finalKey = '';
                $keys = explode('_', $key);

                foreach( $keys as $k ) {
                    $finalKey .= ucfirst($k);
                }

                $method = 'set' . $finalKey;
            } else {
                $method = "set".ucfirst($key);
            }

            if( method_exists( $this, $method ) ){
                $this->$method( $data );
            }
        }
    }

}