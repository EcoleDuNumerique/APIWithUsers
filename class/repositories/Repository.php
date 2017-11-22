<?php
abstract class Repository {

    protected $connection;

    function __construct( $connection ){
        $this->connection = $connection;
    }

}