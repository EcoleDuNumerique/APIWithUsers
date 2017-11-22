<?php 
//BddManager va contenir les instances de nos repository
class BddManager {

    private $connection;
    private $noteRepository;
    private $userRepository;

    /**
     * BddManager constructor.
     */
    public function __construct(){
        $this->connection = Connection::getConnection();
        $this->noteRepository = new NoteRepository( $this->connection );
        $this->userRepository = new UserRepository( $this->connection );
    }

    /**
     * @return NoteRepository
     */
    public function getNoteRepository(){
        return $this->noteRepository;
    }

    /**
     * @return UserRepository
     */
    public function getUserRepository() {
        return $this->userRepository;
    }

}