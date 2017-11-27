<?php 
class NoteRepository extends Repository {

    /**
     * @return array
     */
    public function getAll(){
        $query = "SELECT * FROM notes ORDER BY id DESC";
        $result = $this->connection->query( $query );
        $result = $result->fetchAll( PDO::FETCH_ASSOC );

        $notes = [];

        foreach( $result as $data ){
            $notes[] = new Note( $data );
        }

        return $notes;  
    }

    /**
     * @param Note $note
     * @return bool|Note
     */
    public function getById( Note $note ){

        $query = "SELECT * FROM notes WHERE id=:id";
        $prep = $this->connection->prepare( $query );
        $prep->execute([
            "id" => $note->getId()
        ]);
        $result = $prep->fetch(PDO::FETCH_ASSOC);

        if( empty( $result ) ){
            return false;
        }
        else {
            return new Note( $result );
        }
    }

    /**
     * @param User $user
     * @return array
     */
    public function getByUserId( User $user ) {
        $query = "SELECT * FROM notes WHERE user_id=:user_id";
        $prep = $this->connection->prepare( $query );
        $prep->execute([
            'user_id'   =>  $user->getId(),
        ]);
        $result = $prep->fetchAll( PDO::FETCH_ASSOC );

        $notes = [];
        foreach( $result as $data ){
            $notes[] = new Note( $data );
        }

        return $notes;
    }

    /**
     * @param Note $note
     * @return mixed
     */
    public function save( Note $note ){
        if( empty( $note->getId() ) ){
            return $this->insert( $note );
        }
        else {
            return $this->update( $note );
        }
    }

    /**
     * @param Note $note
     * @return mixed
     */
    private function insert( Note $note ){

        $query = "INSERT INTO notes SET title=:title, content=:content, user_id=:user_id, picture=:picture";
        $prep = $this->connection->prepare( $query );
        $prep->execute([
            "title"     => $note->getTitle(),
            "content"   => $note->getContent(),
            "user_id"   => $note->getUserId(),
            "picture"   => $note->getPicture(),
        ]);
        return $this->connection->lastInsertId();
    }

    /**
     * @param Note $note
     * @return mixed
     */
    private function update( Note $note ){

        $query = "UPDATE notes SET title=:title, content=:content, picture=:picture WHERE id=:id";
        $prep = $this->connection->prepare( $query );
        $prep->execute([
            "id"            => $note->getId(),
            "title"         => $note->getTitle(),
            "content"       => $note->getContent(),
            "picture"       => $note->getPicture(),
        ]);
        return $prep->rowCount();

    }

    /**
     * @param Note $note
     * @return mixed
     */
    function delete( Note $note ) {

        $query = "DELETE FROM notes WHERE id=:id";
        $prep = $this->connection->prepare( $query );
        $prep->execute([
            "id" => $note->getId()
        ]);
        return $prep->rowCount();

    }

}