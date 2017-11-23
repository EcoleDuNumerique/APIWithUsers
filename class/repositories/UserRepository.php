<?php

/**
 * Class UserRepository
 * @author Alexandre Ribes`
 */
class UserRepository extends Repository
{
    /**
     * @param User $user
     * @return mixed
     */
    public function save( User $user ){
        return empty($user->getId()) ?  $this->insert($user) : $this->update($user);
    }

    /**
     * @param User $user
     * @return mixed
     */
    public function insert( User $user ) {
        $query = "INSERT INTO users SET firstname=:firstname, lastname=:lastname, email=:email, password=:password";
        $prep = $this->connection->prepare($query);
        $return = $prep->execute([
            'firstname'     =>  $user->getFirstName(),
            'lastname'      =>  $user->getLastName(),
            'email'         =>  $user->getEmail(),
            'password'      =>  $user->getPassword(),
        ]);
        return $this->connection->lastInsertId();
    }

    /**
     * @param User $user
     * @return mixed
     */
    public function update( User $user ) {
        $query = "UPDATE users SET firstname=:firstname, lastname=:lastname, email=:email, password=:password WHERE id=:id";
        $prep = $this->connection->prepare($query);
        $prep->execute([
            'firstname'     =>  $user->getFirstName(),
            'lastname'      =>  $user->getLastName(),
            'email'         =>  $user->getEmail(),
            'password'      =>  $user->getPassword(),
        ]);
        return $prep->rowCount();
    }

    /**
     * @param $email
     * @param $password
     * @return bool|User
     */
    public function login($email, $password) {
        $query = "SELECT * FROM users WHERE email=:email AND password=:password";
        $prep = $this->connection->prepare($query);
        $prep->execute([
            'email'     =>  $email,
            'password'  =>  md5($password),
        ]);

        $result = $prep->fetch(PDO::FETCH_ASSOC);
        if( !$result ){
            return false;
        }

        return new User($result);
    }

    /**
     * @param User $user
     * @return bool|User
     */
    public function getById( User $user ){

        $query = "SELECT * FROM users WHERE id=:id LIMIT 1";
        $prep = $this->connection->prepare( $query );
        $prep->execute([
            "id" => $user->getId()
        ]);
        $result = $prep->fetch(PDO::FETCH_ASSOC);

        if( empty( $result ) ){
            return false;
        }
        else {
            return new User( $result );
        }
    }

    public function getByEmail( User $user ){

        $query = "SELECT * FROM users WHERE email=:email LIMIT 1";
        $prep = $this->connection->prepare( $query );
        $prep->execute([
            "email" => $user->getEmail()
        ]);
        $result = $prep->fetch(PDO::FETCH_ASSOC);

        if( empty( $result ) ){
            return false;
        }
        else {
            return new User( $result );
        }
    }

    /**
     * Retourne la liste des utilisateurs
     *
     * @param int $limit
     * @param int $offset
     * @return array
     */
    public function getAll($limit = 10, $offset = 0) {
        $query = "SELECT * FROM users ORDER BY id ASC LIMIT $offset,$limit";
        $result = $this->connection->query( $query );
        $result = $result->fetchAll( PDO::FETCH_ASSOC );

        $users = [];
        foreach( $result as $data ){
            $users[] = new User( $data );
        }

        return $users;
    }
}