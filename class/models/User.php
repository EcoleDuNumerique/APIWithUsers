<?php
/**
 * Class User
 * @author Alexandre Ribes
 */
class User extends Model implements JsonSerializable {

    private $firstName;
    private $lastName;
    private $email;
    private $password;

    /**
     * @param $firstName
     */
    public function setFirstName( $firstName ){
        $this->firstName = ucfirst($firstName);
    }

    /**
     * @param $lastName
     */
    public function setLastName( $lastName ) {
        $this->lastName = ucfirst($lastName);
    }

    /**
     * @param $email
     */
    public function setEmail( $email ) {
        $this->email = $email;
    }

    /**
     * @param $password
     */
    public function setPassword( $password ) {
        $this->password = md5($password);
    }

    /**
     * @return mixed
     */
    public function getFirstName() {
        return $this->firstName;
    }

    /**
     * @return mixed
     */
    public function getLastName() {
        return $this->lastName;
    }

    /**
     * @return mixed
     */
    public function getEmail() {
        return $this->email;
    }

    /**
     * @return mixed
     */
    public function getPassword() {
        return $this->password;
    }

    /**
     * @return array
     */
    function jsonSerialize(){
        return [
            'email'         =>  $this->email,
            'first_name'    =>  $this->firstName,
            'last_name'     =>  $this->lastName,
        ];
    }
}