<?php

class Note extends Model implements JsonSerializable {

    private $title;
    private $content;
    private $user_id;

    /**
     * @return mixed
     */
    public function getTitle(){
        return $this->title;
    }

    /**
     * @return mixed
     */
    public function getContent(){
        return $this->content;
    }

    /**
     * @return mixed
     */
    public function getUserId() {
        return $this->user_id;
    }

    /**
     * @param $title
     */
    public function setTitle( $title ){
        $this->title = $title;
    }

    /**
     * @param $content
     */
    public function setContent( $content ){
        $this->content = $content;
    }

    /**
     * @param $userId
     */
    public function setUserId( $user_id ) {
        $this->user_id = $user_id;
    }

    /**
     * @return array
     */
    public function jsonSerialize(){
        return [
            "id"        => $this->id,
            "title"     => $this->title,
            "content"   => $this->content,
            "user_id"   => $this->user_id,
        ];
    }

}