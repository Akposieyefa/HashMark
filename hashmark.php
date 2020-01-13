<?php

    /**
     * HashMark password hashing liberary is a very simple and powerful password hashing liberary
     * developed with PHP  to help make password hashing very easy and fast for developers. this 
     * liberary is trusted and very active in its functionality as it uses more than one hashing 
     * technology to hash the provided password.
     * NOTE:: the user is free to manipulate or add any thing to make it more compactable for his or her own
     * use
     * This Liberary is developed by 
     * NAME :: ORUTU AKPOSIEYEFA WILLIAMS 
     * PHONE :: 08100788859
     * TWITTER :: @OrutuW
     * FACEBOOK :: ORUTU AKPOSIEYEFA WILLIAMS
     * DECEMBER 2019 first realease
     * 
     * USERS NOTE :: the user basicly have to call the 
     * hashMarkRegister($ary1,$ary2) function while trying to hash password for registration and 
     * hashMarkLogin($ary1,$ary2) function for login process
     */

class HashMark{

  public    $password_md5;
  public    $password_sha1;
  public    $password_crypt;
  public    $password_peppered;
  public    $hash;
  public    $con;
  public    $hash_details;

  public $config =  array(
    'host' 		  => 'localhost',//database host
    'user' 		  => 'root', //database user
    'password' 	=> '',//database password
    'dbname' 	  => '', //database name
    'salt'      => 'st',
    'pepper'    => 'foIwUVmkKGrGucNJMOkxkvcQ79iPNzP5OKlbIdGPCMTjJcDYnR',
  );

  /**
   * the __construct() connects to the database and we make use of PDO (PHP Data Object)
   */
  public function __construct(){
    try {
        $this->con = new PDO('mysql:host=' .$this->config['host'].'; dbname=' . $this->config['dbname'], $this->config['user'], $this->config['password']);
        return $this->con;  
      } catch (PDOException $e) {
        return $e->getMessage();
      }
  }//end of __construct() function

  /**
   * The hashMarkRegister() fucntion takes two parameter which could be the $username and $password
   * both parameters would be inserted to the database table
   * NOTE:: the password would have to run through the various hashing algorithm in this fucntion 
   */
  public function hashMarkRegister($ary1,$ary2) {
    $this->password_md5 = md5($ary2);
    $this->password_sha1 = sha1($this->password_md5);
    $this->password_crypt = crypt($this->password_sha1,$this->config['salt']);

    $this->password_peppered = hash_hmac('sha256', $this->password_crypt, $this->config['pepper']);
    $this->hash = password_hash($this->password_peppered, PASSWORD_BCRYPT);
    if ($this->hash) {
      $this->hash_details = $this->set_details($ary1,$this->hash);
      if ($this->hash_details) {
        return true;
      }else{
        return false;
      }
    }else{
      return false;
    }   
  } //end of hashMarkRegister() fucntion

  /**
   * the set_details() function help to insert the hashed details collected from the user to 
   * the database table
  */

  public function set_details($ary1,$ary2){

		$query = "INSERT INTO `table_name` (`email`,`password`)
      VALUES(?,?)"; //provide your table name
		$stmt = $this->con->prepare($query);
		$stmt->bindParam(1, $ary1, PDO::PARAM_STR);
		$stmt->bindParam(2, $ary2, PDO::PARAM_STR);
		$stmt->execute();
    $count = $stmt->rowCount();
    if ($count == 1) {
      return $count;
    }else{
      return false;
    }
  }//end of set_details() function
  
  /**
   * the get_details() fucntion helps to select out the details for the hashMarkLogin() funciton 
   * at this point the username or email alone is checked before the password is verified this method
   * is also used to set the user session variable feel free to make use of the SQL JOIN if you want to 
   * pick details from more than one table
   */

  public function get_details($ary1){
      $query = "SELECT * FROM `table_name` WHERE `email`=?"; //provide your table name
      $stmt = $this->con->prepare($query);
      $stmt->bindParam(1, $ary1, PDO::PARAM_STR);
      $stmt->execute();
      $rowcount = $stmt->rowCount();
      if ($rowcount) {
        $count = $stmt->fetch();
        return $count;
      }else{
        return false;
      }
  }//end of get_details() fucntion

  /**
   * the hashMarkLogin() function help to verify the user detials in the database and to match the 
   * hashed password on other to grant the user access to the website this method also sets the user 
   * session detials 
   */

  public function hashMarkLogin($ary1,$ary2) {

      $this->hash_details = $this->get_details($ary1);

      if ($this->hash_details) {
        
        $this->password_md5 = md5($ary2);
        $this->password_sha1 = sha1($this->password_md5);
        $this->password_crypt = crypt($this->password_sha1,$this->config['salt']);
    
        $this->password_peppered = hash_hmac('sha256', $this->password_crypt, $this->config['pepper']);
      
        if (password_verify($this->password_peppered, $this->hash_details['password'])) {
         return true;
        }else {
          return false;
        }
      }else {
        return false;
      }
  }//end of hashMarkLogin() function
}

?>