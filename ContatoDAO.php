<?php

require_once 'Database.php';
require_once 'Contato.php';

class ContatoDAO {    
    private $db;

    public function __construct()
    {
        $this->db = Database::getInstance()->getConnection();
    }

    // criar um getall
    public function getAll() {
        try {
            $sql = "SELECT * FROM contatos_info";
            $stmt = $this->db->prepare($sql);
            $stmt->execute();
            $contatos = $stmt->fetchAll(PDO::FETCH_ASSOC);

            return array_map(function($contato){
                return new Contato($contato['id'], $contato['nome'], $contato['telefone'], $contato['email']);
            }, $contatos);
        } catch (PDOException $e) {
            return [];
        }
    }
}

?>