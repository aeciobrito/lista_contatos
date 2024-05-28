<?php

require_once 'Database.php';
require_once 'Usuario.php';

class UsuarioDAO
{
    private $db;

    public function __construct()
    {
        $this->db = Database::getInstance()->getConnection();
    }

    public function create($usuario)
    {
        try {
            $sql = "INSERT INTO usuario (nome, senha, email, token)
                    VALUES (:nome, :senha, :email, :token)";
            $stmt = $this->db->prepare($sql);

            $nome = $usuario->getNome();
            $senha = $usuario->getSenha();
            $email = $usuario->getEmail();
            $token = $usuario->getToken();

            $stmt->bindParam(':nome', $nome);
            $stmt->bindParam(':senha', $senha);
            $stmt->bindParam(':email', $email);
            $stmt->bindParam(':token', $token);

            $stmt->execute();
            
            return true;
        } catch (PDOException $e) {
            return false;
        }
    }
}
