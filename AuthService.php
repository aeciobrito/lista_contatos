<?php

session_start();
require_once 'Usuario.php';
require_once 'UsuarioDAO.php';

$type = filter_input(INPUT_POST, "type");

switch ($type) {
    case "register":
        registrarUsuario();
        break;
    case "login":
        efetuarLogin();
        break;
    case "logout":
        sairUsuario();
        break;
    default:
        echo "Tipo de requisição inválido!";
}

function registrarUsuario() {
    // Recebimento de dados vindos por input do HTML
    $new_nome = filter_input(INPUT_POST, "new_nome");
    $new_email = filter_input(INPUT_POST, "new_email", FILTER_SANITIZE_EMAIL);
    $new_password = filter_input(INPUT_POST, "new_password");
    $confirm_password = filter_input(INPUT_POST, "confirm_password");

    // Validação dos dados
    if (!$new_nome || !$new_email || !$new_password) {
        echo "Dados de input inválidos!";
        return;
    }

    if ($new_password !== $confirm_password) {
        echo "Senhas incompativeis!";
        return;
    }

    // Criação de senha segura e token
    $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
    $token = bin2hex(random_bytes(25));

    // Criação do objeto Usuário e tentativa de registro no banco de dados
    $usuario = new Usuario(null, $new_nome, $hashed_password, $new_email, $token);
    $usuarioDAO = new UsuarioDAO();

    if(!$usuarioDAO->getByEmail($new_email)) {
        $success = $usuarioDAO->create($usuario);

        if($success) {
            $_SESSION['token'] = $token;
            header('Location: index.php');
            exit();
        } else {
            echo "Erro ao registrar no banco de dados!";
            exit();
        }
    } else {
        echo "Email já utilizado";
    }
}

function efetuarLogin() {
    // Receber os dados vindos do HTML
    $email = filter_input(INPUT_POST, "email", FILTER_SANITIZE_EMAIL);
    $password = filter_input(INPUT_POST, "password");

    // Buscar usuário por email
    $usuarioDAO = new UsuarioDAO();
    $usuario = $usuarioDAO->getByEmail($email);

    // Validação do login
    if (!$usuario || !password_verify($password, $usuario->getSenha())) {
        echo "Email ou Senha inválidos!";
        return;
    }

    // Gerar novo token e atualizar no banco de dados
    $token = bin2hex(random_bytes(25));
    $usuarioDAO->updateToken($usuario->getId(), $token);

    // Armazenar token na sessão e redirecionar para o index.php
    $_SESSION['token'] = $token;
    header('Location: index.php');
    exit();
}

function sairUsuario() {
    // Limpar todas as variáveis da sessão
    $_SESSION = array();

    // Destruir a sessão
    session_destroy();

    // Redirecionar para a página de login
    header('Location: auth.php');
    exit();
}

?>