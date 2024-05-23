<?php
require_once 'Database.php';
require_once 'Contato.php';
require_once 'ContatoDAO.php';

$contatoDAO = new ContatoDAO();
print_r($contatoDAO->getAll());
?>

<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lista de Contatos</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>
    <div class="container">
        <h1 class="my-4">Lista de Contatos</h1>
        <a href="detalhes.php" class="btn btn-primary mb-4">Adicionar Contato</a>
        <div class="row row-cols-1 row-cols-md-3 g-4">            
                <div class="col">
                    <div class="card">
                        <div class="card-body">
                            <h5 class="card-title">Pessoa X</h5>
                            <p class="card-text">NN-NNNN-NNNN</p>
                            <p class="card-text">mail@mail.com</p>
                            <a href="detalhes.html" class="btn btn-primary">Detalhes</a>
                        </div>
                    </div>
                </div>            
        </div>
    </div>
</body>
</html>
