<?php
require_once 'Database.php';
require_once 'Contato.php';
require_once 'ContatoDAO.php';

$contatoDAO = new ContatoDAO();
$contatos = $contatoDAO->getAll();
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
            <?php foreach($contatos as $contato) : ?>
                <div class="col">
                    <div class="card">
                        <div class="card-body">
                            <h5 class="card-title"><?php echo $contato->getNome(); ?></h5>
                            <p class="card-text"><?php echo $contato->getTelefone(); ?></p>
                            <p class="card-text"><?php echo $contato->getEmail(); ?></p>
                            <a href="detalhes.php?id=<?php echo $contato->getId(); ?>" class="btn btn-primary">Detalhes</a>
                        </div>
                    </div>
                </div>  
            <?php endforeach; ?>
        </div>
    </div>
</body>
</html>
