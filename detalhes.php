<?php
require_once 'Contato.php';
require_once 'ContatoDAO.php';

$contatoDAO = new ContatoDAO();
$contato = null;

if($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['id'])) {
    $contato  = $contatoDAO->getById($_GET['id']);
}

if($_SERVER['REQUEST_METHOD'] === 'POST') {    
    if(isset($_POST['save'])) {
        if (isset($_POST['id']) && !empty($_POST['id'])) {
            $contato  = $contatoDAO->getById($_POST['id']);

            $contato->setNome($_POST['nome']);
            $contato->setTelefone($_POST['telefone']);
            $contato->setEmail($_POST['email']);

            $contatoDAO->update($contato);
        } else {
            $novoContato = new Contato(null, $_POST['nome'], $_POST['telefone'], $_POST['email']);
            $contatoDAO->create($novoContato);            
        }

        header('Location: index.php');
        exit;
    }
}
?>

<!DOCTYPE html>
<html lang="pt-br">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Detalhes do Contato</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>

<body>
    <div class="container">
        <h1 class="my-4">Detalhes do Contato</h1>
        <form action="detalhes.php" method="POST">
            <input type="hidden" name="id" value="<?php echo $contato ? $contato->getId() : ''  ?>">
            <div class="card">
                <div class="card-body">
                    <div class="form-group">
                        <label for="nome">Nome</label>
                        <input type="text" class="form-control" id="nome" name="nome" value="<?php echo $contato ? $contato->getNome() : ''  ?>" required>
                    </div>
                    <div class="form-group">
                        <label for="telefone">Telefone</label>
                        <input type="text" class="form-control" id="telefone" name="telefone" value="<?php echo $contato ? $contato->getTelefone() : ''  ?>">
                    </div>
                    <div class="form-group">
                        <label for="email">Email</label>
                        <input type="email" class="form-control" id="email" name="email" value="<?php echo $contato ? $contato->getEmail() : ''  ?>" required>
                    </div>
                    <button type="submit" name="save" class="btn btn-success">Salvar</button>

                    <button type="submit" name="delete" class="btn btn-danger">Excluir</button>

                    <a href="index.php" class="btn btn-secondary">Voltar</a>
                </div>
            </div>
        </form>
    </div>
</body>

</html>