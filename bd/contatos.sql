-- Criando o banco de dados "contatos"
CREATE DATABASE IF NOT EXISTS contatos;

-- Usando o banco de dados "contatos"
USE contatos;

-- Criando a tabela "contatos_info"
CREATE TABLE IF NOT EXISTS contatos_info (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nome VARCHAR(100) NOT NULL,
    telefone VARCHAR(20),
    email VARCHAR(100) NOT NULL
);

CREATE TABLE IF NOT EXISTS usuario (
	id INT AUTO_INCREMENT PRIMARY KEY,
    nome VARCHAR(100) NOT NULL,
    senha VARCHAR(100),
    email VARCHAR(100) UNIQUE,
    token VARCHAR(255) DEFAULT NULL
);