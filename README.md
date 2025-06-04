DianaGlobal Auth API

API de autenticação desenvolvida com Spring Boot 3 utilizando JWT (JSON Web Token) para autenticação segura, com arquitetura hexagonal (ports & adapters).

🧱 Tecnologias Utilizadas

Java 21

Spring Boot 3.x

Spring Security 6+

JWT (via io.jsonwebtoken)

Lombok

Maven

Swagger/OpenAPI 3

Arquitetura Hexagonal (Clean Architecture)

Banco de dados (ex: PostgreSQL ou MongoDB)

🚀 Funcionalidades

Registro de usuário com criptografia de senha

Login com geração de token JWT

Endpoint protegido que exige autenticação via token

Integração com Swagger para documentação da API

Middleware para interceptar JWTs via filtro personalizado

📦 Endpoints

AuthController

POST /api/auth/register

Cadastra um novo usuário

Exemplo de requisição:

{
"name": "Luiz",
"email": "luiz@example.com",
"password": "12345678"
}

POST /api/auth/login

Autentica e retorna um token JWT

Requisição:

{
"email": "luiz@example.com",
"password": "12345678"
}

Resposta:

{
"token": "eyJhbGciOiJIUzI1NiJ9..."
}

UserController

GET /api/user/profile

Retorna o e-mail do usuário autenticado

Requer:

Authorization: Bearer {token}

🔮 Testes com curl

curl -X POST http://localhost:8080/api/auth/register -H "Content-Type: application/json" -d "{\"name\":\"Luiz\",\"email\":\"luiz@example.com\",\"password\":\"12345678\"}"

curl -X POST http://localhost:8080/api/auth/login -H "Content-Type: application/json" -d "{\"email\":\"luiz@example.com\",\"password\":\"12345678\"}"

curl -H "Authorization: Bearer {TOKEN}" http://localhost:8080/api/user/profile

📘 Swagger

A documentação da API está disponível em:

http://localhost:8080/swagger-ui/index.html

🔐 JWT

O token é assinado com HS256 e possui tempo de expiração configurado. A chave secreta (é recomendado armazenar via variáveis de ambiente):

jwt:
secret: ${JWT_SECRET:my-super-secret-key-my-super-secret-key}

📁 Estrutura do Projeto

loginregister/
├── adapter/
│   ├── in/web/            # Controllers
│   └── out/persistence/   # Repositórios JPA e entidades
├── application/
│   ├── port/in/           # Interfaces dos casos de uso
│   ├── port/out/          # Interfaces para persistência
│   └── service/           # Implementação dos casos de uso
├── config/                # Spring Security, JWT Filter
├── domain/model/          # Modelo de domínio (User)
├── resources/
│   └── application.yml

👨‍💼 Autor

Luiz GasparettoProjeto: DianaGlobal AuthGitHub: https://github.com/lmgaspa