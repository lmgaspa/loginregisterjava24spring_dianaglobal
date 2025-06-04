# 🔐 DianaGlobal Auth API

Autenticação segura com **Spring Boot 3** e **JWT**, baseada em **Arquitetura Hexagonal (Ports & Adapters)**.  
Ideal para sistemas como **exchanges de criptomoedas**, **painéis administrativos** ou **aplicações modernas com autenticação robusta**.

---

## ⚙️ Tecnologias Utilizadas

- ☕ **Java 24**
- 🚀 **Spring Boot 3.x**
- 🔐 **Spring Security 6+**
- 🪪 **JWT (via `io.jsonwebtoken`)**
- 🧠 **Arquitetura Hexagonal** (Clean Architecture)
- 💉 **Lombok**
- 📦 **Maven**
- 🧪 **Swagger/OpenAPI 3**
- 💾 **Banco de Dados**: PostgreSQL ou MongoDB (personalizável)

---

## 🚀 Funcionalidades

- ✅ Registro de usuários com criptografia de senha
- ✅ Login com geração de **JWT + refresh token**
- ✅ Endpoint `/profile` protegido com autenticação JWT
- ✅ Rota `/refresh-token` para renovar tokens expirados
- ✅ Logout com **revogação e blacklist de refresh tokens**
- ✅ Middleware JWT com filtro customizado
- ✅ Integração Swagger: [http://localhost:8080/swagger-ui/index.html](http://localhost:8080/swagger-ui/index.html)

---

## 👨‍💼 Author

Luiz Gasparetto
Project: DianaGlobal Auth
GitHub: https://github.com/lmgaspa