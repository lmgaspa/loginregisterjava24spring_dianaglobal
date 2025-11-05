# 🔄 Atualização Backend - Refresh Token (v146)

## 📋 Mudanças no Backend

O backend foi atualizado para melhorar a validação do endpoint `/api/v1/auth/refresh-token`.

### ✅ O que mudou:

1. **Ordem de validação melhorada:**
   - Primeiro verifica se existe `refresh_token` (retorna 401 se ausente)
   - Depois valida CSRF token (retorna 403 se inválido)
   - Comentários atualizados para maior clareza

2. **Comportamento mantido:**
   - Sem `refresh_token` → `401 Unauthorized`
   - CSRF inválido → `403 Forbidden`
   - Refresh token inválido/expirado → `401 Unauthorized`
   - Sucesso → `200 OK` com novo access token

---

## 🎯 Frontend - O que precisa fazer?

### ⚠️ **IMPORTANTE: O frontend precisa implementar validação ANTES de fazer refresh**

O backend continua retornando `401` ou `403` quando recebe requisições em situações inválidas. Para melhor performance e UX, o frontend deve **evitar fazer essas requisições** quando não há cookies ou está em páginas públicas.

---

## 📝 Implementação Necessária no Frontend

### 1. Verificar se deve tentar refresh

**Antes de chamar `/refresh-token`, verificar:**

```typescript
function shouldAttemptRefresh(): boolean {
  // Verificar se existe cookie de refresh_token
  const hasRefreshToken = document.cookie.includes('refresh_token=');
  
  // Lista de páginas públicas onde refresh não deve ser tentado
  const publicPages = [
    '/login',
    '/register',
    '/forgot-password',
    '/check-email',
    '/reset-password',
    '/confirm-account',
    '/set-password'
  ];
  
  const currentPath = window.location.pathname;
  const isPublicPage = publicPages.some(path => 
    currentPath.includes(path) || currentPath === path
  );
  
  // Só tenta refresh se tem token E não está em página pública
  return hasRefreshToken && !isPublicPage;
}
```

### 2. Usar antes de fazer refresh

```typescript
async function refreshToken() {
  // ✅ VALIDAÇÃO: Não faz requisição se não deve
  if (!shouldAttemptRefresh()) {
    return null; // ou throw error apropriado
  }
  
  // Obter CSRF token do cookie
  const csrfToken = getCsrfTokenFromCookie();
  if (!csrfToken) {
    return null; // ou throw error
  }
  
  // Fazer requisição normalmente
  const response = await fetch('/api/v1/auth/refresh-token', {
    method: 'POST',
    credentials: 'include', // importante para enviar cookies
    headers: {
      'X-CSRF-Token': csrfToken
    }
  });
  
  // Tratar resposta...
}
```

---

## 📊 Status Codes do Backend (v146)

| Situação | Status | Resposta | Ação do Frontend |
|----------|--------|----------|------------------|
| Sem `refresh_token` | `401 Unauthorized` | `{"message": "Missing refresh cookie"}` | Não fazer refresh em páginas públicas |
| CSRF inválido | `403 Forbidden` | `{"message": "Invalid CSRF token"}` | Tentar ler CSRF novamente ou redirecionar para login |
| Refresh token inválido/expirado | `401 Unauthorized` | `{"message": "Invalid or expired refresh token"}` | Limpar cookies e redirecionar para login |
| Sucesso | `200 OK` | `{"token": "novo-access-token"}` | Atualizar access token no localStorage |

---

## ✅ Checklist de Implementação

- [ ] Implementar função `shouldAttemptRefresh()`
- [ ] Verificar antes de chamar `/refresh-token`
- [ ] Não fazer refresh em páginas públicas (`/login`, `/register`, `/forgot-password`, `/check-email`, etc.)
- [ ] Não fazer refresh quando não há cookie `refresh_token`
- [ ] Tratar erro `401` → redirecionar para login
- [ ] Tratar erro `403` → tentar novamente ou redirecionar para login
- [ ] Testar em páginas públicas (não deve fazer requisição)
- [ ] Testar em páginas protegidas (deve fazer refresh quando necessário)

---

## 🎯 Benefícios

1. ✅ **Performance:** Evita requisições desnecessárias ao servidor
2. ✅ **UX:** Menos erros no console do navegador
3. ✅ **Arquitetura:** Lógica de UI fica no frontend
4. ✅ **Segurança:** Backend continua validando (defensivo)

---

## 📌 Resumo

**O backend está funcionando corretamente e retornando os status codes apropriados. O frontend deve implementar validação para evitar fazer requisições desnecessárias em páginas públicas ou quando não há cookies de autenticação.**

---

**Versão do Backend:** v146  
**Data:** 2025-11-05

