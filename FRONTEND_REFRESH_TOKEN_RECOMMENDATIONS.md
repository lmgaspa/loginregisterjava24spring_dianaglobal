# 🔄 Recomendações Frontend - Refresh Token

## 📋 Problema

O endpoint `/api/v1/auth/refresh-token` está retornando `403 Forbidden` quando o frontend tenta fazer refresh em páginas públicas onde o usuário não está autenticado (ex: `/check-email`, `/forgot-password`).

## 🎯 Solução Recomendada

**Implementar validação no frontend ANTES de fazer a requisição de refresh.**

---

## ✅ Implementação no Frontend

### 1. Verificar se deve tentar refresh

```typescript
/**
 * Verifica se o frontend deve tentar fazer refresh do token
 * @returns true se deve tentar refresh, false caso contrário
 */
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
  
  const isPublicPage = publicPages.some(path => 
    window.location.pathname.includes(path)
  );
  
  // Só tenta refresh se tem token E não está em página pública
  return hasRefreshToken && !isPublicPage;
}
```

### 2. Usar antes de fazer refresh

```typescript
// No seu interceptor ou hook de refresh
async function refreshToken() {
  // ✅ VALIDAÇÃO: Não faz requisição se não deve
  if (!shouldAttemptRefresh()) {
    return null; // ou throw error apropriado
  }
  
  // Fazer requisição normalmente
  const response = await fetch('/api/v1/auth/refresh-token', {
    method: 'POST',
    credentials: 'include', // importante para enviar cookies
    headers: {
      'X-CSRF-Token': getCsrfTokenFromCookie() // pegar do cookie csrf_token
    }
  });
  
  if (!response.ok) {
    // Tratar erro
    if (response.status === 401) {
      // Token expirado ou inválido - redirecionar para login
      redirectToLogin();
    } else if (response.status === 403) {
      // CSRF inválido - pode tentar novamente ou redirecionar
      handleCsrfError();
    }
    return null;
  }
  
  return await response.json();
}
```

### 3. Exemplo com React Hook

```typescript
import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';

function useTokenRefresh() {
  const location = useLocation();
  
  useEffect(() => {
    // Verificar se deve fazer refresh
    if (!shouldAttemptRefresh()) {
      return; // Não faz nada em páginas públicas
    }
    
    // Intervalo para fazer refresh (ex: a cada 15 minutos)
    const interval = setInterval(async () => {
      try {
        await refreshToken();
      } catch (error) {
        console.error('Failed to refresh token:', error);
        // Opcional: redirecionar para login se falhar
      }
    }, 15 * 60 * 1000); // 15 minutos
    
    return () => clearInterval(interval);
  }, [location.pathname]);
}
```

### 4. Exemplo com Axios Interceptor

```typescript
import axios from 'axios';

// Request interceptor
axios.interceptors.request.use((config) => {
  // Se for refresh-token, verificar antes
  if (config.url?.includes('/refresh-token')) {
    if (!shouldAttemptRefresh()) {
      // Cancelar a requisição
      return Promise.reject(new Error('Should not refresh token on public pages'));
    }
  }
  
  // Adicionar CSRF token se necessário
  const csrfToken = getCsrfTokenFromCookie();
  if (csrfToken) {
    config.headers['X-CSRF-Token'] = csrfToken;
  }
  
  return config;
});
```

---

## 🔍 Função auxiliar para ler CSRF token

```typescript
/**
 * Lê o token CSRF do cookie
 */
function getCsrfTokenFromCookie(): string | null {
  const cookies = document.cookie.split(';');
  const csrfCookie = cookies.find(cookie => 
    cookie.trim().startsWith('csrf_token=')
  );
  
  if (csrfCookie) {
    return csrfCookie.split('=')[1];
  }
  
  return null;
}
```

---

## 📊 Comportamento Esperado

| Cenário | Deve fazer refresh? | Por quê? |
|---------|---------------------|----------|
| Página `/login` | ❌ Não | Usuário não está autenticado |
| Página `/check-email` | ❌ Não | Usuário não está autenticado |
| Página `/dashboard` com cookies | ✅ Sim | Usuário autenticado |
| Sem cookie `refresh_token` | ❌ Não | Não há token para refresh |
| Cookie `refresh_token` existe | ✅ Sim (se não for página pública) | Token válido disponível |

---

## ⚠️ Tratamento de Erros

### Status 401 (Unauthorized)
- **Causa:** Refresh token ausente, expirado ou inválido
- **Ação:** Redirecionar para `/login` e limpar cookies

### Status 403 (Forbidden)
- **Causa:** CSRF token inválido ou ausente
- **Ação:** 
  - Tentar ler CSRF token novamente do cookie
  - Se ainda falhar, pode ser que o cookie expirou → redirecionar para login

### Status 200 (OK)
- **Causa:** Refresh bem-sucedido
- **Ação:** 
  - Atualizar access token
  - Atualizar CSRF token se retornado no header `X-CSRF-Token`

---

## 🎯 Benefícios

1. ✅ **Performance:** Evita requisições desnecessárias ao servidor
2. ✅ **UX:** Menos erros no console do navegador
3. ✅ **Arquitetura:** Lógica de UI fica no frontend (onde deve estar)
4. ✅ **Segurança:** Backend continua validando (defensivo)

---

## 📝 Checklist de Implementação

- [ ] Criar função `shouldAttemptRefresh()`
- [ ] Implementar verificação antes de chamar `/refresh-token`
- [ ] Adicionar função `getCsrfTokenFromCookie()`
- [ ] Configurar interceptor ou hook para refresh
- [ ] Tratar erros 401 (redirecionar para login)
- [ ] Tratar erros 403 (tentar novamente ou redirecionar)
- [ ] Testar em páginas públicas (não deve fazer refresh)
- [ ] Testar em páginas protegidas (deve fazer refresh)

---

## 🔗 Referências

- **Endpoint:** `POST /api/v1/auth/refresh-token`
- **Cookies necessários:** `refresh_token`, `csrf_token`
- **Header necessário:** `X-CSRF-Token` (deve ser igual ao cookie `csrf_token`)
- **Status codes:**
  - `200 OK`: Refresh bem-sucedido
  - `401 Unauthorized`: Token ausente/inválido
  - `403 Forbidden`: CSRF token inválido

---

**Última atualização:** 2025-11-05  
**Versão do Backend:** v144

