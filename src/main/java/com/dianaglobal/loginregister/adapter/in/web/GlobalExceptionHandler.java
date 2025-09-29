// src/main/java/com/dianaglobal/loginregister/adapter/in/web/GlobalExceptionHandler.java
package com.dianaglobal.loginregister.adapter.in.web;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;
import java.util.stream.Collectors;

@RestControllerAdvice
public class GlobalExceptionHandler {

    /* 400 - Malformed/invalid JSON */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Object> handleNotReadable(HttpMessageNotReadableException ex, HttpServletRequest req) {
        return build(HttpStatus.BAD_REQUEST, "Malformed JSON request", safeDetail(ex), req);
    }

    /* 400 - @Valid on @RequestBody */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex, HttpServletRequest req) {
        Map<String, String> fieldErrors = ex.getBindingResult().getFieldErrors().stream()
                .collect(Collectors.toMap(
                        fe -> fe.getField(),
                        DefaultMessageSourceResolvable::getDefaultMessage,
                        (a, b) -> a,
                        LinkedHashMap::new
                ));
        Map<String, Object> body = baseBody(HttpStatus.BAD_REQUEST, "Validation failed", req);
        body.put("errors", fieldErrors);
        return new ResponseEntity<>(body, HttpStatus.BAD_REQUEST);
    }

    /* 400 - @RequestParam / @PathVariable constraint violations */
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<Object> handleConstraintViolation(ConstraintViolationException ex, HttpServletRequest req) {
        Map<String, String> errors = ex.getConstraintViolations().stream()
                .collect(Collectors.toMap(
                        v -> v.getPropertyPath().toString(),
                        v -> v.getMessage(),
                        (a, b) -> a,
                        LinkedHashMap::new
                ));
        Map<String, Object> body = baseBody(HttpStatus.BAD_REQUEST, "Constraint violation", req);
        body.put("errors", errors);
        return new ResponseEntity<>(body, HttpStatus.BAD_REQUEST);
    }

    /* 400 - Common MVC parameter issues */
    @ExceptionHandler({
            MissingServletRequestParameterException.class,
            MethodArgumentTypeMismatchException.class
    })
    public ResponseEntity<Object> handleBadRequest(Exception ex, HttpServletRequest req) {
        return build(HttpStatus.BAD_REQUEST, "Bad request", safeDetail(ex), req);
    }

    /* 401 - Auth issues */
    @ExceptionHandler({
            BadCredentialsException.class
    })
    public ResponseEntity<Object> handleBadCredentials(Exception ex, HttpServletRequest req) {
        return build(HttpStatus.UNAUTHORIZED, "Invalid credentials", safeDetail(ex), req);
    }

    /* 401 - JWT problems */
    @ExceptionHandler({ExpiredJwtException.class, SignatureException.class, MalformedJwtException.class})
    public ResponseEntity<Object> handleJwt(Exception ex, HttpServletRequest req) {
        String msg = (ex instanceof ExpiredJwtException)
                ? "Token expired. Please login again."
                : "Invalid token.";
        return build(HttpStatus.UNAUTHORIZED, msg, safeDetail(ex), req);
    }

    /* 403 - Forbidden */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Object> handleAccessDenied(AccessDeniedException ex, HttpServletRequest req) {
        return build(HttpStatus.FORBIDDEN, "Access denied", safeDetail(ex), req);
    }

    /* 404 - Not found from Optional.orElseThrow() */
    @ExceptionHandler(NoSuchElementException.class)
    public ResponseEntity<Object> handleNoSuchElement(NoSuchElementException ex, HttpServletRequest req) {
        return build(HttpStatus.NOT_FOUND, "Resource not found", safeDetail(ex), req);
    }

    /* 409 - Duplicate e-mail or integrity violations */
    @ExceptionHandler({DuplicateKeyException.class, DataIntegrityViolationException.class})
    public ResponseEntity<Object> handleConflict(Exception ex, HttpServletRequest req) {
        // Most common case in your app is duplicate e-mail
        return build(HttpStatus.CONFLICT, "E-mail is already registered", safeDetail(ex), req);
    }

    /* 400 - Simple business rule failures you throw with IllegalArgumentException */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Object> handleIllegalArgument(IllegalArgumentException ex, HttpServletRequest req) {
        return build(HttpStatus.BAD_REQUEST, ex.getMessage(), safeDetail(ex), req);
    }

    /* 500 - Fallback */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Object> handleGeneric(Exception ex, HttpServletRequest req) {
        // Attach a simple correlation ID so you can find the stack trace in server logs.
        String errorId = UUID.randomUUID().toString();
        Map<String, Object> body = baseBody(HttpStatus.INTERNAL_SERVER_ERROR, "Internal server error", req);
        body.put("detail", "Error ID: " + errorId);
        return new ResponseEntity<>(body, new HttpHeaders(), HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /* Helpers */
    private ResponseEntity<Object> build(HttpStatus status, String message, String detail, HttpServletRequest req) {
        Map<String, Object> body = baseBody(status, message, req);
        body.put("detail", detail);
        return new ResponseEntity<>(body, new HttpHeaders(), status);
    }

    private Map<String, Object> baseBody(HttpStatus status, String message, HttpServletRequest req) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", OffsetDateTime.now().toString());
        body.put("path", req.getRequestURI());
        body.put("status", status.value());
        body.put("error", status.getReasonPhrase());
        body.put("message", message);
        return body;
    }

    /** Avoid echoing raw stack traces or huge messages back to clients. */
    private String safeDetail(Exception ex) {
        String m = ex.getMessage();
        if (m == null || m.length() > 300) return ex.getClass().getSimpleName();
        return m;
    }
}
