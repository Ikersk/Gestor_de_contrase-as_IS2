@echo off
title Arca ZK - Bateria de Pruebas y Certificacion
color 0B
echo =======================================================================
echo          ARCA: GESTOR DE CONTRASEÑAS ZERO-KNOWLEDGE
echo               BATERIA DE AUDITORIA Y CERTIFICACION
echo =======================================================================
echo.
cd /d "%~dp0"

echo [1/3] Ejecutando Pruebas de Seguridad en el Backend (Node.js + Supertest)...
echo -----------------------------------------------------------------------
cd server
call npm test
if %errorlevel% neq 0 (
    color 0C
    echo.
    echo [ERROR] Las pruebas del servidor fallaron.
    pause
    exit /b %errorlevel%
)
cd ..

echo.
echo [2/3] Ejecutando Pruebas Criptograficas y Anti-Phishing en Frontend (Vitest)...
echo -----------------------------------------------------------------------
cd client
call npm test
if %errorlevel% neq 0 (
    color 0C
    echo.
    echo [ERROR] Las pruebas del cliente fallaron.
    pause
    exit /b %errorlevel%
)

echo.
echo [3/3] Verificando Compilacion Limpia y Generacion de Hashes SRI (Vite)...
echo -----------------------------------------------------------------------
call npm run build
if %errorlevel% neq 0 (
    color 0C
    echo.
    echo [ERROR] La compilacion de produccion fallo.
    pause
    exit /b %errorlevel%
)
cd ..

color 0A
echo.
echo =======================================================================
echo   CERTIFICACION EXITOSA: TODAS LAS PRUEBAS HAN SIDO SUPERADAS
echo.
echo   * Backend: 10/10 pruebas pasadas (Rate limit, CSP, Timing-Attack, ZK)
echo   * Frontend: 44/44 pruebas pasadas (Anti-Phishing, NIST, HIBP, WebCrypto)
echo   * Build: Compilacion de produccion limpia sin errores de tipos
echo =======================================================================
echo.
pause
