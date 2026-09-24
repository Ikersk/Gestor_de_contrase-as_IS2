@echo off
title Gestor de Contrasenas ZK - Iniciar Proyecto
echo ========================================================
echo    Iniciando Gestor de Contrasenas Zero-Knowledge
echo ========================================================
echo.

cd /d "%~dp0"

echo [1/2] Iniciando Servidor Backend (http://localhost:3000)...
start "Servidor Backend (Puerto 3000)" cmd /k "cd /d %~dp0server && npm run dev"

echo [2/2] Iniciando Cliente Frontend (http://localhost:5173)...
start "Cliente Frontend (Puerto 5173)" cmd /k "cd /d %~dp0client && npm run dev"

echo.
echo ========================================================
echo   El backend y el frontend se estan ejecutando en ventanas
echo   separadas.
echo.
echo   * Frontend: http://localhost:5173
echo   * Backend:  http://localhost:3000
echo.
echo   NOTA: Recuerda configurar tus credenciales de Supabase
echo         o PostgreSQL en: server\.env
echo ========================================================
echo.
pause
