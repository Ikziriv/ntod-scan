@echo off
rem Run `ecc memory` against this repo's .ncc vault regardless of cwd —
rem ECC_MEMORY_PROJECT_ROOT resolves relative to cwd and silently misses
rem the vault from subdirectories.
for /f "delims=" %%i in ('git rev-parse --show-toplevel') do set "ROOT=%%i"
cd /d "%ROOT%"
ecc memory %*
