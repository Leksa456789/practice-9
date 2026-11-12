@echo off
setlocal EnableExtensions DisableDelayedExpansion
chcp 65001 >nul

rem ====================================================================
rem  pc_info.bat, версия 2 (ветка feature/client-check-audit)
rem  Собирает сведения о компьютере, сверяет список установленных программ
rem  с эталонными перечнями и формирует отчёт с рекомендациями.
rem  Запуск: двойной щелчок или команда pc_info.bat
rem  Тестовый режим: pc_info.bat /test
rem  Сведения о системе берутся через PowerShell, потому что wmic
rem  в новых сборках Windows 11 устарел и может отсутствовать.
rem ====================================================================

rem --- Блок 0. Пути, режим работы и счётчики ---
set "REPORT=%~dp0pc_report.txt"
set "APPS_RAW=%TEMP%\apps_raw.txt"
set "APPLIST=%TEMP%\apps_list.txt"
set "PATFILE=%TEMP%\audit_patterns.txt"
set "HITS=%TEMP%\audit_hits.txt"

set "TESTMODE=0"
if /i "%~1"=="/test" set "TESTMODE=1"

set "checked=0"
set "miss_recs=0"
set "groups=0"
set "flagged=0"
set "flagged_groups=0"
set "app_count=0"

rem Создаём пустой отчёт. Если папку скрипта защищена от записи, пишем во временную папку.
type nul > "%REPORT%" 2>nul
if not exist "%REPORT%" set "REPORT=%TEMP%\pc_report.txt"
type nul > "%REPORT%"

cls
echo Проверка рабочего места запущена. Окно не закрывайте, это займёт до минуты.
echo.

rem --- Блок 1. Дата и время формирования отчёта ---
echo [1/6] Определяю дату и время...
set "stamp="
for /f "usebackq delims=" %%A in (`powershell -NoProfile -Command "Get-Date -Format 'dd.MM.yyyy HH:mm:ss'" 2^>nul`) do set "stamp=%%A"
if not defined stamp set "stamp=%date% %time:~0,8%"

call :log "========================================================"
call :log "  ОТЧЁТ О СОСТОЯНИИ РАБОЧЕГО МЕСТА"
call :log "  Сформирован: %stamp%"
if "%TESTMODE%"=="1" call :log "  РЕЖИМ ТЕСТА: в список программ добавлены тестовые строки, отчёт не отражает реальное состояние."
call :log "========================================================"
call :log ""

rem --- Блок 2. Сведения о системе ---
rem Перед каждым запросом переменная очищается, после запроса проверяется, получено ли значение.
echo [2/6] Собираю сведения о системе...
call :log "--- 1. СВЕДЕНИЯ О СИСТЕМЕ ---"

set "pc_name=%COMPUTERNAME%"
set "pc_user=%USERNAME%"
if defined pc_name (call :log "Компьютер: %pc_name%") else (call :log "Компьютер: данные получить не удалось")
if defined pc_user (call :log "Пользователь: %pc_user%") else (call :log "Пользователь: данные получить не удалось")

set "os_line="
for /f "usebackq tokens=1,2 delims=;" %%A in (`powershell -NoProfile -Command "$o=Get-CimInstance Win32_OperatingSystem; $o.Caption + ';' + $o.Version" 2^>nul`) do set "os_line=%%A, версия %%B"
if defined os_line (call :log "Операционная система: %os_line%") else (call :log "Операционная система: данные получить не удалось")

set "cpu_name="
for /f "usebackq delims=" %%A in (`powershell -NoProfile -Command "(Get-CimInstance Win32_Processor | Select-Object -First 1).Name" 2^>nul`) do set "cpu_name=%%A"
if defined cpu_name (call :log "Процессор: %cpu_name%") else (call :log "Процессор: данные получить не удалось")

rem Объём памяти и дисков переводится в гигабайты внутри PowerShell: так нет переполнения разрядной сетки при делении в cmd.
set "ram_gb="
for /f "usebackq delims=" %%A in (`powershell -NoProfile -Command "[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB,1)" 2^>nul`) do set "ram_gb=%%A"
if defined ram_gb (call :log "Оперативная память: %ram_gb% ГБ") else (call :log "Оперативная память: данные получить не удалось")

set "disk_found=0"
for /f "usebackq tokens=1-3" %%A in (`powershell -NoProfile -Command "Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { '{0} {1} {2}' -f $_.DeviceID,[math]::Round($_.Size/1GB,1),[math]::Round($_.FreeSpace/1GB,1) }" 2^>nul`) do (
    call :log "Диск %%A всего %%B ГБ, свободно %%C ГБ"
    set "disk_found=1"
)
if "%disk_found%"=="0" call :log "Диски: данные получить не удалось"

rem --- Блок 3. Список установленных программ ---
rem Опрашиваем три ветки реестра: 64-битные программы, 32-битные программы и программы текущего пользователя.
rem Из каждой строки вывода reg query берём только третью часть, то есть само название.
echo [3/6] Опрашиваю реестр, это самый долгий этап...
if exist "%APPS_RAW%" del "%APPS_RAW%"
if exist "%APPLIST%" del "%APPLIST%"
type nul > "%APPS_RAW%"

for %%R in (
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
) do (
    for /f "tokens=1,2,*" %%A in ('reg query "%%~R" /s /v DisplayName 2^>nul ^| findstr /i /c:"DisplayName"') do (
        if /i "%%A"=="DisplayName" >>"%APPS_RAW%" echo(%%C
    )
)

rem Антивирусы, зарегистрированные в Центре безопасности Windows, добавляем в тот же список.
rem Встроенный Microsoft Defender в списке удаления программ не значится, поэтому иначе он не был бы найден.
for /f "usebackq delims=" %%A in (`powershell -NoProfile -Command "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object -ExpandProperty displayName" 2^>nul`) do >>"%APPS_RAW%" echo(%%A

rem Сортируем и убираем повторы. Запись без BOM, чтобы поиск по файлу не ломался на первой строке.
powershell -NoProfile -Command "[string[]]$l = [IO.File]::ReadAllLines('%APPS_RAW%') | Where-Object { $_.Trim() } | Sort-Object -Unique; [IO.File]::WriteAllLines('%APPLIST%', $l)" 2>nul
if not exist "%APPLIST%" copy "%APPS_RAW%" "%APPLIST%" >nul 2>&1

if "%TESTMODE%"=="1" call :apply_test

for /f %%N in ('type "%APPLIST%" 2^>nul ^| find /c /v ""') do set "app_count=%%N"
call :log "Установлено программ (уникальных названий): %app_count%"
call :log ""

rem Если список пуст, анализ невозможен: честно сообщаем об этом, а не выдаём ложные рекомендации.
if "%app_count%"=="0" (
    call :log "Список установленных программ получить не удалось. Разделы 2 и 3 пропущены."
    call :log ""
    goto summary
)

rem --- Блок 4. Раздел 2: недостающее базовое ПО ---
echo [4/6] Проверяю наличие базового ПО...
call :log "--- 2. БАЗОВОЕ ПО ДЛЯ ОФИСНОЙ РАБОТЫ ---"
call :log "Эталонный набор и обоснование выбора:"
call :log "  - офисный пакет: создание и правка документов, таблиц и презентаций;"
call :log "  - браузер: работа с корпоративными веб-сервисами и почтой;"
call :log "  - программа для PDF: договоры, счета и инструкции приходят в PDF;"
call :log "  - архиватор: вложения в почте и обмен файлами приходят в архивах;"
call :log "  - антивирус: базовая защита рабочего места."
call :log "Проверка: поиск названия в списке программ без учёта регистра."
call :log ""

(
    echo Microsoft Office
    echo Microsoft 365
    echo LibreOffice
    echo OpenOffice
    echo MyOffice
    echo WPS Office
) > "%PATFILE%"
call :check_cat "Офисный пакет" "Не обнаружен офисный пакет. Для работы с документами, таблицами и презентациями рекомендуется установить LibreOffice или Microsoft Office."

call :check_browser

(
    echo Acrobat
    echo Adobe Reader
    echo Foxit
    echo SumatraPDF
    echo PDF-XChange
) > "%PATFILE%"
call :check_cat "Программа для PDF" "Не обнаружена программа для чтения PDF. Для работы с договорами и счетами рекомендуется установить Adobe Acrobat Reader, Foxit Reader или SumatraPDF."

(
    echo 7-Zip
    echo WinRAR
    echo WinZip
    echo PeaZip
    echo Bandizip
) > "%PATFILE%"
call :check_cat "Архиватор" "Не обнаружен архиватор. Для работы с вложениями в почте рекомендуется установить 7-Zip или WinRAR."

(
    echo Defender
    echo Kaspersky
    echo ESET
    echo Dr.Web
    echo Avast
    echo McAfee
    echo Norton
    echo Bitdefender
) > "%PATFILE%"
call :check_cat "Антивирус" "Не обнаружен антивирус. Для защиты рабочего места рекомендуется включить Microsoft Defender или установить корпоративное антивирусное решение."
call :log ""

rem --- Блок 5. Раздел 3: ПО, не относящееся к базовым задачам ---
echo [5/6] Проверяю наличие ПО, не относящегося к офисным задачам...
call :log "--- 3. ПО, НЕ ОТНОСЯЩЕЕСЯ К БАЗОВЫМ ОФИСНЫМ ЗАДАЧАМ ---"
call :log "ВАЖНО: это рекомендации к проверке, а не указание к удалению."
call :log "Часть программ может быть установлена по согласованию с руководством или нужна для специфических задач. Решение принимает администратор."
call :log ""

(
    echo Steam
    echo Epic Games
    echo GOG
    echo Origin
    echo Ubisoft
    echo Battle.net
    echo Riot
    echo game
    echo gaming
) > "%PATFILE%"
call :check_group "3.1 Игровое ПО и игровые платформы" "Не относится к базовым офисным задачам. Проверьте, согласована ли установка."

(
    echo torrent
    echo Vuze
) > "%PATFILE%"
call :check_group "3.2 Торрент-клиенты и файлообменные программы" "Создают нагрузку на сеть и часто бывают источником нежелательного ПО. Проверьте, для чего установлены."

(
    echo Discord
    echo Telegram
    echo WhatsApp
    echo Viber
    echo Skype
) > "%PATFILE%"
call :check_group "3.3 Мессенджеры для личного общения" "В части организаций это рабочий инструмент. Проверьте, входит ли программа в корпоративный стандарт."

(
    echo Wallpaper Engine
    echo OBS Studio
    echo Soundpad
    echo VLC
    echo PotPlayer
    echo KMPlayer
    echo AIMP
    echo Winamp
) > "%PATFILE%"
call :check_group "3.4 Развлечения, оформление и медиаплееры" "Не нужны для работы. Проверьте, есть ли корпоративный стандартный плеер и согласована ли установка."
call :log ""

rem --- Блок 6. Итог, очистка, пауза ---
:summary
echo [6/6] Формирую итог...
set /a total_recs=miss_recs+flagged_groups
call :log "--- ИТОГ ---"
call :log "Проверено категорий базового ПО: %checked%"
call :log "Рекомендаций по недостающему ПО: %miss_recs%"
call :log "Проверено групп излишнего ПО: %groups%"
call :log "Групп с находками: %flagged_groups%, программ к проверке: %flagged%"
call :log "Всего рекомендаций: %total_recs%"
call :log ""
call :log "Отчёт сохранён: %REPORT%"

rem Временные файлы удаляем, чтобы не оставлять мусор в папке TEMP.
del "%APPS_RAW%" "%APPLIST%" "%PATFILE%" "%HITS%" >nul 2>&1

echo.
pause
endlocal
exit /b 0

rem ====================================================================
rem  ПОДПРОГРАММЫ (ниже основного кода, поэтому основной код завершается exit /b)
rem ====================================================================

rem --- :log - вывод строки на экран и в отчёт ---
rem Текст передаётся в кавычках. Кавычки защищают символы амперсанда, вертикальной черты и угловых скобок,
rem а вывод через переменную с отложенным раскрытием не даёт им сработать как команды.
rem Пустая строка: call :log "" . Конструкция echo( всегда печатает пустую строку.
:log
set "msg=%~1"
setlocal EnableDelayedExpansion
echo(!msg!
>>"%REPORT%" echo(!msg!
endlocal
exit /b

rem --- :find_first - первая найденная в списке программа по признакам из PATFILE ---
:find_first
set "found="
for /f "usebackq delims=" %%P in (`findstr /i /l /g:"%PATFILE%" "%APPLIST%" 2^>nul`) do if not defined found set "found=%%P"
exit /b

rem --- :check_cat - проверка одной категории базового ПО ---
rem %1 - название категории, %2 - текст рекомендации, признаки поиска лежат в PATFILE
:check_cat
set /a checked+=1
call :find_first
if defined found (
    call :log "[OK] %~1: найдено - %found%."
) else (
    set /a miss_recs+=1
    call :log "[РЕКОМЕНДАЦИЯ] %~2"
)
exit /b

rem --- :check_browser - браузер проверяется отдельно ---
rem Microsoft Edge есть в любой современной Windows, поэтому его наличие не говорит о настройке рабочего места.
rem Сначала ищем другие браузеры, и только если их нет, смотрим на Edge.
:check_browser
set /a checked+=1
(
    echo Chrome
    echo Firefox
    echo Yandex
    echo Opera
) > "%PATFILE%"
call :find_first
if defined found (
    call :log "[OK] Браузер: найдено - %found%."
    exit /b
)
set "edge="
for /f "usebackq delims=" %%P in (`findstr /i /x /l /c:"Microsoft Edge" "%APPLIST%" 2^>nul`) do set "edge=%%P"
if defined edge (
    call :log "[OK] Браузер: найден Microsoft Edge. Это компонент системы Windows, а не результат настройки рабочего места. Для корпоративных задач стоит определить стандартный браузер."
    exit /b
)
set /a miss_recs+=1
call :log "[РЕКОМЕНДАЦИЯ] Не обнаружен браузер. Для работы с корпоративными веб-сервисами рекомендуется установить Google Chrome или Mozilla Firefox."
exit /b

rem --- :check_group - проверка одной группы излишнего ПО ---
rem %1 - название группы, %2 - формулировка проверки, признаки поиска лежат в PATFILE
:check_group
set /a groups+=1
set "grp_hits=0"
findstr /i /l /g:"%PATFILE%" "%APPLIST%" > "%HITS%" 2>nul
for /f "usebackq delims=" %%P in ("%HITS%") do set /a grp_hits+=1
if %grp_hits% equ 0 (
    call :log "[OK] %~1: признаков не обнаружено."
    exit /b
)
set /a flagged+=grp_hits
set /a flagged_groups+=1
call :log "[К ПРОВЕРКЕ] %~1: найдено %grp_hits%. %~2"
for /f "usebackq delims=" %%P in ("%HITS%") do call :log "      - %%P"
exit /b

rem --- :apply_test - тестовый режим (запуск с ключом /test) ---
rem Добавляет тестовые строки в список программ и убирает архиваторы,
rem чтобы проверить обе ветви логики: находки в разделе 3 и рекомендацию в разделе 2.
:apply_test
>>"%APPLIST%" echo(uTorrent 3.6 [TEST]
>>"%APPLIST%" echo(Steam [TEST]
>>"%APPLIST%" echo(Telegram Desktop [TEST]
findstr /i /v /l /c:"7-Zip" /c:"WinRAR" /c:"WinZip" /c:"PeaZip" /c:"Bandizip" "%APPLIST%" > "%APPLIST%.tmp" 2>nul
move /y "%APPLIST%.tmp" "%APPLIST%" >nul 2>&1
exit /b
