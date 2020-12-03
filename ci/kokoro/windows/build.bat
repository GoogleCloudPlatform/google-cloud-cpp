@REM Copyright 2020 Google LLC
@REM
@REM Licensed under the Apache License, Version 2.0 (the "License");
@REM you may not use this file except in compliance with the License.
@REM You may obtain a copy of the License at
@REM
@REM     http://www.apache.org/licenses/LICENSE-2.0
@REM
@REM Unless required by applicable law or agreed to in writing, software
@REM distributed under the License is distributed on an "AS IS" BASIS,
@REM WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
@REM See the License for the specific language governing permissions and
@REM limitations under the License.

REM Install Bazel using Chocolatey.
choco install --no-progress -y bazel --version 3.5.0

REM Change PATH to use chocolatey's version of Bazel
set PATH=C:\ProgramData\chocolatey\bin;%PATH%

@REM capture the version for troubleshooting
bazel version
@REM shutdown afterwards otherwise the server locks files
bazel shutdown

@REM TODO(#5575) - remove this and use the Kokoro configuration
set MSVC_VERSION=2019

REM DEBUG DEBUG DEBUG Show available MSVC versions
REM DEBUG DEBUG DEBUG Show available MSVC versions
dir "c:\Program Files (x86)\Microsoft Visual Studio\"
call "c:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\"
call "c:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\"
REM DEBUG DEBUG DEBUG Show available MSVC versions

REM Configure the environment to use MSVC %MSVC_VERSION% and then switch to PowerShell.
call "c:\Program Files (x86)\Microsoft Visual Studio\%MSVC_VERSION%\Community\VC\Auxiliary\Build\vcvars64.bat"

REM The remaining of the build script is implemented in PowerShell.
echo %date% %time%
cd github\google-cloud-cpp
powershell -exec bypass ci\kokoro\windows\build.ps1
if %errorlevel% neq 0 exit /b %errorlevel%

@echo DONE "============================================="
@echo %date% %time%
