# !/usr/bin/env powershell

# Copyright 2017 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

## DEBUG DEBUG DEBUG DO NOT MERGE
Write-Host "netsh"
Get-Date -Format o
netsh interface ipv4 show subinterface

Write-Host "Get-CimInstance"
Get-Date -Format o
Get-CimInstance Win32_NetworkAdapter | Write-Host

Write-Host "before netkvm loop"
Get-Date -Format o

do {
    $netkvm = Get-CimInstance Win32_NetworkAdapter -filter "ServiceName='netkvm'"
    Write-Host "netkvm loop"
    Get-Date -Format o
    Write-Host "netkvm = " $netkvm
    if (!$netkvm) {
        Start-Sleep 5
    }
} while (!$netkvm)

Write-Host "netkvm set loop"
Get-Date -Format o
$netkvm | ForEach-Object {
    Write-Host "setting via netsh on" $_.NetConnectionID
    Get-Date -Format o
    Write-Host "object = " $_
    netsh interface ipv4 set interface $_.NetConnectionID mtu=1460
}

Write-Host "netsh at end"
Get-Date -Format o
netsh interface ipv4 show subinterface
## DEBUG DEBUG DEBUG DO NOT MERGE

Write-Host
Write-Host "choco sources"
Get-Date -Format o

choco sources list

# Ignore errors
Write-Host
Write-Host "choco install"
Get-Date -Format o
choco install --no-progress -y cmake

# Ignore errors
choco install --no-progress -y cmake.portable

# Ignore errors
choco install --no-progress -y ninja

Write-Host
Write-Host "Post choco install"
Get-Date -Format o
