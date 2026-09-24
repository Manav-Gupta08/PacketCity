# Dev helper: invokes a button in the PacketCity window by its accessible name (UI Automation).
param([Parameter(Mandatory)][string]$Name)

Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$proc = Get-Process packetcity -ErrorAction Stop | Where-Object MainWindowHandle -ne 0 | Select-Object -First 1
$root = [System.Windows.Automation.AutomationElement]::FromHandle($proc.MainWindowHandle)
$cond = New-Object System.Windows.Automation.AndCondition(
  (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Button)),
  (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, $Name))
)
$btn = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $cond)
if (-not $btn) { throw "Button '$Name' not found" }
$btn.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
Write-Host "invoked '$Name'"
