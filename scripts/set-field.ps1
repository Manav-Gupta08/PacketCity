# Dev helper: sets the value of a text field in the PacketCity window by its accessible name.
param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][AllowEmptyString()][string]$Value)

Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$proc = Get-Process packetcity -ErrorAction Stop | Where-Object MainWindowHandle -ne 0 | Select-Object -First 1
$root = [System.Windows.Automation.AutomationElement]::FromHandle($proc.MainWindowHandle)
$cond = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, $Name)
$field = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $cond)
if (-not $field) { throw "Field '$Name' not found" }
$field.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).SetValue($Value)
Write-Host "set '$Name'"
