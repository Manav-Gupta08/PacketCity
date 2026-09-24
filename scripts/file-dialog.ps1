# Dev helper: fills and confirms the native "Open" file dialog shown by PacketCity.
# Messages go straight to the dialog's own control handles, so no other window or the keyboard
# focus is involved.
param([Parameter(Mandatory)][string]$Path, [int]$TimeoutSec = 10)

Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class Win32Msg {
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr SendMessage(IntPtr h, uint msg, IntPtr w, string l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
}
"@
$WM_SETTEXT = 0x000C
$BM_CLICK = 0x00F5
$A = [System.Windows.Automation.AutomationElement]
$T = [System.Windows.Automation.TreeScope]

$main = Get-Process packetcity -ErrorAction Stop | Where-Object MainWindowHandle -ne 0 | Select-Object -First 1
$root = $A::FromHandle($main.MainWindowHandle)
$dialogCond = New-Object System.Windows.Automation.PropertyCondition($A::ClassNameProperty, "#32770")
$deadline = (Get-Date).AddSeconds($TimeoutSec)
$dialog = $root.FindFirst($T::Children, $dialogCond)
while (-not $dialog -and (Get-Date) -lt $deadline) {
  Start-Sleep -Milliseconds 200
  $dialog = $root.FindFirst($T::Children, $dialogCond)
}
if (-not $dialog) { throw "PacketCity file dialog did not appear" }

function Find-Control([string]$automationId, [string]$className) {
  $cond = New-Object System.Windows.Automation.AndCondition(
    (New-Object System.Windows.Automation.PropertyCondition($A::AutomationIdProperty, $automationId)),
    (New-Object System.Windows.Automation.PropertyCondition($A::ClassNameProperty, $className))
  )
  $el = $dialog.FindFirst($T::Descendants, $cond)
  if (-not $el) { throw "control $automationId/$className not found" }
  [IntPtr]$el.Current.NativeWindowHandle
}

# 1148 = file name combo box (its inner Edit), 1 = Open button (standard common-dialog IDs).
[void][Win32Msg]::SendMessage((Find-Control "1148" "Edit"), $WM_SETTEXT, [IntPtr]::Zero, $Path)
[void][Win32Msg]::SendMessage((Find-Control "1" "Button"), $BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero)
Write-Host "chose $Path"
