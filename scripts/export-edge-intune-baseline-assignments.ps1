<#
.SYNOPSIS
    Exports Microsoft Edge Intune Security Baseline assignments for documentation and auditing.

.DESCRIPTION
    This script connects to Microsoft Graph using the Microsoft Graph PowerShell SDK and retrieves
    all Device Management Intents (Security Baselines) whose display name contains 'Edge'.
    For each matching baseline, it enumerates all assignments and outputs the baseline name
    alongside each assignment target type.

    This is useful for IT administrators and security teams who want to document which Edge
    Security Baselines are deployed in their Intune tenant and verify assignment targets
    (e.g., specific AAD groups, all devices, all users) as part of a compliance or
    change management process.

    Prerequisites:
        - Microsoft Graph PowerShell SDK installed:
          Install-Module Microsoft.Graph -Scope CurrentUser
        - Sufficient Intune permissions in Entra ID (at minimum DeviceManagement.Read.All)
        - PowerShell 5.1+ or PowerShell 7+

.NOTES
    Author:      Souhaiel Morhag
    Company:     MSEndpoint.com
    Blog:        https://msendpoint.com
    Academy:     https://app.msendpoint.com/academy
    LinkedIn:    https://linkedin.com/in/souhaiel-morhag
    GitHub:      https://github.com/Msendpoint
    License:     MIT

.EXAMPLE
    # Run interactively with default parameters (outputs to console)
    .\Export-EdgeBaselineAssignments.ps1

.EXAMPLE
    # Run and redirect output to a text file for documentation
    .\Export-EdgeBaselineAssignments.ps1 | Tee-Object -FilePath .\EdgeBaselineAssignments.txt

.EXAMPLE
    # Run with a custom keyword filter to find baselines with a different naming convention
    .\Export-EdgeBaselineAssignments.ps1 -BaselineFilter "Browser"
#>

[CmdletBinding()]
param (
    # Filter string used to search for Edge-related Security Baselines by display name.
    # Defaults to 'Edge' to match Microsoft's standard baseline naming.
    [Parameter(Mandatory = $false)]
    [string]$BaselineFilter = "Edge",

    # Optional: Export results to a CSV file at the specified path.
    [Parameter(Mandatory = $false)]
    [string]$ExportCsvPath = ""
)

#region --- Functions ---

function Connect-ToMicrosoftGraph {
    <#
    .SYNOPSIS
        Authenticates to Microsoft Graph with the required Intune read scopes.
    #>
    [CmdletBinding()]
    param ()

    Write-Verbose "Connecting to Microsoft Graph with scope: DeviceManagement.Read.All"
    try {
        Connect-MgGraph -Scopes "DeviceManagement.Read.All" -ErrorAction Stop
        Write-Verbose "Successfully connected to Microsoft Graph."
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph. Ensure the Microsoft.Graph module is installed and you have appropriate permissions.`nError: $_"
        exit 1
    }
}

function Get-EdgeBaselines {
    <#
    .SYNOPSIS
        Retrieves Device Management Intents (Security Baselines) matching the specified filter.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Filter
    )

    Write-Verbose "Querying Device Management Intents with filter: '*$Filter*'"
    try {
        $baselines = Get-MgDeviceManagementIntent -ErrorAction Stop | Where-Object {
            $_.DisplayName -like "*$Filter*"
        }

        if (-not $baselines) {
            Write-Warning "No Security Baselines found matching filter: '$Filter'. Verify the baseline exists in your tenant."
        }
        else {
            Write-Verbose "Found $($baselines.Count) baseline(s) matching filter '$Filter'."
        }

        return $baselines
    }
    catch {
        Write-Error "Failed to retrieve Device Management Intents.`nError: $_"
        return $null
    }
}

function Get-BaselineAssignments {
    <#
    .SYNOPSIS
        Retrieves assignments for a given Device Management Intent (Security Baseline).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$IntentId
    )

    try {
        $assignments = Get-MgDeviceManagementIntentAssignment `
            -DeviceManagementIntentId $IntentId `
            -ErrorAction Stop
        return $assignments
    }
    catch {
        Write-Warning "Failed to retrieve assignments for Intent ID: $IntentId.`nError: $_"
        return @()
    }
}

#endregion --- Functions ---

#region --- Main Execution ---

Write-Output "=== Edge Security Baseline Assignment Export ==="
Write-Output "Filter: '$BaselineFilter'"
Write-Output "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "-------------------------------------------------"

# Step 1: Authenticate to Microsoft Graph
Connect-ToMicrosoftGraph

# Step 2: Retrieve all Edge-related Security Baselines
$baselines = Get-EdgeBaselines -Filter $BaselineFilter

if (-not $baselines) {
    Write-Output "No baselines found. Exiting."
    Disconnect-MgGraph | Out-Null
    exit 0
}

# Step 3: Collect results for optional CSV export
$results = [System.Collections.Generic.List[PSCustomObject]]::new()

# Step 4: Iterate over each baseline and retrieve its assignments
foreach ($baseline in $baselines) {
    Write-Output ""
    Write-Output "Baseline : $($baseline.DisplayName)"
    Write-Output "Intent ID: $($baseline.Id)"

    $assignments = Get-BaselineAssignments -IntentId $baseline.Id

    if (-not $assignments -or $assignments.Count -eq 0) {
        Write-Output "  -> No assignments found for this baseline."

        # Record in results list even if unassigned
        $results.Add([PSCustomObject]@{
            BaselineName = $baseline.DisplayName
            IntentId     = $baseline.Id
            AssignmentId = "N/A"
            TargetType   = "No Assignments"
        })
    }
    else {
        foreach ($assignment in $assignments) {
            # Extract the OData type which identifies the assignment target
            # e.g., #microsoft.graph.allDevicesAssignmentTarget,
            #        #microsoft.graph.groupAssignmentTarget, etc.
            $targetType = $assignment.Target.AdditionalProperties['@odata.type']

            # Attempt to extract group ID if it is a group-based assignment
            $groupId = $assignment.Target.AdditionalProperties['groupId']
            $targetDisplay = if ($groupId) {
                "$targetType (GroupId: $groupId)"
            }
            else {
                $targetType
            }

            Write-Output "  -> Assignment ID : $($assignment.Id)"
            Write-Output "     Target Type   : $targetDisplay"

            $results.Add([PSCustomObject]@{
                BaselineName = $baseline.DisplayName
                IntentId     = $baseline.Id
                AssignmentId = $assignment.Id
                TargetType   = $targetDisplay
            })
        }
    }
}

# Step 5: Optionally export to CSV
if ($ExportCsvPath -ne "") {
    try {
        $results | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Output ""
        Write-Output "Results exported to CSV: $ExportCsvPath"
    }
    catch {
        Write-Warning "Failed to export CSV to '$ExportCsvPath'.`nError: $_"
    }
}

Write-Output ""
Write-Output "-------------------------------------------------"
Write-Output "Export complete. Total baselines processed: $($baselines.Count)"

# Step 6: Disconnect from Microsoft Graph cleanly
try {
    Disconnect-MgGraph | Out-Null
    Write-Verbose "Disconnected from Microsoft Graph."
}
catch {
    Write-Verbose "Note: Could not explicitly disconnect from Microsoft Graph: $_"
}

#endregion --- Main Execution ---
