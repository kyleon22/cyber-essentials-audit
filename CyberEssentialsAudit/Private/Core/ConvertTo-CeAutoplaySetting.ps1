# AutoPlay/AutoRun detection helpers.
#
# Matching MUST tolerate word separators: the legacy MDM security baselines
# (intents) surface these settings as "Auto Play" / "Auto play default auto
# run behavior" / "Block auto play for non-volume devices" - WITH SPACES -
# while settings-catalog ids are one word (..._autoplay_turnoffautoplay) and
# GPO names use "AutoPlay"/"AutoRun". A plain 'autoplay|autorun' regex misses
# every legacy-baseline form, which is how an enabled baseline was reported
# as "no setting found".
#
# Keep in sync with the AutoPlay entry in ConvertFrom-CeGpoReportXml.ps1.
$script:CeAutoplayPattern = '(?i)auto[\s\-_]?(play|run)'

# Classify a settings-catalog (definitionId, value) pair as an AutoPlay
# setting. Returns $null for non-AutoPlay pairs; otherwise a friendly name,
# a readable state, and whether the value actually DISABLES AutoPlay/AutoRun.
#
# Policy CSP reference (Autoplay area):
#   TurnOffAutoPlay                       _1 = Enabled (AutoPlay off)
#   DisallowAutoplayForNonVolumeDevices   _1 = Enabled (blocked)
#   SetDefaultAutoRunBehavior             _1 = Enabled; child choice
#     1 = do not execute autorun commands, 2 = automatically execute.
function ConvertTo-CeAutoplaySetting {
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Pair)
    if ($Pair.Id -notmatch $script:CeAutoplayPattern) { return $null }

    $friendly = ($Pair.Id -split '_')[-1]
    $state    = [string]$Pair.Value
    $disables = $false

    switch -Regex ($Pair.Id) {
        '(?i)turnoffautoplay' {
            $friendly = 'Turn off AutoPlay'
            if     ($Pair.Value -match '(?i)_1$|_true$|alldrives') { $disables = $true; $state = 'Enabled (AutoPlay turned off)' }
            elseif ($Pair.Value -match '(?i)_0$|_false$')          { $state = 'Disabled (AutoPlay allowed)' }
            break
        }
        '(?i)disallowautoplayfornonvolumedevices' {
            $friendly = 'Disallow AutoPlay for non-volume devices'
            if     ($Pair.Value -match '(?i)_1$|_true$') { $disables = $true; $state = 'Enabled (AutoPlay blocked for non-volume devices)' }
            elseif ($Pair.Value -match '(?i)_0$|_false$') { $state = 'Disabled / not enforced' }
            break
        }
        '(?i)setdefaultautorunbehavior|noautorun' {
            $friendly = 'Default AutoRun behaviour'
            if     ($Pair.Value -match '(?i)donotexecute|_1$|_true$') { $disables = $true; $state = 'Enabled - do not execute any autorun commands' }
            elseif ($Pair.Value -match '(?i)_2$') { $state = 'Automatically execute autorun commands (does NOT disable AutoRun)' }
            break
        }
        default {
            if     ($Pair.Value -match '(?i)_1$|_true$|donotexecute|donotplay|enabled') { $disables = $true; $state = 'Enabled (disables AutoPlay/AutoRun)' }
            elseif ($Pair.Value -match '(?i)_0$|_false$') { $state = 'Not enforced' }
        }
    }

    [pscustomobject]@{
        Id       = [string]$Pair.Id
        Setting  = $friendly
        State    = $state
        Disables = $disables
    }
}
